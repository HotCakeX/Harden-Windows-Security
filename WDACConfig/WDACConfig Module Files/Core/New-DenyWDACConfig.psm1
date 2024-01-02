Function New-DenyWDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = 'Drivers',
        PositionalBinding = $false,
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    Param(
        # Main parameters for position 0
        [Alias('N')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')][System.Management.Automation.SwitchParameter]$Normal,
        [Alias('D')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Drivers')][System.Management.Automation.SwitchParameter]$Drivers,
        [Alias('P')]
        [parameter(mandatory = $false, ParameterSetName = 'Installed AppXPackages')][System.Management.Automation.SwitchParameter]$InstalledAppXPackages,
        [Alias('W')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Folder Path With WildCards')][System.Management.Automation.SwitchParameter]$PathWildCards,

        [parameter(Mandatory = $true, ParameterSetName = 'Installed AppXPackages', ValueFromPipelineByPropertyName = $true)]
        [System.String]$PackageName,

        [ValidateCount(1, 232)]
        [ValidatePattern('^[a-zA-Z0-9 \-]+$', ErrorMessage = 'The policy name can only contain alphanumeric, space and dash (-) characters.')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String]$PolicyName,

        [ValidatePattern('\*', ErrorMessage = 'You did not supply a path that contains wildcard character (*) .')]
        [parameter(Mandatory = $true, ParameterSetName = 'Folder Path With WildCards', ValueFromPipelineByPropertyName = $true)]
        [System.String]$FolderPath,

        [ValidateScript({ Test-Path -Path $_ -PathType 'Container' }, ErrorMessage = 'The path you selected is not a folder path.')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Drivers')]
        [System.String[]]$ScanLocations,

        [ValidateSet([Levelz])]
        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Drivers')]
        [System.String]$Level = 'FilePublisher',

        [ValidateSet([Fallbackz])]
        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Drivers')]
        [System.String[]]$Fallbacks = 'Hash',

        [ValidateSet('OriginalFileName', 'InternalName', 'FileDescription', 'ProductName', 'PackageFamilyName', 'FilePath')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.String]$SpecificFileNameLevel,

        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.Management.Automation.SwitchParameter]$NoUserPEs,

        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.Management.Automation.SwitchParameter]$NoScript,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$Deploy,

        [Parameter(Mandatory = $false, ParameterSetName = 'Installed AppXPackages')]
        [System.Management.Automation.SwitchParameter]$Force,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )

    begin {
        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null

        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Importing the required sub-modules
        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Update-self.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Write-ColorfulText.psm1" -Force

        # Detecting if Debug switch is used, will do debugging actions based on that
        $PSBoundParameters.Debug.IsPresent ? ([System.Boolean]$Debug = $true) : ([System.Boolean]$Debug = $false) | Out-Null

        # argument tab auto-completion and ValidateSet for Fallbacks
        Class Fallbackz : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $Fallbackz = ('Hash', 'FileName', 'SignedVersion', 'Publisher', 'FilePublisher', 'LeafCertificate', 'PcaCertificate', 'RootCertificate', 'WHQL', 'WHQLPublisher', 'WHQLFilePublisher', 'PFN', 'FilePath', 'None')

                return [System.String[]]$Fallbackz
            }
        }

        # argument tab auto-completion and ValidateSet for level
        Class Levelz : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $Levelz = ('Hash', 'FileName', 'SignedVersion', 'Publisher', 'FilePublisher', 'LeafCertificate', 'PcaCertificate', 'RootCertificate', 'WHQL', 'WHQLPublisher', 'WHQLFilePublisher', 'PFN', 'FilePath', 'None')

                return [System.String[]]$Levelz
            }
        }

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-self -InvocationStatement $MyInvocation.Statement }

        # Detecting if Confirm switch is used to bypass the confirmation prompts
        if ($Force -and -Not $Confirm) {
            $ConfirmPreference = 'None'
        }
    }

    process {

        # Create deny supplemental policy for general files, apps etc.
        if ($Normal) {

            # The total number of the main steps for the progress bar to render
            [System.Int16]$TotalSteps = $Deploy ? 4 : 3
            [System.Int16]$CurrentStep = 0

            Write-Verbose -Message 'Removing any possible files from previous runs'
            Remove-Item -Path '.\ProgramDir_ScanResults*.xml' -Force -ErrorAction SilentlyContinue

            # An array to hold the temporary xml files of each user-selected folders
            [System.Object[]]$PolicyXMLFilesArray = @()

            $CurrentStep++
            Write-Progress -Id 22 -Activity 'Processing user selected Folders' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Processing Program Folders From User input'
            for ($i = 0; $i -lt $ScanLocations.Count; $i++) {

                # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
                [System.Collections.Hashtable]$UserInputProgramFoldersPolicyMakerHashTable = @{
                    FilePath               = ".\ProgramDir_ScanResults$($i).xml"
                    ScanPath               = $ScanLocations[$i]
                    Level                  = $Level
                    Fallback               = $Fallbacks
                    MultiplePolicyFormat   = $true
                    UserWriteablePaths     = $true
                    Deny                   = $true
                    AllowFileNameFallbacks = $true
                }
                # Assess user input parameters and add the required parameters to the hash table
                if ($SpecificFileNameLevel) { $UserInputProgramFoldersPolicyMakerHashTable['SpecificFileNameLevel'] = $SpecificFileNameLevel }
                if ($NoScript) { $UserInputProgramFoldersPolicyMakerHashTable['NoScript'] = $true }
                if (!$NoUserPEs) { $UserInputProgramFoldersPolicyMakerHashTable['UserPEs'] = $true }

                # Create the supplemental policy via parameter splatting
                Write-Verbose -Message "Currently scanning and creating a deny policy for the folder: $($ScanLocations[$i])"
                New-CIPolicy @UserInputProgramFoldersPolicyMakerHashTable
            }

            Write-ColorfulText -Color Pink -InputText 'The Deny policy with the following configuration is being created'
            $UserInputProgramFoldersPolicyMakerHashTable

            # Merge-CiPolicy accepts arrays - collecting all the policy files created by scanning user specified folders
            Write-Verbose -Message 'Collecting all the policy files created by scanning user specified folders'
            foreach ($file in (Get-ChildItem -File -Path '.\' -Filter 'ProgramDir_ScanResults*.xml')) {
                $PolicyXMLFilesArray += $file.FullName
            }

            Write-Verbose -Message 'Adding the AllowAll default template policy path to the array of policy paths to merge'
            $PolicyXMLFilesArray += 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml'

            $CurrentStep++
            Write-Progress -Id 22 -Activity 'Merging the policies' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Creating the final Deny base policy from the xml files in the paths array'
            Merge-CIPolicy -PolicyPaths $PolicyXMLFilesArray -OutputFilePath ".\DenyPolicy $PolicyName.xml" | Out-Null

            $CurrentStep++
            Write-Progress -Id 22 -Activity 'Creating the base policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Assigning a name and resetting the policy ID'
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath "DenyPolicy $PolicyName.xml" -ResetPolicyID -PolicyName "$PolicyName"
            [System.String]$PolicyID = $PolicyID.Substring(11)

            Write-Verbose -Message 'Setting the policy version to 1.0.0.0'
            Set-CIPolicyVersion -FilePath "DenyPolicy $PolicyName.xml" -Version '1.0.0.0'

            Write-Verbose -Message 'Setting the policy rule options'
            @(0, 2, 5, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object -Process {
                Set-RuleOption -FilePath "DenyPolicy $PolicyName.xml" -Option $_ }

            Write-Verbose -Message 'Deleting the unnecessary policy rule options'
            @(3, 4, 9, 10, 13, 18) | ForEach-Object -Process {
                Set-RuleOption -FilePath "DenyPolicy $PolicyName.xml" -Option $_ -Delete }

            Write-Verbose -Message 'Setting the HVCI to Strict'
            Set-HVCIOptions -Strict -FilePath "DenyPolicy $PolicyName.xml"

            Write-Verbose -Message 'Converting the policy XML to .CIP'
            ConvertFrom-CIPolicy -XmlFilePath "DenyPolicy $PolicyName.xml" -BinaryFilePath "$PolicyID.cip" | Out-Null

            Write-ColorfulText -Color MintGreen -InputText "DenyPolicyFile = DenyPolicy $PolicyName.xml"
            Write-ColorfulText -Color MintGreen -InputText "DenyPolicyGUID = $PolicyID"

            if (!$Debug) {
                Remove-Item -Path '.\ProgramDir_ScanResults*.xml' -Force
            }

            if ($Deploy) {
                $CurrentStep++
                Write-Progress -Id 22 -Activity 'Deploying the base policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Deploying the policy'
                &'C:\Windows\System32\CiTool.exe' --update-policy "$PolicyID.cip" -json | Out-Null

                Write-ColorfulText -Color Pink -InputText "A Deny Base policy with the name $PolicyName has been deployed."

                Write-Verbose -Message 'Removing the .CIP file after deployment'
                Remove-Item -Path "$PolicyID.cip" -Force
            }
            Write-Progress -Id 22 -Activity 'Complete.' -Completed
        }

        # Create Deny base policy for Driver files
        if ($Drivers) {

            # The total number of the main steps for the progress bar to render
            [System.Int16]$TotalSteps = $Deploy ? 4 : 3
            [System.Int16]$CurrentStep = 0

            $CurrentStep++
            Write-Progress -Id 23 -Activity 'Processing user selected Folders' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Looping through each user-selected folder paths, scanning them, creating a temp policy file based on them'
            powershell.exe -Command {
                [System.Object[]]$DriverFilesObject = @()
                # loop through each user-selected folder paths
                foreach ($ScanLocation in $args[0]) {
                    # DriverFile object holds the full details of all of the scanned drivers - This scan is greedy, meaning it stores as much information as it can find
                    # about each driver file, any available info about digital signature, hash, FileName, Internal Name etc. of each driver is saved and nothing is left out
                    $DriverFilesObject += Get-SystemDriver -ScanPath $ScanLocation -UserPEs
                }

                [System.Collections.Hashtable]$PolicyMakerHashTable = @{
                    FilePath             = '.\DenyPolicy Temp.xml'
                    DriverFiles          = $DriverFilesObject
                    Level                = $args[1]
                    Fallback             = $args[2]
                    MultiplePolicyFormat = $true
                    UserWriteablePaths   = $true
                    Deny                 = $true
                }
                # Creating a base policy using the DriverFile object and specifying which detail about each driver should be used in the policy file
                New-CIPolicy @PolicyMakerHashTable

            } -args $ScanLocations, $Level, $Fallbacks

            $CurrentStep++
            Write-Progress -Id 23 -Activity 'Merging the policies' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            # Merging AllowAll default policy with our Deny temp policy
            Write-Verbose -Message 'Merging AllowAll default template policy with our Deny temp policy'
            Merge-CIPolicy -PolicyPaths 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml', '.\DenyPolicy Temp.xml' -OutputFilePath ".\DenyPolicy $PolicyName.xml" | Out-Null

            Write-Verbose -Message 'Removing the temp deny policy file after using it in the merge operation'
            Remove-Item -Path '.\DenyPolicy Temp.xml' -Force

            $CurrentStep++
            Write-Progress -Id 23 -Activity 'Configuring the base policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Assigning a name and resetting the policy ID'
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath "DenyPolicy $PolicyName.xml" -ResetPolicyID -PolicyName "$PolicyName"
            [System.String]$PolicyID = $PolicyID.Substring(11)

            Write-Verbose -Message 'Setting the policy version to 1.0.0.0'
            Set-CIPolicyVersion -FilePath "DenyPolicy $PolicyName.xml" -Version '1.0.0.0'

            Write-Verbose -Message 'Setting the policy rule options'
            @(0, 2, 5, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object -Process {
                Set-RuleOption -FilePath "DenyPolicy $PolicyName.xml" -Option $_ }

            Write-Verbose -Message 'Deleting the unnecessary policy rule options from the base deny policy'
            @(3, 4, 9, 10, 13, 18) | ForEach-Object -Process {
                Set-RuleOption -FilePath "DenyPolicy $PolicyName.xml" -Option $_ -Delete }

            Write-Verbose -Message 'Setting the HVCI to Strict'
            Set-HVCIOptions -Strict -FilePath "DenyPolicy $PolicyName.xml"

            Write-Verbose -Message 'Converting the policy XML to .CIP'
            ConvertFrom-CIPolicy -XmlFilePath "DenyPolicy $PolicyName.xml" -BinaryFilePath "$PolicyID.cip" | Out-Null

            Write-ColorfulText -Color MintGreen -InputText "DenyPolicyFile = DenyPolicy $PolicyName.xml"
            Write-ColorfulText -Color MintGreen -InputText "DenyPolicyGUID = $PolicyID"

            if ($Deploy) {
                $CurrentStep++
                Write-Progress -Id 23 -Activity 'Deploying the base policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Deploying the policy'
                &'C:\Windows\System32\CiTool.exe' --update-policy "$PolicyID.cip" -json | Out-Null

                Write-ColorfulText -Color Pink -InputText "A Deny Base policy with the name $PolicyName has been deployed."

                Write-Verbose -Message 'Removing the .CIP file after deployment'
                Remove-Item -Path "$PolicyID.cip" -Force
            }
            Write-Progress -Id 23 -Activity 'Complete.' -Completed
        }

        # Creating Deny rule for Appx Packages
        if ($InstalledAppXPackages) {

            try {
                # The total number of the main steps for the progress bar to render
                [System.Int16]$TotalSteps = $Deploy ? 3 : 2
                [System.Int16]$CurrentStep = 0

                $CurrentStep++
                Write-Progress -Id 24 -Activity 'Getting the Appx package' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Backing up PS Formatting Styles
                [System.Collections.Hashtable]$OriginalStyle = @{}
                $PSStyle.Formatting | Get-Member -MemberType Property | ForEach-Object -Process {
                    $OriginalStyle[$_.Name] = $PSStyle.Formatting.$($_.Name)
                }

                # Change the color for the list items to plum
                $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(221,160,221))"

                Write-Verbose -Message 'Displaying the installed Appx packages based on the supplied name'
                Get-AppxPackage -Name $PackageName | Select-Object -Property Name, Publisher, version, PackageFamilyName, PackageFullName, InstallLocation, Dependencies, SignatureKind, Status

                # Prompt for confirmation before proceeding
                if ($PSCmdlet.ShouldProcess('', 'Select No to cancel and choose another name', 'Is this the intended results based on your Installed Appx packages?')) {

                    $CurrentStep++
                    Write-Progress -Id 24 -Activity 'Creating the base policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Creating a temporary Deny policy for the supplied Appx package name'
                    powershell.exe -Command {
                        # Get all the packages based on the supplied name
                        $Package = Get-AppxPackage -Name $args[0]

                        # Create rules for each package
                        foreach ($Item in $Package) {
                            $Rules += New-CIPolicyRule -Deny -Package $Item
                        }

                        # Generate the supplemental policy xml file
                        New-CIPolicy -MultiplePolicyFormat -FilePath '.\AppxDenyPolicyTemp.xml' -Rules $Rules
                    } -args $PackageName

                    # Merging AllowAll default policy with our Deny temp policy
                    Write-Verbose -Message 'Merging AllowAll default template policy with our AppX Deny temp policy'
                    Merge-CIPolicy -PolicyPaths 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml', '.\AppxDenyPolicyTemp.xml' -OutputFilePath ".\AppxDenyPolicy $PolicyName.xml" | Out-Null

                    Write-Verbose -Message 'Removing the temp deny policy file after using it in the merge operation'
                    Remove-Item -Path '.\AppxDenyPolicyTemp.xml' -Force

                    Write-Verbose -Message 'Assigning a name and resetting the policy ID'
                    [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath ".\AppxDenyPolicy $PolicyName.xml" -ResetPolicyID -PolicyName "$PolicyName"
                    [System.String]$PolicyID = $PolicyID.Substring(11)

                    Write-Verbose -Message 'Setting the policy version to 1.0.0.0'
                    Set-CIPolicyVersion -FilePath ".\AppxDenyPolicy $PolicyName.xml" -Version '1.0.0.0'

                    Write-Verbose -Message 'Setting the policy rule options'
                    @(0, 2, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object -Process {
                        Set-RuleOption -FilePath ".\AppxDenyPolicy $PolicyName.xml" -Option $_ }

                    Write-Verbose -Message 'Deleting the unnecessary policy rule options from the base deny policy'
                    @(3, 4, 8, 9, 10, 13, 14, 15, 18) | ForEach-Object -Process {
                        Set-RuleOption -FilePath ".\AppxDenyPolicy $PolicyName.xml" -Option $_ -Delete }

                    Write-Verbose -Message 'Setting the HVCI to Strict'
                    Set-HVCIOptions -Strict -FilePath ".\AppxDenyPolicy $PolicyName.xml"

                    Write-Verbose -Message 'Converting the policy XML to .CIP'
                    ConvertFrom-CIPolicy -XmlFilePath ".\AppxDenyPolicy $PolicyName.xml" -BinaryFilePath "$PolicyID.cip" | Out-Null

                    Write-ColorfulText -Color MintGreen -InputText "DenyPolicyFile = AppxDenyPolicy $PolicyName.xml"
                    Write-ColorfulText -Color MintGreen -InputText "DenyPolicyGUID = $PolicyID"

                    if ($Deploy) {
                        $CurrentStep++
                        Write-Progress -Id 24 -Activity 'Deploying the base policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                        Write-Verbose -Message 'Deploying the policy'
                        &'C:\Windows\System32\CiTool.exe' --update-policy "$PolicyID.cip" -json | Out-Null

                        Write-ColorfulText -Color Pink -InputText "A Deny Base policy with the name $PolicyName has been deployed."

                        Write-Verbose -Message 'Removing the .CIP file after deployment'
                        Remove-Item -Path "$PolicyID.cip" -Force
                    }
                }
            }
            finally {
                # Restore PS Formatting Styles
                $OriginalStyle.Keys | ForEach-Object -Process {
                    $PSStyle.Formatting.$_ = $OriginalStyle[$_]
                }
                Write-Progress -Id 24 -Activity 'Complete.' -Completed
            }
        }

        # Create Deny base policy for a folder with wildcards
        if ($PathWildCards) {

            # The total number of the main steps for the progress bar to render
            [System.Int16]$TotalSteps = $Deploy ? 3 : 2
            [System.Int16]$CurrentStep = 0

            $CurrentStep++
            Write-Progress -Id 29 -Activity 'Creating the wildcard deny policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            # Using Windows PowerShell to handle serialized data since PowerShell core throws an error
            Write-Verbose -Message 'Creating the deny policy file'
            powershell.exe -Command {
                $RulesWildCards = New-CIPolicyRule -Deny -FilePathRule $args[0]
                New-CIPolicy -MultiplePolicyFormat -FilePath '.\DenyPolicyWildcardTemp.xml' -Rules $RulesWildCards
            } -args $FolderPath

            # Merging AllowAll default policy with our Deny temp policy
            Write-Verbose -Message 'Merging AllowAll default template policy with our Wildcard Deny temp policy'
            Merge-CIPolicy -PolicyPaths 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml', '.\DenyPolicyWildcardTemp.xml' -OutputFilePath ".\DenyPolicyWildcard $PolicyName.xml" | Out-Null

            $CurrentStep++
            Write-Progress -Id 29 -Activity 'Configuring the wildcard deny policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Removing the temp deny policy file after using it in the merge operation'
            Remove-Item -Path '.\DenyPolicyWildcardTemp.xml' -Force

            Write-Verbose -Message 'Assigning a name and resetting the policy ID'
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath ".\DenyPolicyWildcard $PolicyName.xml" -ResetPolicyID -PolicyName "$PolicyName"
            [System.String]$PolicyID = $PolicyID.Substring(11)

            Write-Verbose -Message 'Setting the policy version to 1.0.0.0'
            Set-CIPolicyVersion -FilePath ".\DenyPolicyWildcard $PolicyName.xml" -Version '1.0.0.0'

            Write-Verbose -Message 'Setting the policy rule options'
            @(0, 2, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object -Process {
                Set-RuleOption -FilePath ".\DenyPolicyWildcard $PolicyName.xml" -Option $_ }

            Write-Verbose -Message 'Deleting the unnecessary policy rule options from the base deny policy'
            @(3, 4, 8, 9, 10, 13, 14, 15, 18) | ForEach-Object -Process {
                Set-RuleOption -FilePath ".\DenyPolicyWildcard $PolicyName.xml" -Option $_ -Delete }

            Write-Verbose -Message 'Setting the HVCI to Strict'
            Set-HVCIOptions -Strict -FilePath ".\DenyPolicyWildcard $PolicyName.xml"

            Write-Verbose -Message 'Converting the policy XML to .CIP'
            ConvertFrom-CIPolicy -XmlFilePath ".\DenyPolicyWildcard $PolicyName.xml" -BinaryFilePath "$PolicyID.cip" | Out-Null

            Write-ColorfulText -Color MintGreen -InputText "DenyPolicyFile = DenyPolicyWildcard $PolicyName.xml"
            Write-ColorfulText -Color MintGreen -InputText "DenyPolicyGUID = $PolicyID"

            if ($Deploy) {
                $CurrentStep++
                Write-Progress -Id 29 -Activity 'Deploying the base policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Deploying the policy'
                &'C:\Windows\System32\CiTool.exe' --update-policy "$PolicyID.cip" -json | Out-Null

                Write-ColorfulText -Color Pink -InputText "A Deny Base policy with the name $PolicyName has been deployed."

                Write-Verbose -Message 'Removing the .CIP file after deployment'
                Remove-Item -Path "$PolicyID.cip" -Force
            }
            Write-Progress -Id 29 -Activity 'Complete.' -Completed
        }
    }

    <#
.SYNOPSIS
    Creates Deny base policies (Windows Defender Application Control)
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-DenyWDACConfig
.DESCRIPTION
    Using official Microsoft methods to create Deny base policies (Windows Defender Application Control)
.COMPONENT
    Windows Defender Application Control, ConfigCI PowerShell module
.FUNCTIONALITY
    Using official Microsoft methods, Removes Signed and unsigned deployed WDAC policies (Windows Defender Application Control)
.PARAMETER PolicyName
    It's used by the entire Cmdlet. It is the name of the base policy that will be created.
.PARAMETER Normal
    Creates a Deny standalone base policy by scanning a directory for files. The base policy created by this parameter can be deployed side by side any other base/supplemental policy.
.PARAMETER Level
    The level that determines how the selected folder will be scanned.
    The default value for it is FilePublisher.
.PARAMETER Fallbacks
    The fallback level(s) that determine how the selected folder will be scanned.
    The default value for it is Hash.
.PARAMETER Deploy
    It's used by the entire Cmdlet. Indicates that the created Base deny policy will be deployed on the system.
.PARAMETER Drivers
    Creates a Deny standalone base policy for drivers only by scanning a directory for driver files. The base policy created by this parameter can be deployed side by side any other base/supplemental policy.
.PARAMETER InstalledAppXPackages
    Creates a Deny standalone base policy for an installed App based on Appx package family names
.PARAMETER Force
    It's used by the entire Cmdlet. Indicates that the confirmation prompts will be bypassed.
.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases
    It's used by the entire Cmdlet.
.PARAMETER PackageName
    The name of the Appx package to create a Deny base policy for.
.PARAMETER ScanLocations
    The path(s) to scan for files to create a Deny base policy for.
.PARAMETER SpecificFileNameLevel
    The more specific level that determines how the selected folder will be scanned.
.PARAMETER NoUserPEs
    Indicates that the selected folder will not be scanned for user PE files.
.PARAMETER NoScript
    Indicates that the selected folder will not be scanned for script files.
.PARAMETER Verbose
    Indicates that the cmdlet will display detailed information about the operation.
.PARAMETER PathWildCards
    Creates a Deny standalone base policy for a folder using wildcards. The base policy created by this parameter can be deployed side by side any other base/supplemental policy.
.PARAMETER FolderPath
    The folder path to add to the deny base policy using wildcards.
.INPUTS
    System.String[]
    System.String
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
.EXAMPLE
    New-DenyWDACConfig -PolicyName 'MyDenyPolicy' -Normal -ScanLocations 'C:\Program Files', 'C:\Program Files (x86)'
    Creates a Deny standalone base policy by scanning the specified folders for files.
#>
}

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\Resources\ArgumentCompleters.ps1"
Register-ArgumentCompleter -CommandName 'New-DenyWDACConfig' -ParameterName 'ScanLocations' -ScriptBlock $ArgumentCompleterFolderPathsPicker
Register-ArgumentCompleter -CommandName 'New-DenyWDACConfig' -ParameterName 'PackageName' -ScriptBlock $ArgumentCompleterAppxPackageNames
Register-ArgumentCompleter -CommandName 'New-DenyWDACConfig' -ParameterName 'FolderPath' -ScriptBlock $ArgumentCompleterFolderPathsPickerWildCards

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCARUqNZqACY5yFZ
# TCzbCcoHEgllpEaLx4jnZ9G6vBrb2KCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
# LDQz/68TAAAAAAAEMA0GCSqGSIb3DQEBDQUAME8xEzARBgoJkiaJk/IsZAEZFgNj
# b20xIjAgBgoJkiaJk/IsZAEZFhJIT1RDQUtFWC1DQS1Eb21haW4xFDASBgNVBAMT
# C0hPVENBS0VYLUNBMCAXDTIzMTIyNzExMjkyOVoYDzIyMDgxMTEyMTEyOTI5WjB5
# MQswCQYDVQQGEwJVSzEeMBwGA1UEAxMVSG90Q2FrZVggQ29kZSBTaWduaW5nMSMw
# IQYJKoZIhvcNAQkBFhRob3RjYWtleEBvdXRsb29rLmNvbTElMCMGCSqGSIb3DQEJ
# ARYWU3B5bmV0Z2lybEBvdXRsb29rLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAKb1BJzTrpu1ERiwr7ivp0UuJ1GmNmmZ65eckLpGSF+2r22+7Tgm
# pEifj9NhPw0X60F9HhdSM+2XeuikmaNMvq8XRDUFoenv9P1ZU1wli5WTKHJ5ayDW
# k2NP22G9IPRnIpizkHkQnCwctx0AFJx1qvvd+EFlG6ihM0fKGG+DwMaFqsKCGh+M
# rb1bKKtY7UEnEVAsVi7KYGkkH+ukhyFUAdUbh/3ZjO0xWPYpkf/1ldvGes6pjK6P
# US2PHbe6ukiupqYYG3I5Ad0e20uQfZbz9vMSTiwslLhmsST0XAesEvi+SJYz2xAQ
# x2O4n/PxMRxZ3m5Q0WQxLTGFGjB2Bl+B+QPBzbpwb9JC77zgA8J2ncP2biEguSRJ
# e56Ezx6YpSoRv4d1jS3tpRL+ZFm8yv6We+hodE++0tLsfpUq42Guy3MrGQ2kTIRo
# 7TGLOLpayR8tYmnF0XEHaBiVl7u/Szr7kmOe/CfRG8IZl6UX+/66OqZeyJ12Q3m2
# fe7ZWnpWT5sVp2sJmiuGb3atFXBWKcwNumNuy4JecjQE+7NF8rfIv94NxbBV/WSM
# pKf6Yv9OgzkjY1nRdIS1FBHa88RR55+7Ikh4FIGPBTAibiCEJMc79+b8cdsQGOo4
# ymgbKjGeoRNjtegZ7XE/3TUywBBFMf8NfcjF8REs/HIl7u2RHwRaUTJdAgMBAAGj
# ggJzMIICbzA8BgkrBgEEAYI3FQcELzAtBiUrBgEEAYI3FQiG7sUghM++I4HxhQSF
# hqV1htyhDXuG5sF2wOlDAgFkAgEIMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1Ud
# DwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYB
# BQUHAwMwHQYDVR0OBBYEFOlnnQDHNUpYoPqECFP6JAqGDFM6MB8GA1UdIwQYMBaA
# FICT0Mhz5MfqMIi7Xax90DRKYJLSMIHUBgNVHR8EgcwwgckwgcaggcOggcCGgb1s
# ZGFwOi8vL0NOPUhPVENBS0VYLUNBLENOPUhvdENha2VYLENOPUNEUCxDTj1QdWJs
# aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
# LERDPU5vbkV4aXN0ZW50RG9tYWluLERDPWNvbT9jZXJ0aWZpY2F0ZVJldm9jYXRp
# b25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwgccG
# CCsGAQUFBwEBBIG6MIG3MIG0BggrBgEFBQcwAoaBp2xkYXA6Ly8vQ049SE9UQ0FL
# RVgtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZp
# Y2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Tm9uRXhpc3RlbnREb21haW4sREM9Y29t
# P2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0
# aG9yaXR5MA0GCSqGSIb3DQEBDQUAA4ICAQA7JI76Ixy113wNjiJmJmPKfnn7brVI
# IyA3ZudXCheqWTYPyYnwzhCSzKJLejGNAsMlXwoYgXQBBmMiSI4Zv4UhTNc4Umqx
# pZSpqV+3FRFQHOG/X6NMHuFa2z7T2pdj+QJuH5TgPayKAJc+Kbg4C7edL6YoePRu
# HoEhoRffiabEP/yDtZWMa6WFqBsfgiLMlo7DfuhRJ0eRqvJ6+czOVU2bxvESMQVo
# bvFTNDlEcUzBM7QxbnsDyGpoJZTx6M3cUkEazuliPAw3IW1vJn8SR1jFBukKcjWn
# aau+/BE9w77GFz1RbIfH3hJ/CUA0wCavxWcbAHz1YoPTAz6EKjIc5PcHpDO+n8Fh
# t3ULwVjWPMoZzU589IXi+2Ol0IUWAdoQJr/Llhub3SNKZ3LlMUPNt+tXAs/vcUl0
# 7+Dp5FpUARE2gMYA/XxfU9T6Q3pX3/NRP/ojO9m0JrKv/KMc9sCGmV9sDygCOosU
# 5yGS4Ze/DJw6QR7xT9lMiWsfgL96Qcw4lfu1+5iLr0dnDFsGowGTKPGI0EvzK7H+
# DuFRg+Fyhn40dOUl8fVDqYHuZJRoWJxCsyobVkrX4rA6xUTswl7xYPYWz88WZDoY
# gI8AwuRkzJyUEA07IYtsbFCYrcUzIHME4uf8jsJhCmb0va1G2WrWuyasv3K/G8Nn
# f60MsDbDH1mLtzGCAxgwggMUAgEBMGYwTzETMBEGCgmSJomT8ixkARkWA2NvbTEi
# MCAGCgmSJomT8ixkARkWEkhPVENBS0VYLUNBLURvbWFpbjEUMBIGA1UEAxMLSE9U
# Q0FLRVgtQ0ECEx4AAAAEjzQsNDP/rxMAAAAAAAQwDQYJYIZIAWUDBAIBBQCggYQw
# GAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
# NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQx
# IgQg4AzmXBXcgtjOsM3v9FELFvxXzN6dvLS+GCX+ljPIIcQwDQYJKoZIhvcNAQEB
# BQAEggIAnPsWNpSq7UIgcmdywJMeoXa0EiQyfLzYku8tfXHB3XI0WXq+SCvMpSOA
# eQMsShHBJR9G02P/hRstRY4HisVzgJgSoO0InYrKbzaFXa4FYK+HK3cQvTstyvse
# vQP1ryGjQfCvJzOPdaRfF0Yk+//swRDaKpGQntCGZ3wZVHvAlO47spq4R+0QLBpT
# 41R5rFp7n7j8Q99zkWv2pSL/83iBrosuonbmkl5hnN/rcwo2ITY45WM8/A0OC1l9
# mbBzqFhJnbMGxVDIwB45Q5la/2j19PRkOBr1o3DweoHyjs3Ia5iOrKJy+JSAJDFy
# N3Qqvw2lRMpR1qR4z4Ya1JkdPB+DgVW+ezPTb9VCkI55k+JwTELtVFZvM7Nr24zJ
# jSAdFl+dxqlpKi9yW73EtlZwnB+oPHhN2PRiPKRphR0lXcXM66XFs6PbE1zUXi/Q
# 16wYieMfdxQ830EGV+SlzRkk24lf1s7tkbUToEnP44dBAgiNBaqnA16e3g5vXLVQ
# TGu/B2FIQlTbGCpIih+lHej11u9MmZI77+hd8BdH3R11ATDD6kGrbbjjw0Yy51I/
# CULff1RAXClpiuaqoOYHXJRXKuTKQEVPavXolPGIjQKJg107vEMuLVPQKY7EqAmI
# 2cATB+s9DnPwudDqGfjAHZgqUG7MKZE2IdghPGaq7ySPM4t3hyY=
# SIG # End signature block
