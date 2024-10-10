Function New-DenyWDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = 'Drivers',
        PositionalBinding = $false,
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    [OutputType([System.String])]
    Param(
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

        [ArgumentCompleter([WDACConfig.ArgCompleter.FolderPickerWithWildcard])]
        [ValidatePattern('\*', ErrorMessage = 'You did not supply a path that contains wildcard character (*) .')]
        [parameter(Mandatory = $true, ParameterSetName = 'Folder Path With WildCards', ValueFromPipelineByPropertyName = $true)]
        [System.IO.DirectoryInfo]$FolderPath,

        [ArgumentCompleter([WDACConfig.ArgCompleter.FolderPicker])]
        [ValidateScript({ [System.IO.Directory]::Exists($_) }, ErrorMessage = 'One of the paths you selected is not a valid folder path.')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Drivers')]
        [System.IO.DirectoryInfo[]]$ScanLocations,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$Deploy,

        [ArgumentCompleter({ [WDACConfig.ScanLevelz]::New().GetValidValues() })]
        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.String]$Level = 'WHQLFilePublisher',

        [ArgumentCompleter({ [WDACConfig.ScanLevelz]::New().GetValidValues() })]
        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.String[]]$Fallbacks = ('FilePublisher', 'Hash'),

        [ValidateSet('OriginalFileName', 'InternalName', 'FileDescription', 'ProductName', 'PackageFamilyName', 'FilePath')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.String]$SpecificFileNameLevel,

        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.Management.Automation.SwitchParameter]$NoUserPEs,

        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.Management.Automation.SwitchParameter]$NoScript,

        [Parameter(Mandatory = $false, ParameterSetName = 'Installed AppXPackages')]
        [System.Management.Automation.SwitchParameter]$Force,

        [Parameter(Mandatory = $false, ParameterSetName = 'Folder Path With WildCards')][System.Management.Automation.SwitchParameter]$EmbeddedVerboseOutput,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )
    Begin {
        [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)
        if (-NOT $SkipVersionCheck) { Update-WDACConfigPSModule -InvocationStatement $MyInvocation.Statement }

        if ([WDACConfig.GlobalVars]::ConfigCIBootstrap -eq $false) {
            Invoke-MockConfigCIBootstrap
            [WDACConfig.GlobalVars]::ConfigCIBootstrap = $true
        }

        [System.IO.DirectoryInfo]$StagingArea = [WDACConfig.StagingArea]::NewStagingArea('New-DenyWDACConfig')

        # Detecting if Confirm switch is used to bypass the confirmation prompts
        if ($Force -and -Not $Confirm) {
            $ConfirmPreference = 'None'
        }

        [System.IO.FileInfo]$FinalDenyPolicyPath = Join-Path -Path $StagingArea -ChildPath "DenyPolicy $PolicyName.xml"
        [System.IO.FileInfo]$FinalDenyPolicyCIPPath = Join-Path -Path $StagingArea -ChildPath "DenyPolicy $PolicyName.cip"

        # Due to the ACLs of the Windows directory, we make a copy of the AllowAll template policy in the Staging Area and then use it
        [System.IO.FileInfo]$AllowAllPolicyPath = Join-Path -Path $StagingArea -ChildPath 'AllowAllPolicy.xml'
        Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml' -Destination $AllowAllPolicyPath -Force

        [System.IO.FileInfo]$TempPolicyPath = Join-Path -Path $StagingArea -ChildPath 'DenyPolicy Temp.xml'

        # Flag indicating the final files should not be copied to the main user config directory
        [System.Boolean]$NoCopy = $false
    }

    process {

        Try {
            # Create deny supplemental policy for general files, apps etc.
            if ($Normal) {

                # The total number of the main steps for the progress bar to render
                $TotalSteps = $Deploy ? 4us : 3us
                $CurrentStep = 0us

                # An array to hold the temporary xml files of each user-selected folders
                [System.IO.FileInfo[]]$PolicyXMLFilesArray = @()

                $CurrentStep++
                Write-Progress -Id 22 -Activity 'Processing user selected Folders' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.Logger]::Write('Processing Program Folders From User input')
                for ($i = 0; $i -lt $ScanLocations.Count; $i++) {

                    # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
                    [System.Collections.Hashtable]$UserInputProgramFoldersPolicyMakerHashTable = @{
                        FilePath               = (Join-Path -Path $StagingArea -ChildPath "ProgramDir_ScanResults$($i).xml")
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

                    [WDACConfig.Logger]::Write("Currently scanning and creating a deny policy for the folder: $($ScanLocations[$i])")
                    New-CIPolicy @UserInputProgramFoldersPolicyMakerHashTable

                    $PolicyXMLFilesArray += (Join-Path -Path $StagingArea -ChildPath "ProgramDir_ScanResults$($i).xml")
                }

                Write-ColorfulTextWDACConfig -Color Pink -InputText 'The Deny policy with the following configuration is being created'
                $UserInputProgramFoldersPolicyMakerHashTable

                [WDACConfig.Logger]::Write('Adding the AllowAll default template policy path to the array of policy paths to merge')
                $PolicyXMLFilesArray += $AllowAllPolicyPath

                $CurrentStep++
                Write-Progress -Id 22 -Activity 'Merging the policies' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.Logger]::Write('Creating the final Deny base policy from the xml files in the paths array')
                $null = Merge-CIPolicy -PolicyPaths $PolicyXMLFilesArray -OutputFilePath $FinalDenyPolicyPath

                $CurrentStep++
                Write-Progress -Id 22 -Activity 'Creating the base policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.Logger]::Write('Assigning a name and resetting the policy ID')
                $null = [WDACConfig.SetCiPolicyInfo]::Set($FinalDenyPolicyPath, $true, $PolicyName, $null, $null)

                [WDACConfig.SetCiPolicyInfo]::Set($FinalDenyPolicyPath, ([version]'1.0.0.0'))

                [WDACConfig.CiRuleOptions]::Set($FinalDenyPolicyPath, [WDACConfig.CiRuleOptions+PolicyTemplate]::Base, $null, $null, $null, $null, $null, $null, $null, $null, $null)

                [WDACConfig.Logger]::Write('Converting the policy XML to .CIP')
                $null = ConvertFrom-CIPolicy -XmlFilePath $FinalDenyPolicyPath -BinaryFilePath $FinalDenyPolicyCIPPath

                if ($Deploy) {
                    $CurrentStep++
                    Write-Progress -Id 22 -Activity 'Deploying the base policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [WDACConfig.CiToolHelper]::UpdatePolicy($FinalDenyPolicyCIPPath)

                    Write-ColorfulTextWDACConfig -Color Pink -InputText "A Deny Base policy with the name '$PolicyName' has been deployed."
                }
                Write-Progress -Id 22 -Activity 'Complete.' -Completed
            }

            # Create Deny base policy for Driver files
            if ($Drivers) {

                # The total number of the main steps for the progress bar to render
                $TotalSteps = $Deploy ? 4us : 3us
                $CurrentStep = 0us

                $CurrentStep++
                Write-Progress -Id 23 -Activity 'Processing user selected Folders' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.Logger]::Write('Looping through each user-selected folder paths, scanning them, creating a temp policy file based on them')
                powershell.exe -NoProfile -Command {

                    # Prep the environment as a workaround for the ConfigCI bug
                    if ([System.IO.Directory]::Exists('C:\Program Files\Windows Defender\Offline')) {
                        [System.String]$RandomGUID = [System.Guid]::NewGuid().ToString()
                        New-CIPolicy -UserPEs -ScanPath 'C:\Program Files\Windows Defender\Offline' -Level hash -FilePath ".\$RandomGUID.xml" -NoShadowCopy -PathToCatroot 'C:\Program Files\Windows Defender\Offline' -WarningAction SilentlyContinue
                        Remove-Item -LiteralPath ".\$RandomGUID.xml" -Force
                    }

                    [System.Collections.ArrayList]$DriverFilesObject = @()

                    # loop through each user-selected folder paths
                    foreach ($ScanLocation in $args[0]) {

                        # DriverFile object holds the full details of all of the scanned drivers - This scan is greedy, meaning it stores as much information as it can find
                        # about each driver file, any available info about digital signature, hash, FileName, Internal Name etc. of each driver is saved and nothing is left out
                        $DriverFilesObject += Get-SystemDriver -ScanPath $ScanLocation -UserPEs
                    }

                    [System.Collections.Hashtable]$PolicyMakerHashTable = @{
                        FilePath               = $args[1]
                        DriverFiles            = $DriverFilesObject
                        Level                  = 'WHQLFilePublisher'
                        Fallback               = 'None'
                        MultiplePolicyFormat   = $true
                        UserWriteablePaths     = $true
                        Deny                   = $true
                        AllowFileNameFallbacks = $true
                    }
                    # Creating a base policy using the DriverFile object and specifying which detail about each driver should be used in the policy file
                    New-CIPolicy @PolicyMakerHashTable

                } -args $ScanLocations, $TempPolicyPath

                $CurrentStep++
                Write-Progress -Id 23 -Activity 'Merging the policies' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Merging AllowAll default policy with our Deny temp policy
                [WDACConfig.Logger]::Write('Merging AllowAll default template policy with our Deny temp policy')
                $null = Merge-CIPolicy -PolicyPaths $AllowAllPolicyPath, $TempPolicyPath -OutputFilePath $FinalDenyPolicyPath

                $CurrentStep++
                Write-Progress -Id 23 -Activity 'Configuring the base policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.Logger]::Write('Assigning a name and resetting the policy ID')
                $null = [WDACConfig.SetCiPolicyInfo]::Set($FinalDenyPolicyPath, $true, $PolicyName, $null, $null)

                [WDACConfig.SetCiPolicyInfo]::Set($FinalDenyPolicyPath, ([version]'1.0.0.0'))

                [WDACConfig.CiRuleOptions]::Set($FinalDenyPolicyPath, [WDACConfig.CiRuleOptions+PolicyTemplate]::Base, $null, $null, $null, $null, $null, $null, $null, $null, $null)

                [WDACConfig.Logger]::Write('Converting the policy XML to .CIP')
                $null = ConvertFrom-CIPolicy -XmlFilePath $FinalDenyPolicyPath -BinaryFilePath $FinalDenyPolicyCIPPath

                if ($Deploy) {
                    $CurrentStep++
                    Write-Progress -Id 23 -Activity 'Deploying the base policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [WDACConfig.CiToolHelper]::UpdatePolicy($FinalDenyPolicyCIPPath)

                    Write-ColorfulTextWDACConfig -Color Pink -InputText "A Deny Base policy with the name '$PolicyName' has been deployed."
                }
                Write-Progress -Id 23 -Activity 'Complete.' -Completed
            }

            # Creating Deny rule for Appx Packages
            if ($InstalledAppXPackages) {

                try {
                    # The total number of the main steps for the progress bar to render
                    $TotalSteps = $Deploy ? 3us : 2us
                    $CurrentStep = 0us

                    $CurrentStep++
                    Write-Progress -Id 24 -Activity 'Getting the Appx package' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    # Backing up PS Formatting Styles
                    [System.Collections.Hashtable]$OriginalStyle = @{}
                    $PSStyle.Formatting | Get-Member -MemberType Property | ForEach-Object -Process {
                        $OriginalStyle[$_.Name] = $PSStyle.Formatting.$($_.Name)
                    }

                    # Change the color for the list items to plum
                    $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(221,160,221))"

                    [WDACConfig.Logger]::Write('Displaying the installed Appx packages based on the supplied name')
                    Get-AppxPackage -Name $PackageName | Select-Object -Property Name, Publisher, version, PackageFamilyName, PackageFullName, InstallLocation, Dependencies, SignatureKind, Status

                    # Prompt for confirmation before proceeding
                    if ($PSCmdlet.ShouldProcess('', 'Select No to cancel and choose another name', 'Is this the intended results based on your Installed Appx packages?')) {

                        $CurrentStep++
                        Write-Progress -Id 24 -Activity 'Creating the base policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                        [WDACConfig.Logger]::Write('Creating a temporary Deny policy for the supplied Appx package name')
                        powershell.exe -NoProfile -Command {
                            # Get all the packages based on the supplied name
                            [Microsoft.Windows.Appx.PackageManager.Commands.AppxPackage[]]$Package = Get-AppxPackage -Name $args[0]

                            $Rules = @()

                            # Create rules for each package
                            foreach ($Item in $Package) {
                                $Rules += New-CIPolicyRule -Deny -Package $Item
                            }

                            # Generate the supplemental policy xml file
                            New-CIPolicy -MultiplePolicyFormat -FilePath $args[1] -Rules $Rules
                        } -args $PackageName, $TempPolicyPath

                        # Merging AllowAll default policy with our Deny temp policy
                        [WDACConfig.Logger]::Write('Merging AllowAll default template policy with our AppX Deny temp policy')
                        $null = Merge-CIPolicy -PolicyPaths $AllowAllPolicyPath, $TempPolicyPath -OutputFilePath $FinalDenyPolicyPath

                        [WDACConfig.Logger]::Write('Assigning a name and resetting the policy ID')
                        $null = [WDACConfig.SetCiPolicyInfo]::Set($FinalDenyPolicyPath, $true, $PolicyName, $null, $null)

                        [WDACConfig.SetCiPolicyInfo]::Set($FinalDenyPolicyPath, ([version]'1.0.0.0'))

                        [WDACConfig.CiRuleOptions]::Set($FinalDenyPolicyPath, [WDACConfig.CiRuleOptions+PolicyTemplate]::Base, $null, $null, $null, $null, $null, $null, $null, $null, $null)

                        [WDACConfig.Logger]::Write('Converting the policy XML to .CIP')
                        $null = ConvertFrom-CIPolicy -XmlFilePath $FinalDenyPolicyPath -BinaryFilePath $FinalDenyPolicyCIPPath

                        if ($Deploy) {
                            $CurrentStep++
                            Write-Progress -Id 24 -Activity 'Deploying the base policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                            [WDACConfig.CiToolHelper]::UpdatePolicy($FinalDenyPolicyCIPPath)

                            Write-ColorfulTextWDACConfig -Color Pink -InputText "A Deny Base policy with the name '$PolicyName' has been deployed."
                        }
                    }
                    else {
                        $NoCopy = $true
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
                $TotalSteps = $Deploy ? 3us : 2us
                $CurrentStep = 0us

                $CurrentStep++
                Write-Progress -Id 29 -Activity 'Creating the wildcard deny policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Using Windows PowerShell to handle serialized data since PowerShell core throws an error
                [WDACConfig.Logger]::Write('Creating the deny policy file')
                powershell.exe -NoProfile -Command {
                    $RulesWildCards = New-CIPolicyRule -Deny -FilePathRule $args[0]
                    New-CIPolicy -MultiplePolicyFormat -FilePath $args[1] -Rules $RulesWildCards
                } -args $FolderPath, $TempPolicyPath

                # Merging AllowAll default policy with our Deny temp policy
                [WDACConfig.Logger]::Write('Merging AllowAll default template policy with our Wildcard Deny temp policy')
                $null = Merge-CIPolicy -PolicyPaths $AllowAllPolicyPath, $TempPolicyPath -OutputFilePath $FinalDenyPolicyPath

                $CurrentStep++
                Write-Progress -Id 29 -Activity 'Configuring the wildcard deny policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.Logger]::Write('Assigning a name and resetting the policy ID')
                $null = [WDACConfig.SetCiPolicyInfo]::Set($FinalDenyPolicyPath, $true, $PolicyName, $null, $null)

                [WDACConfig.SetCiPolicyInfo]::Set($FinalDenyPolicyPath, ([version]'1.0.0.0'))

                [WDACConfig.CiRuleOptions]::Set($FinalDenyPolicyPath, [WDACConfig.CiRuleOptions+PolicyTemplate]::Base, $null, $null, $null, $null, $null, $null, $null, $null, $null)

                [WDACConfig.Logger]::Write('Converting the policy XML to .CIP')
                $null = ConvertFrom-CIPolicy -XmlFilePath $FinalDenyPolicyPath -BinaryFilePath $FinalDenyPolicyCIPPath

                if ($Deploy) {
                    $CurrentStep++
                    Write-Progress -Id 29 -Activity 'Deploying the base policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [WDACConfig.CiToolHelper]::UpdatePolicy($FinalDenyPolicyCIPPath)

                    if ($EmbeddedVerboseOutput) {
                        [WDACConfig.Logger]::Write("A Deny Base policy with the name '$PolicyName' has been deployed.")
                    }
                    else {
                        Write-ColorfulTextWDACConfig -Color Pink -InputText "A Deny Base policy with the name '$PolicyName' has been deployed."
                    }
                }
                Write-Progress -Id 29 -Activity 'Complete.' -Completed
            }
        }
        Catch {
            $NoCopy = $true
            Throw $_
        }
        finally {
            # If the cmdlet is not running in embedded mode
            if (-NOT $EmbeddedVerboseOutput) {
                # If there was no error
                if (!$NoCopy) {
                    # Display the output
                    if ($Deploy) {
                        Write-FinalOutput -Paths $FinalDenyPolicyPath
                    }
                    else {
                        Write-FinalOutput -Paths $FinalDenyPolicyPath, $FinalDenyPolicyCIPPath
                    }
                }
            }

            # Copy the final policy files to the user config directory
            if (!$NoCopy) {
                Copy-Item -Path ($Deploy ? $FinalDenyPolicyPath : $FinalDenyPolicyPath, $FinalDenyPolicyCIPPath) -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force
            }
            if (![WDACConfig.GlobalVars]::DebugPreference) {
                Remove-Item -Path $StagingArea -Recurse -Force
            }
        }
    }

    <#
.SYNOPSIS
    Creates Deny App Control for Business base policies
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-DenyWDACConfig
.DESCRIPTION
    Using official Microsoft methods to create Deny App Control for Business base policies
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
.PARAMETER EmbeddedVerboseOutput
    Used for when the WDACConfig module is in the embedded mode by the Harden Windows Security module
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
    System.IO.DirectoryInfo
    System.IO.DirectoryInfo[]
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
.EXAMPLE
    New-DenyWDACConfig -PolicyName 'MyDenyPolicy' -Normal -ScanLocations 'C:\Program Files', 'C:\Program Files (x86)'
    Creates a Deny standalone base policy by scanning the specified folders for files.
#>
}
