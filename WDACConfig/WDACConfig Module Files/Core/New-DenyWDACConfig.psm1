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

        [parameter(Mandatory = $true, ParameterSetName = 'Installed AppXPackages', ValueFromPipelineByPropertyName = $true)]
        [System.String]$PackageName,

        [ValidatePattern('^[a-zA-Z0-9 ]+$', ErrorMessage = 'The Supplemental Policy Name can only contain alphanumeric characters and spaces.')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String]$PolicyName,

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

        [Parameter(Mandatory = $false)]
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
.INPUTS
    System.String[]
    System.String
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
#>
}

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\Resources\ArgumentCompleters.ps1"
Register-ArgumentCompleter -CommandName 'New-DenyWDACConfig' -ParameterName 'ScanLocations' -ScriptBlock $ArgumentCompleterFolderPathsPicker
Register-ArgumentCompleter -CommandName 'New-DenyWDACConfig' -ParameterName 'PackageName' -ScriptBlock $ArgumentCompleterAppxPackageNames

# SIG # Begin signature block
# MIILhgYJKoZIhvcNAQcCoIILdzCCC3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBEGfiM3cxzTGrD
# vzvSMtd2NhIez9q6HkkAKoNBNoG3RKCCB88wggfLMIIFs6ADAgECAhNUAAAABzgp
# /t9ITGbLAAAAAAAHMA0GCSqGSIb3DQEBDQUAMEQxEzARBgoJkiaJk/IsZAEZFgNj
# b20xFDASBgoJkiaJk/IsZAEZFgRCaW5nMRcwFQYDVQQDEw5CaW5nLVNFUlZFUi1D
# QTAgFw0yMzEyMjcwODI4MDlaGA8yMTMzMTIyNzA4MzgwOVoweDELMAkGA1UEBhMC
# VUsxFjAUBgNVBAoTDVNweU5ldEdpcmwgQ28xKjAoBgNVBAMTIUhvdENha2VYIENv
# ZGUgU2lnbmluZyBDZXJ0aWZpY2F0ZTElMCMGCSqGSIb3DQEJARYWU3B5bmV0Z2ly
# bEBvdXRsb29rLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANsD
# szHV9Ea21AhOw4a35P1R30HHtmz+DlWKk/a4FvYQivl9dd+f+SZaybl0O96H6YNp
# qLnx7KD9TSEBbB+HxjE39GfWoX2R1VlPaDqkbGMA0XmnUB+/5CsbhktY4gbvJpW5
# LWXk0xUmCSvLMs7eiuBOGNs3zw5xVVNhsES6/aYMCWREI9YPTVbh7En6P4uZOisy
# K2tZtkSe/TXabfr1KtNhELr3DpTNtJBMBLzhz8d6ztJExKebFqpiaNqF7TpTOTRI
# 4P02k6u6lsWMz/rH9mMHdGSyBJ3DEyJGL9QT4jO4BFLHsxHuWTpjxnqxZNjwLTjB
# NEhH+VcKIIy2iWHfWwK2Nwr/3hzDbfqsWrMrXvvCqGpei+aZTxyplbMPpmd5myKo
# qLI58zc7cMi/HuAbbjo1YWxd/J1shHifMfhXfuncjHr7RTGC3BaEzwirQ12t1Z2K
# Zn2AhLnhSElbgZppt+WS4bmzT6L693srDxSMcBpRcu8NyDteLVCmgfBGXDdfAKEZ
# KXPi9liV0b66YQWnBp9/3bYwtYTh5VwjfSVAMfWsrMpIeGmvGUcsnQCqCxCulHKX
# onoYmbyotyOiXObXVgzB2G0k+VjxiFTSb1ENf3GJV1FJbzbch/p/tASY9w2L7kT/
# l+/Nnp4XOuPDYhm/0KWgEH7mUyq4KkP/BG/on7Q5AgMBAAGjggJ+MIICejA8Bgkr
# BgEEAYI3FQcELzAtBiUrBgEEAYI3FQjinCqC5rhWgdmZEIP42AqB4MldgT6G3Kk+
# mJFMAgFkAgEOMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDAM
# BgNVHRMBAf8EAjAAMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYBBQUHAwMwHQYDVR0O
# BBYEFFr7G/HfmP3Om/RStyhaEtEFmSYKMB8GA1UdEQQYMBaBFEhvdGNha2V4QG91
# dGxvb2suY29tMB8GA1UdIwQYMBaAFChQ2b1sdIHklqMDHsFKcUCX6YREMIHIBgNV
# HR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPUJpbmctU0VSVkVSLUNBLENO
# PVNlcnZlcixDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2Vy
# dmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1CaW5nLERDPWNvbT9jZXJ0aWZpY2F0
# ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9u
# UG9pbnQwgb0GCCsGAQUFBwEBBIGwMIGtMIGqBggrBgEFBQcwAoaBnWxkYXA6Ly8v
# Q049QmluZy1TRVJWRVItQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZp
# Y2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9QmluZyxEQz1jb20/
# Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRo
# b3JpdHkwDQYJKoZIhvcNAQENBQADggIBAE/AISQevRj/RFQdRbaA0Ffk3Ywg4Zui
# +OVuCHrswpja/4twBwz4M58aqBSoR/r9GZo69latO74VMmki83TX+Pzso3cG5vPD
# +NLxwAQUo9b81T08ZYYpdWKv7f+9Des4WbBaW9AGmX+jJn+JLAFp+8V+nBkN2rS9
# 47seK4lwtfs+rVMGBxquc786fXBAMRdk/+t8G58MZixX8MRggHhVeGc5ecCRTDhg
# nN68MhJjpwqsu0sY2NeKz5gMSk6wvt+NDPcfSZyNo1uSEMKTl/w5UH7mnrv0D4fZ
# UOY3cpIwbIagwdBuFupKG/m1I2LXZdLgGfOtZyZyw+c5Kd0KlMxonBiVoqN7PvoA
# 7sfwDI7PMLMQ3mseFbIpSUQGXHGeyouN1jF5ciySfHnW1goiG8tfDKNAT7WEz+ZT
# c1iIH+lCDUV/LmFD1Bvj2A9Q01C9BsScH+9vb2CnIwaSmfFRI6PY9cKOEHdy/ULi
# hp72QBd6W6ZQMZWXI5m48DdiKlQGA1aCdNN6+C0of43a7L0rAtLPYKySpd6gc34I
# h7/DgGLqXg0CO4KtbGdEWfKHqvh0qYLRmo/obhyVMYib4ceKrCcdc9aVlng/25nE
# ExvokF0vVXKSZkRUAfNHmmfP3lqbjABHC2slbStolocXwh8CoN8o2iOEMnY/xez0
# gxGYBY5UvhGKMYIDDTCCAwkCAQEwWzBEMRMwEQYKCZImiZPyLGQBGRYDY29tMRQw
# EgYKCZImiZPyLGQBGRYEQmluZzEXMBUGA1UEAxMOQmluZy1TRVJWRVItQ0ECE1QA
# AAAHOCn+30hMZssAAAAAAAcwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIB
# DDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEE
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgZ3glNRpm19lt
# SN5Pgj6/FtkI+4T8Jzc301lsXOJuW1owDQYJKoZIhvcNAQEBBQAEggIAmzh5CgSy
# pqFyV7uCJyAdylfg3EnUiDqgip4ccVFeWPYRNTyAo+qACLvI8k/dqQbPw/6zgscX
# 9bPIsPUVcjRivvbNMdvX0xBJVslBJffIApmbiXJhRJMZ4jcdmYOILSE0k0eLGjy2
# MqzdmY4xU5Ox6K31HInSRdrf9yqDgo8rwK9QbR1A26bQ2rmIeYE0bz7oG4p7IjxI
# 2rXqryB5h+ZHVqetcfj+ZrHDMhqAAmHg/BtVHznkEcI8ClkV6YX9MhWClzGDrE0H
# mCgaH9tgG3MCL7pDttdCZmHSoG0UjQPxeTskg1hpU1++YIDR2dWmNgMgZuh67eBX
# lXpTnAtH6VRcbkPKo919mqxMQJeeG2lHmK7Jna5aSiNbpzAlhQpOUlobB793eNRw
# c26WQ5Mck9BddNA4RRR9iqvP6RkRlCECDaePhqPyWrfEVjQvKYvbsCqpCQ50i5OR
# W/9CtPGI0J8dOtLmW/VLyTIK5MAzRh05MvEYCzJwyIb+JNhA3XQSSZbrrR3HNKRR
# D4aheUGgsLziuZ9adJviBlOTW1YH8Qs2VoMSRRWG33bsT87DA8Cyk0FQrgo76iEA
# X/xmI7Eu72GBiXAffwk3f8ReieU9dhrvogvdDi6dEjaoSqX2YUqXQ0ufw7Kg/fX/
# IIEkfPO/LlJ2VFLUCIIJAUP5S+QyvEYsO/w=
# SIG # End signature block
