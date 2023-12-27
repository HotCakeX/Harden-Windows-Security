Function New-SupplementalWDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = 'Normal',
        PositionalBinding = $false,
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    Param(
        # Main parameters for position 0
        [Alias('N')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')][System.Management.Automation.SwitchParameter]$Normal,
        [Alias('W')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Folder Path With WildCards')][System.Management.Automation.SwitchParameter]$PathWildCards,
        [Alias('P')]
        [parameter(mandatory = $false, ParameterSetName = 'Installed AppXPackages')][System.Management.Automation.SwitchParameter]$InstalledAppXPackages,

        [parameter(Mandatory = $true, ParameterSetName = 'Installed AppXPackages', ValueFromPipelineByPropertyName = $true)]
        [System.String]$PackageName,

        [ValidateScript({ Test-Path -Path $_ -PathType 'Container' }, ErrorMessage = 'The path you selected is not a folder path.')]
        [parameter(Mandatory = $true, ParameterSetName = 'Normal', ValueFromPipelineByPropertyName = $true)]
        [System.String]$ScanLocation,

        [ValidatePattern('\*', ErrorMessage = 'You did not supply a path that contains wildcard character (*) .')]
        [parameter(Mandatory = $true, ParameterSetName = 'Folder Path With WildCards', ValueFromPipelineByPropertyName = $true)]
        [System.String]$FolderPath,

        [ValidatePattern('^[a-zA-Z0-9 ]+$', ErrorMessage = 'The Supplemental Policy Name can only contain alphanumeric and space characters.')]
        [parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String]$SuppPolicyName,

        [ValidatePattern('\.xml$')]
        [ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' }, ErrorMessage = 'The path you selected is not a file path.')]
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [System.String]$PolicyPath,

        [parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$Deploy,

        [ValidateSet('OriginalFileName', 'InternalName', 'FileDescription', 'ProductName', 'PackageFamilyName', 'FilePath')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.String]$SpecificFileNameLevel,

        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.Management.Automation.SwitchParameter]$NoUserPEs,

        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.Management.Automation.SwitchParameter]$NoScript,

        [ValidateSet([Levelz])]
        [parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.String]$Level = 'FilePublisher',

        [ValidateSet([Fallbackz])]
        [parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.String[]]$Fallbacks = 'Hash',

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

        #Region User-Configurations-Processing-Validation
        # If any of these parameters, that are mandatory for all of the position 0 parameters, isn't supplied by user, start validating the user config file
        if (!$PolicyPath) {
            # Read User configuration file if it exists
            $UserConfig = Get-Content -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json" -ErrorAction SilentlyContinue
            if ($UserConfig) {
                # Validate the Json file and read its content to make sure it's not corrupted
                try { $UserConfig = $UserConfig | ConvertFrom-Json }
                catch {
                    Write-Error -Message 'User Configuration Json file is corrupted, deleting it...' -ErrorAction Continue
                    Remove-CommonWDACConfig
                }
            }
        }
        # If PolicyPaths has no values
        if (!$PolicyPath) {
            if ($UserConfig.UnsignedPolicyPath) {
                # validate each policyPath read from user config file
                if (Test-Path -Path $($UserConfig.UnsignedPolicyPath)) {
                    $PolicyPath = $UserConfig.UnsignedPolicyPath
                }
                else {
                    throw 'The currently saved value for UnsignedPolicyPath in user configurations is invalid.'
                }
            }
            else {
                throw 'PolicyPath parameter cannot be empty and no valid configuration was found for UnsignedPolicyPath.'
            }
        }
        #Endregion User-Configurations-Processing-Validation

        # Ensure when user selects the -Deploy parameter, the base policy is not signed
        if ($Deploy) {
            $XmlTest = [System.Xml.XmlDocument](Get-Content -Path $PolicyPath)
            $RedFlag1 = $XmlTest.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
            $RedFlag2 = $XmlTest.SiPolicy.UpdatePolicySigners.UpdatePolicySigner.SignerId
            if ($RedFlag1 -or $RedFlag2) {
                Throw 'You are using -Deploy parameter and the selected base policy is Signed. Please use Deploy-SignedWDACConfig to deploy it.'
            }
        }

        # Detecting if Confirm switch is used to bypass the confirmation prompts
        if ($Force -and -Not $Confirm) {
            $ConfirmPreference = 'None'
        }
    }

    process {

        if ($Normal) {

            # The total number of the main steps for the progress bar to render
            [System.Int16]$TotalSteps = $Deploy ? 3 : 2
            [System.Int16]$CurrentStep = 0

            $CurrentStep++
            Write-Progress -Id 19 -Activity 'Processing user selected folders' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Processing Program Folder From User input'
            # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
            [System.Collections.Hashtable]$PolicyMakerHashTable = @{
                FilePath               = "SupplementalPolicy $SuppPolicyName.xml"
                ScanPath               = $ScanLocation
                Level                  = $Level
                Fallback               = $Fallbacks
                MultiplePolicyFormat   = $true
                UserWriteablePaths     = $true
                AllowFileNameFallbacks = $true
            }
            # Assess user input parameters and add the required parameters to the hash table
            if ($SpecificFileNameLevel) { $PolicyMakerHashTable['SpecificFileNameLevel'] = $SpecificFileNameLevel }
            if ($NoScript) { $PolicyMakerHashTable['NoScript'] = $true }
            if (!$NoUserPEs) { $PolicyMakerHashTable['UserPEs'] = $true }

            Write-ColorfulText -Color HotPink -InputText 'Generating Supplemental policy with the following specifications:'
            $PolicyMakerHashTable
            Write-Host -Object ''

            # Create the supplemental policy via parameter splatting
            New-CIPolicy @PolicyMakerHashTable

            $CurrentStep++
            Write-Progress -Id 19 -Activity 'Configuring the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Changing the policy type from base to Supplemental, assigning its name and resetting its policy ID'
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath "SupplementalPolicy $SuppPolicyName.xml" -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath -PolicyName "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')"
            [System.String]$PolicyID = $PolicyID.Substring(11)

            Write-Verbose -Message 'Setting the Supplemental policy version to 1.0.0.0'
            Set-CIPolicyVersion -FilePath "SupplementalPolicy $SuppPolicyName.xml" -Version '1.0.0.0'

            Write-Verbose -Message 'Making sure policy rule options that do not belong to a Supplemental policy do not exist'
            @(0, 1, 2, 3, 4, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object -Process {
                Set-RuleOption -FilePath "SupplementalPolicy $SuppPolicyName.xml" -Option $_ -Delete }

            Write-Verbose -Message 'Setting the HVCI to Strict'
            Set-HVCIOptions -Strict -FilePath "SupplementalPolicy $SuppPolicyName.xml"

            Write-Verbose -Message 'Converting the Supplemental policy XML file to a CIP file'
            ConvertFrom-CIPolicy -XmlFilePath "SupplementalPolicy $SuppPolicyName.xml" -BinaryFilePath "$PolicyID.cip" | Out-Null

            Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyFile = SupplementalPolicy $SuppPolicyName.xml"
            Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyGUID = $PolicyID"

            if ($Deploy) {
                $CurrentStep++
                Write-Progress -Id 19 -Activity 'Deploying the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Deploying the Supplemental policy'
                &'C:\Windows\System32\CiTool.exe' --update-policy "$PolicyID.cip" -json | Out-Null
                Write-ColorfulText -Color Pink -InputText "A Supplemental policy with the name $SuppPolicyName has been deployed."

                Write-Verbose -Message 'Removing the CIP file after deployment'
                Remove-Item -Path "$PolicyID.cip" -Force
            }
            Write-Progress -Id 19 -Activity 'Complete.' -Completed
        }

        if ($PathWildCards) {

            # The total number of the main steps for the progress bar to render
            [System.Int16]$TotalSteps = $Deploy ? 2 : 1
            [System.Int16]$CurrentStep = 0

            $CurrentStep++
            Write-Progress -Id 20 -Activity 'Creating the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            # Using Windows PowerShell to handle serialized data since PowerShell core throws an error
            Write-Verbose -Message 'Creating the Supplemental policy file'
            powershell.exe -Command {
                $RulesWildCards = New-CIPolicyRule -FilePathRule $args[0]
                New-CIPolicy -MultiplePolicyFormat -FilePath ".\SupplementalPolicy $($args[1]).xml" -Rules $RulesWildCards
            } -args $FolderPath, $SuppPolicyName

            Write-Verbose -Message 'Changing the policy type from base to Supplemental, assigning its name and resetting its policy ID'
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath ".\SupplementalPolicy $SuppPolicyName.xml" -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath -PolicyName "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')"
            [System.String]$PolicyID = $PolicyID.Substring(11)

            Write-Verbose -Message 'Setting the Supplemental policy version to 1.0.0.0'
            Set-CIPolicyVersion -FilePath ".\SupplementalPolicy $SuppPolicyName.xml" -Version '1.0.0.0'

            Write-Verbose -Message 'Making sure policy rule options that do not belong to a Supplemental policy do not exist'
            @(0, 1, 2, 3, 4, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object -Process {
                Set-RuleOption -FilePath ".\SupplementalPolicy $SuppPolicyName.xml" -Option $_ -Delete }

            Write-Verbose -Message 'Adding policy rule option 18 Disabled:Runtime FilePath Rule Protection'
            Set-RuleOption -FilePath ".\SupplementalPolicy $SuppPolicyName.xml" -Option 18

            Write-Verbose -Message 'Setting the HVCI to Strict'
            Set-HVCIOptions -Strict -FilePath ".\SupplementalPolicy $SuppPolicyName.xml"

            Write-Verbose -Message 'Converting the Supplemental policy XML file to a CIP file'
            ConvertFrom-CIPolicy -XmlFilePath ".\SupplementalPolicy $SuppPolicyName.xml" -BinaryFilePath "$PolicyID.cip" | Out-Null

            Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyFile = SupplementalPolicy $SuppPolicyName.xml"
            Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyGUID = $PolicyID"

            if ($Deploy) {
                $CurrentStep++
                Write-Progress -Id 20 -Activity 'Deploying the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Deploying the Supplemental policy'
                &'C:\Windows\System32\CiTool.exe' --update-policy "$PolicyID.cip" -json | Out-Null
                Write-ColorfulText -Color Pink -InputText "A Supplemental policy with the name $SuppPolicyName has been deployed."

                Write-Verbose -Message 'Removing the CIP file after deployment'
                Remove-Item -Path "$PolicyID.cip" -Force
            }
            Write-Progress -Id 20 -Activity 'Complete.' -Completed
        }

        if ($InstalledAppXPackages) {
            try {
                # The total number of the main steps for the progress bar to render
                [System.Int16]$TotalSteps = $Deploy ? 3 : 2
                [System.Int16]$CurrentStep = 0

                $CurrentStep++
                Write-Progress -Id 21 -Activity 'Getting the Appx package' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

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
                    Write-Progress -Id 21 -Activity 'Creating the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Creating a policy for the supplied Appx package name and its dependencies (if any)'
                    powershell.exe -Command {
                        # Get all the packages based on the supplied name
                        $Package = Get-AppxPackage -Name $args[0]

                        # Get package dependencies if any
                        $PackageDependencies = $Package.Dependencies

                        # Create rules for each package
                        foreach ($Item in $Package) {
                            $Rules += New-CIPolicyRule -Package $Item
                        }

                        # Create rules for each package dependency, if any
                        if ($PackageDependencies) {
                            foreach ($Item in $PackageDependencies) {
                                $Rules += New-CIPolicyRule -Package $Item
                            }
                        }

                        # Generate the supplemental policy xml file
                        New-CIPolicy -MultiplePolicyFormat -FilePath ".\SupplementalPolicy $($args[1]).xml" -Rules $Rules
                    } -args $PackageName, $SuppPolicyName

                    Write-Verbose -Message 'Converting the policy type from base to Supplemental, assigning its name and resetting its policy ID'
                    [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath ".\SupplementalPolicy $SuppPolicyName.xml" -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath -PolicyName "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')"
                    [System.String]$PolicyID = $PolicyID.Substring(11)

                    Write-Verbose -Message 'Setting the Supplemental policy version to 1.0.0.0'
                    Set-CIPolicyVersion -FilePath ".\SupplementalPolicy $SuppPolicyName.xml" -Version '1.0.0.0'

                    Write-Verbose -Message 'Making sure the policy rule options that do not belong to a Supplemental policy do not exist'
                    @(0, 1, 2, 3, 4, 9, 10, 11, 12, 15, 16, 17, 18, 19, 20) | ForEach-Object -Process {
                        Set-RuleOption -FilePath ".\SupplementalPolicy $SuppPolicyName.xml" -Option $_ -Delete }

                    Write-Verbose -Message 'Setting the HVCI to Strict'
                    Set-HVCIOptions -Strict -FilePath ".\SupplementalPolicy $SuppPolicyName.xml"

                    Write-Verbose -Message 'Converting the Supplemental policy XML file to a CIP file'
                    ConvertFrom-CIPolicy -XmlFilePath ".\SupplementalPolicy $SuppPolicyName.xml" -BinaryFilePath "$PolicyID.cip" | Out-Null

                    Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyFile = SupplementalPolicy $SuppPolicyName.xml"
                    Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyGUID = $PolicyID"

                    if ($Deploy) {
                        $CurrentStep++
                        Write-Progress -Id 21 -Activity 'Deploying the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                        Write-Verbose -Message 'Deploying the Supplemental policy'
                        &'C:\Windows\System32\CiTool.exe' --update-policy "$PolicyID.cip" -json | Out-Null
                        Write-ColorfulText -Color Pink -InputText "A Supplemental policy with the name $SuppPolicyName has been deployed."

                        Write-Verbose -Message 'Removing the CIP file after deployment'
                        Remove-Item -Path "$PolicyID.cip" -Force
                    }
                }
            }
            finally {
                # Restore PS Formatting Styles
                $OriginalStyle.Keys | ForEach-Object -Process {
                    $PSStyle.Formatting.$_ = $OriginalStyle[$_]
                }
                Write-Progress -Id 21 -Activity 'Complete.' -Completed
            }
        }
    }

    <#
.SYNOPSIS
    Automate a lot of tasks related to WDAC (Windows Defender Application Control)
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-SupplementalWDACConfig
.DESCRIPTION
    Using official Microsoft methods, configure and use Windows Defender Application Control
.COMPONENT
    Windows Defender Application Control, ConfigCI PowerShell module
.FUNCTIONALITY
    Automate various tasks related to Windows Defender Application Control (WDAC)
.PARAMETER Normal
    Make a Supplemental policy by scanning a directory, you can optionally use other parameters too to fine tune the scan process
.PARAMETER PathWildCards
    Make a Supplemental policy by scanning a directory and creating a wildcard FilePath rules for all of the files inside that directory, recursively
.PARAMETER InstalledAppXPackages
    Make a Supplemental policy based on the Package Family Name of an installed Windows app (Appx)
.PARAMETER PackageName
    Enter the package name of an installed app. Supports wildcard * character. e.g., *Edge* or "*Microsoft*".
.PARAMETER ScanLocation
    The directory or drive that you want to scan for files that will be allowed to run by the Supplemental policy.
.PARAMETER FolderPath
    Path of a folder that you want to allow using wildcards *.
.PARAMETER SuppPolicyName
    Add a descriptive name for the Supplemental policy. Accepts only alphanumeric and space characters.
    It is used by the entire Cmdlet.
.PARAMETER PolicyPath
    Browse for the xml file of the Base policy this Supplemental policy is going to expand. Supports tab completion by showing only .xml files with Base Policy Type.
    It is used by the entire Cmdlet.
.PARAMETER Deploy
    Indicates that the module will automatically deploy the Supplemental policy after creation.
    It is used by the entire Cmdlet.
.PARAMETER SpecificFileNameLevel
    You can choose one of the following options: "OriginalFileName", "InternalName", "FileDescription", "ProductName", "PackageFamilyName", "FilePath"
.PARAMETER NoUserPEs
    By default the module includes user PEs in the scan, but when you use this switch parameter, they won't be included.
.PARAMETER NoScript
    Refer to this page for more info: https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-noscript
.PARAMETER Level
    The level that determines how the selected folder will be scanned.
    The default value for it is FilePublisher.
.PARAMETER Fallbacks
    The fallback level(s) that determine how the selected folder will be scanned.
    The default value for it is Hash.
.PARAMETER Force
    It's used by the entire Cmdlet. Indicates that the confirmation prompts will be bypassed.
.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases
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
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'PolicyPath' -ScriptBlock $ArgumentCompleterPolicyPathsBasePoliciesOnly
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'PackageName' -ScriptBlock $ArgumentCompleterAppxPackageNames
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'ScanLocation' -ScriptBlock $ArgumentCompleterFolderPathsPicker
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'FolderPath' -ScriptBlock $ArgumentCompleterFolderPathsPickerWildCards

# SIG # Begin signature block
# MIILhgYJKoZIhvcNAQcCoIILdzCCC3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAdqdhs/OCYtMx/
# bz8eZR6L+TkbwaA1PHTQ81r87IT4qKCCB88wggfLMIIFs6ADAgECAhNUAAAABzgp
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
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQghXlHebwq3vAh
# ApGoVUda8KKWWIl0x98UgVi/cAk9P3owDQYJKoZIhvcNAQEBBQAEggIAtGJ0TKjx
# 705CkxxLITCWXGaFgryplSSS4WfhszU6AtPxKHyQR3fc+zU8BHwcMd8nm6sILGOO
# NwiaoLEXV7t0qI0dh+2mzR65OA9BmKGe+kHJdZLQnb7BuWeFP8qRd3sXb3EZ+s0v
# aalukQYJi04MYNBtvO6XhAHiehVZ/VVbXgvSL1vjJixRHP+psEXlTZhlb+/5c9TM
# V1NyNQ3sOFfBAB9W3BT50+Xq1s2sxDoWRA69W6aDUtWL2iT67uUz12FcGLzErns/
# laXx5TrBCISfiH23KRl3xkQI4gC3L8isLblIaHAYYzkrjSKDdX2Pt1pYJbMwzNZf
# FMcVVYuITA4CD0Iv5vK5emre/hWbMYp4jhRv+c6JLDGUsYXmPXJu27IFA40CvNQR
# BYRHYun8o9gqvBZ1i6KxfEhpRee/7ybZDePY4w9mRQRnkS66+poS93BgJf5FDh6H
# aMzi5E3ivL1mKIXkoSrlfjlaJCZtVZ7Sk/mZ07xDKU5cSoE4LCRofw8yjiH/09HC
# DQAx/9ghoeNK6LU2p7KkHSSBNfWDT8kRL74O4W2HMu5tvdCIHAEvFuVIgIF9i5VE
# CMgQc/kCIsJ9NsOqPTpCXNIpMNXhxt+4eobkBQF9+l1dEJ86Ktbd2zfOW5qVkeNw
# dMw9N9hu+gh8nuXiGcI8nSiWsyPnsReCaNw=
# SIG # End signature block
