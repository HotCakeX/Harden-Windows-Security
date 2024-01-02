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

        [ValidateCount(1, 232)]
        [ValidatePattern('^[a-zA-Z0-9 \-]+$', ErrorMessage = 'The policy name can only contain alphanumeric, space and dash (-) characters.')]
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
        # If PolicyPath was not provided by user, check if a valid value exists in user configs, if so, use it, otherwise throw an error
        if (!$PolicyPath) {
            if (Test-Path -Path (Get-CommonWDACConfig -UnsignedPolicyPath)) {
                $PolicyPath = Get-CommonWDACConfig -UnsignedPolicyPath
            }
            else {
                throw 'PolicyPath parameter cannot be empty and no valid user configuration was found for UnsignedPolicyPath.'
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
.PARAMETER Verbose
    It's used by the entire Cmdlet. Indicates that the verbose messages will be displayed.
.INPUTS
    System.String[]
    System.String
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
.EXAMPLE
    New-SupplementalWDACConfig -Normal -SuppPolicyName 'MyPolicy' -PolicyPath 'C:\MyPolicy.xml' -ScanLocation 'C:\Program Files\MyApp' -Deploy
    This example will create a Supplemental policy named MyPolicy based on the Base policy located at C:\MyPolicy.xml and will scan the C:\Program Files\MyApp folder for files that will be allowed to run by the Supplemental policy.
#>
}

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\Resources\ArgumentCompleters.ps1"
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'PolicyPath' -ScriptBlock $ArgumentCompleterPolicyPathsBasePoliciesOnly
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'PackageName' -ScriptBlock $ArgumentCompleterAppxPackageNames
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'ScanLocation' -ScriptBlock $ArgumentCompleterFolderPathsPicker
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'FolderPath' -ScriptBlock $ArgumentCompleterFolderPathsPickerWildCards

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC/7cicNa8x/anz
# +ULL+OyoImIftYhBjFRIwjZ/GW4ztqCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgZoNvOpazmLb4UvHCcHFDHkP+PpoY53Sq+D5fMYBdFIEwDQYJKoZIhvcNAQEB
# BQAEggIAB+gITTUDDzezao3etCAI5hRQJ03MGrvKXxalwoGysPPwXDi4hV9Zbqpz
# bBMsvAXOPNyTiVYwQ3p5UcJ4OppLwVhOjP8HP4gi8+9MAS3/t+4bzTuyKmo7WzF1
# loDxowZADFlBnhACWq5UqGX56cYMuvghYFRfqew+9bIcwSljNfgkbY2sjorEx7UI
# aY9sAGDGfyw5TxZjUVybHfGu/+Zt4k/38eXFrlM6tTS2hx0vlR8nAYZkXAy/ue1O
# FaTTHuWrYbS394BmTiflsJsS8bH0Ce02x7wK3oV1TUxiP9BEu+hVgx/3BmR72Ymv
# nBOtdgiDWDloLSu4yUwEm/WY2D1dEltg+bIdCVWIoXWejtorAdMAYfz0IjqLzr3A
# X3FKotEGI06IIPGqbrhQ8UqQ4D3BPNM2mO9DPJ4YqPqv5ebuekWI5rimoUmobtRu
# jOHhtbRVZ3jVHQH7TU3v2PkWVL5RedPtCeLbP81gZymQiWt4b4saxfA6WBlXnOvf
# pk1L2U78SE65prYnLroYCXLzQOTivWL6ucuM0fnaoTlR21Ee1/7V1J4mhwVXwE2z
# rQbjAWYEICMHfGaeI4rVsgxx9znLCXxR5laFPdNmZ55kl7DGTjLlm7Qnqzgwpy2S
# Np3sMK8P64jkOgkIZP0mMDT2PAQpDZ0vjkVVQP8SFlEZa46gYWk=
# SIG # End signature block
