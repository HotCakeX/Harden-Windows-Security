Function Deploy-SignedWDACConfig {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    [OutputType([System.String])]
    Param(
        [ValidateScript({ Test-CiPolicy -XmlFile $_ })]
        [parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [System.IO.FileInfo[]]$PolicyPaths,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$Deploy,

        [ValidatePattern('\.cer$')]
        [ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' }, ErrorMessage = 'The path you selected is not a file path.')]
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)][System.IO.FileInfo]$CertPath,

        [ValidateSet([CertCNz])]
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)][System.String]$CertCN,

        [ValidatePattern('\.exe$')]
        [ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' }, ErrorMessage = 'The path you selected is not a file path.')]
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [System.IO.FileInfo]$SignToolPath,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$Force,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )

    begin {
        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null
        # Detecting if Debug switch is used, will do debugging actions based on that
        $PSBoundParameters.Debug.IsPresent ? ([System.Boolean]$Debug = $true) : ([System.Boolean]$Debug = $false) | Out-Null

        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Update-self.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-SignTool.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Write-ColorfulText.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Copy-CiRules.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\New-StagingArea.psm1" -Force

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-self -InvocationStatement $MyInvocation.Statement }

        [System.IO.DirectoryInfo]$StagingArea = New-StagingArea -CmdletName 'Deploy-SignedWDACConfig'

        #Region User-Configurations-Processing-Validation
        # Get SignToolPath from user parameter or user config file or auto-detect it
        if ($SignToolPath) {
            $SignToolPathFinal = Get-SignTool -SignToolExePathInput $SignToolPath
        } # If it is null, then Get-SignTool will behave the same as if it was called without any arguments.
        else {
            $SignToolPathFinal = Get-SignTool -SignToolExePathInput (Get-CommonWDACConfig -SignToolPath)
        }

        # If CertPath parameter wasn't provided by user, check if a valid value exists in user configs, if so, use it, otherwise throw an error
        if (!$CertPath ) {
            if (Test-Path -Path (Get-CommonWDACConfig -CertPath)) {
                $CertPath = Get-CommonWDACConfig -CertPath
            }
            else {
                throw 'CertPath parameter cannot be empty and no valid user configuration was found for it. Use the Build-WDACCertificate cmdlet to create one.'
            }
        }

        # If CertCN was not provided by user, check if a valid value exists in user configs, if so, use it, otherwise throw an error
        if (!$CertCN) {
            if ([CertCNz]::new().GetValidValues() -contains (Get-CommonWDACConfig -CertCN)) {
                [System.String]$CertCN = Get-CommonWDACConfig -CertCN
            }
            else {
                throw 'CertCN parameter cannot be empty and no valid user configuration was found for it.'
            }
        }
        #Endregion User-Configurations-Processing-Validation

        # Detecting if Confirm switch is used to bypass the confirmation prompts
        if ($Force -and -Not $Confirm) {
            $ConfirmPreference = 'None'
        }
    }

    process {

        Try {

            foreach ($PolicyPath in $PolicyPaths) {
                # The total number of the main steps for the progress bar to render
                [System.UInt16]$TotalSteps = $Deploy ? 4 : 3
                [System.UInt16]$CurrentStep = 0

                $CurrentStep++
                Write-Progress -Id 13 -Activity 'Gathering policy details' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message "Gathering policy details from: $PolicyPath"
                $Xml = [System.Xml.XmlDocument](Get-Content -Path $PolicyPath)
                [System.String]$PolicyType = $Xml.SiPolicy.PolicyType
                [System.String]$PolicyID = $Xml.SiPolicy.PolicyID
                [System.String]$PolicyName = ($Xml.SiPolicy.Settings.Setting | Where-Object -FilterScript { $_.provider -eq 'PolicyInfo' -and $_.valuename -eq 'Name' -and $_.key -eq 'Information' }).value.string
                [System.String[]]$PolicyRuleOptions = $Xml.SiPolicy.Rules.Rule.Option

                Write-Verbose -Message 'Checking if the policy type is Supplemental and if so, removing the -Supplemental parameter from the SignerRule command'
                if ($PolicyType -eq 'Supplemental Policy') {

                    Write-Verbose -Message 'Policy type is Supplemental'

                    # Make sure -User is not added if the UMCI policy rule option doesn't exist in the policy, typically for Strict kernel mode policies
                    if ('Enabled:UMCI' -in $PolicyRuleOptions) {
                        Add-SignerRule -FilePath $PolicyPath -CertificatePath $CertPath -Update -User -Kernel
                    }
                    else {
                        Write-Verbose -Message 'UMCI policy rule option does not exist in the policy, typically for Strict kernel mode policies'
                        Add-SignerRule -FilePath $PolicyPath -CertificatePath $CertPath -Update -Kernel
                    }
                }
                elseif ($PolicyType -eq 'Base Policy') {

                    Write-Verbose -Message 'Policy type is Base'

                    # Make sure -User is not added if the UMCI policy rule option doesn't exist in the policy, typically for Strict kernel mode policies
                    if ('Enabled:UMCI' -in $PolicyRuleOptions) {

                        Write-Verbose -Message 'Checking whether SignTool.exe is allowed to execute in the policy or not'
                        if (-NOT (Invoke-WDACSimulation -FilePath $SignToolPathFinal -XmlFilePath $PolicyPath -BooleanOutput)) {

                            Write-Verbose -Message 'The policy type is base policy and it applies to user mode files, yet the policy prevents SignTool.exe from executing. As a precautionary measure, scanning and including the SignTool.exe in the policy before deployment so you can modify/remove the signed policy later from the system.'

                            Write-Verbose -Message 'Creating a temporary folder to store the symbolic link to the SignTool.exe'
                            [System.IO.DirectoryInfo]$SymLinksStorage = New-Item -Path (Join-Path -Path $StagingArea -ChildPath 'SymLinkStorage') -ItemType Directory -Force

                            Write-Verbose -Message 'Creating symbolic link to the SignTool.exe'
                            New-Item -ItemType SymbolicLink -Path "$SymLinksStorage\SignTool.exe" -Target $SignToolPathFinal | Out-Null

                            Write-Verbose -Message 'Scanning the SignTool.exe and generating the SignTool.xml policy'
                            New-CIPolicy -ScanPath $SymLinksStorage -Level FilePublisher -Fallback None -UserPEs -UserWriteablePaths -MultiplePolicyFormat -AllowFileNameFallbacks -FilePath "$SymLinksStorage\SignTool.xml"

                            [System.IO.FileInfo]$AugmentedPolicyPath = Join-Path -Path $SymLinksStorage -ChildPath $PolicyPath.Name

                            Write-Verbose -Message 'Merging the SignTool.xml policy with the policy being signed'
                            # First policy in the array should always be the main one so that its settings will be used in the merged policy
                            Merge-CIPolicy -PolicyPaths $PolicyPath, "$SymLinksStorage\SignTool.xml" -OutputFilePath $AugmentedPolicyPath | Out-Null

                            Write-Verbose -Message 'Making sure policy rule options stay the same after merging the policies'
                            Copy-CiRules -SourceFile $PolicyPath -DestinationFile $AugmentedPolicyPath

                            Write-Verbose -Message 'Replacing the new policy with the old one'
                            Move-Item -Path $AugmentedPolicyPath -Destination $PolicyPath -Force
                        }
                        else {
                            Write-Verbose -Message 'The base policy allows SignTool.exe to execute, no need to scan and include it in the policy'
                        }

                        Add-SignerRule -FilePath $PolicyPath -CertificatePath $CertPath -Update -User -Kernel -Supplemental
                    }
                    else {
                        Write-Verbose -Message 'UMCI policy rule option does not exist in the policy, typically for Strict kernel mode policies'
                        Add-SignerRule -FilePath $PolicyPath -CertificatePath $CertPath -Update -Kernel -Supplemental
                    }
                }
                else {
                    Throw "Policy type is not Base or Supplemental, it is: $PolicyType"
                }

                $CurrentStep++
                Write-Progress -Id 13 -Activity 'Creating CIP file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Setting HVCI to Strict'
                Set-HVCIOptions -Strict -FilePath $PolicyPath

                Write-Verbose -Message 'Removing the Unsigned mode option from the policy rules'
                Set-RuleOption -FilePath $PolicyPath -Option 6 -Delete

                [system.io.FileInfo]$PolicyCIPPath = Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip"

                Write-Verbose -Message 'Converting the policy to .CIP file'
                ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath $PolicyCIPPath | Out-Null

                $CurrentStep++
                Write-Progress -Id 13 -Activity 'Signing the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Push-Location -Path $StagingArea
                # Configure the parameter splat
                [System.Collections.Hashtable]$ProcessParams = @{
                    'ArgumentList' = 'sign', '/v' , '/n', "`"$CertCN`"", '/p7', '.', '/p7co', '1.3.6.1.4.1.311.79.1', '/fd', 'certHash', "$($PolicyCIPPath.Name)"
                    'FilePath'     = $SignToolPathFinal
                    'NoNewWindow'  = $true
                    'Wait'         = $true
                    'ErrorAction'  = 'Stop'
                }
                # Hide the SignTool.exe's normal output unless -Verbose parameter was used
                if (!$Verbose) { $ProcessParams['RedirectStandardOutput'] = 'NUL' }

                # Sign the files with the specified cert
                Write-Verbose -Message 'Signing the policy with the specified certificate'
                Start-Process @ProcessParams

                Pop-Location

                Write-Verbose -Message 'Renaming the .p7 file to .cip'
                Move-Item -LiteralPath "$StagingArea\$PolicyID.cip.p7" -Destination $PolicyCIPPath -Force

                if ($Deploy) {

                    $CurrentStep++
                    Write-Progress -Id 13 -Activity 'Deploying' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    # Prompt for confirmation before proceeding
                    if ($PSCmdlet.ShouldProcess('This PC', 'Deploying the signed policy')) {

                        Write-Verbose -Message 'Deploying the policy'
                        &'C:\Windows\System32\CiTool.exe' --update-policy $PolicyCIPPath -json | Out-Null

                        Write-ColorfulText -Color Lavender -InputText 'policy with the following details has been Signed and Deployed in Enforced Mode:'
                        Write-ColorfulText -Color MintGreen -InputText "PolicyName = $PolicyName"
                        Write-ColorfulText -Color MintGreen -InputText "PolicyGUID = $PolicyID"

                        #Region Detecting Strict Kernel mode policy and removing it from User Configs
                        if ('Enabled:UMCI' -notin $PolicyRuleOptions) {

                            [System.String]$StrictKernelPolicyGUID = Get-CommonWDACConfig -StrictKernelPolicyGUID
                            [System.String]$StrictKernelNoFlightRootsPolicyGUID = Get-CommonWDACConfig -StrictKernelNoFlightRootsPolicyGUID

                            if (($PolicyName -like '*Strict Kernel mode policy Enforced*')) {

                                Write-Verbose -Message 'The deployed policy is Strict Kernel mode'

                                if ($StrictKernelPolicyGUID) {
                                    if ($($PolicyID.TrimStart('{').TrimEnd('}')) -eq $StrictKernelPolicyGUID) {

                                        Write-Verbose -Message 'Removing the GUID of the deployed Strict Kernel mode policy from the User Configs'
                                        Remove-CommonWDACConfig -StrictKernelPolicyGUID | Out-Null
                                    }
                                }
                            }
                            elseif (($PolicyName -like '*Strict Kernel No Flights mode policy Enforced*')) {

                                Write-Verbose -Message 'The deployed policy is Strict Kernel No Flights mode'

                                if ($StrictKernelNoFlightRootsPolicyGUID) {
                                    if ($($PolicyID.TrimStart('{').TrimEnd('}')) -eq $StrictKernelNoFlightRootsPolicyGUID) {

                                        Write-Verbose -Message 'Removing the GUID of the deployed Strict Kernel No Flights mode policy from the User Configs'
                                        Remove-CommonWDACConfig -StrictKernelNoFlightRootsPolicyGUID | Out-Null
                                    }
                                }
                            }
                        }
                        #Endregion Detecting Strict Kernel mode policy and removing it from User Configs
                    }
                }
                else {
                    Copy-Item -Path $PolicyCIPPath -Destination $UserConfigDir -Force

                    Write-ColorfulText -Color Lavender -InputText 'policy with the following details has been Signed and is ready for deployment:'
                    Write-ColorfulText -Color MintGreen -InputText "PolicyName = $PolicyName"
                    Write-ColorfulText -Color MintGreen -InputText "PolicyGUID = $PolicyID"
                }
                Write-Progress -Id 13 -Activity 'Complete.' -Completed
            }
        }
        Finally {
            if (-NOT $Debug) {
                Remove-Item -Path $StagingArea -Recurse -Force
            }
        }
    }

    <#
.SYNOPSIS
    Signs and Deploys WDAC policies, accepts signed or unsigned policies and deploys them
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-SignedWDACConfig
.DESCRIPTION
    Using official Microsoft methods, Signs and Deploys WDAC policies, accepts signed or unsigned policies and deploys them (Windows Defender Application Control)
.COMPONENT
    Windows Defender Application Control, ConfigCI PowerShell module
.FUNCTIONALITY
    Using official Microsoft methods, Signs and Deploys WDAC policies, accepts signed or unsigned policies and deploys them (Windows Defender Application Control)
.PARAMETER CertPath
    Path to the certificate .cer file
.PARAMETER PolicyPaths
    Path to the policy xml files that are going to be signed
.PARAMETER CertCN
    Certificate common name
.PARAMETER SignToolPath
    Path to the SignTool.exe - optional parameter
.PARAMETER Deploy
    Indicates that the cmdlet will deploy the signed policy on the current system
.PARAMETER Force
    Indicates that the cmdlet will bypass the confirmation prompts
.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases
.INPUTS
    System.String
    System.String[]
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
.EXAMPLE
    Deploy-SignedWDACConfig -PolicyPaths 'C:\Users\WDACConfig\Policy.xml' -CertPath 'C:\Users\WDACConfig\MyCert.cer' -CertCN 'MyCertCN' -Deploy
    This example signs and deploys the policy.xml file using the MyCert.cer certificate and deploys it on the current system
.EXAMPLE
    Deploy-SignedWDACConfig -PolicyPaths 'C:\Users\WDACConfig\Policy.xml'
    This example signs the policy.xml file using the MyCert.cer certificate but does not deploy it on the current system.
    It accesses the user configs to get the certificate path and common name, if they are not found, it throws an error.
#>
}

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\CoreExt\ArgumentCompleters.ps1"
Register-ArgumentCompleter -CommandName 'Deploy-SignedWDACConfig' -ParameterName 'PolicyPaths' -ScriptBlock $ArgumentCompleterMultipleXmlFilePathsPicker
Register-ArgumentCompleter -CommandName 'Deploy-SignedWDACConfig' -ParameterName 'CertPath' -ScriptBlock $ArgumentCompleterCerFilePathsPicker
Register-ArgumentCompleter -CommandName 'Deploy-SignedWDACConfig' -ParameterName 'SignToolPath' -ScriptBlock $ArgumentCompleterExeFilePathsPicker

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC/KmWN5RKK8QYV
# FxjmjNUP/jYOA7ltR70V8EI3zcMK+KCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgJ3658Hc6FYyCPL7RoAm6pFKA+ZweCL7kGH3Z6cZ8ttQwDQYJKoZIhvcNAQEB
# BQAEggIAT7Apt01o2ab5s3DK7UwIFRTqTl7XR8Xbx9WfNNf3I+Ii7E2litVp1zmq
# cL0aJOLEur11gKaF3OWN0bAcahPgSFpnQsMwMRj3GIlQkJu73jwy8J1Dj3ORW/O2
# gfiplwK3q81DenrMMUQ0BWOU8/Ld5K16x+yD7yg8rtXZZ6r43BJdQuuHCdOW2gQq
# w1eBa5F8KVoO2+X1QpDB5zfTPEhHqF7OilRnAjaef4v9VtyKTBPmzW7EJytVZu5r
# libQLmKx5+/lQZ/sfBEB6xaQLjvsC1ENRBOJwzO40Sds3WLFOJykQHoTOkmHmPAu
# 5dYta/+8vy0vukVg/b6enPdG/heQP+cc1Uuret2qEXzKKZYEy5v3y03JsNgO2qFE
# KsKO2s2rO3M9f7yn3nGuviE9Cnk1kWpiHSPkTeL0t7Vehyf03D3No83q0tTCQhiv
# NcNOMGfVys6ooCBwf+Ar2mrtwEoB7UCVkiwAi7Fd9D3N+jqturIX8DfjGo6uDJsF
# GWuXwdx+V6AfKbqcHbU5PFiQ8Ija6pepeyzSpN8usHN2Y+nz508+Z/BLdYKIWprG
# G34Rrzl5x+ayvqHxz56uU/0Y4vE97+tE+T7/+B/10MoFV/83fq+aPy4ul+qHStkB
# 1hGFnAyFbe3c9DPgpR98pxq35yJU/ftgXDyF4NxdNNmWKatOPw0=
# SIG # End signature block
