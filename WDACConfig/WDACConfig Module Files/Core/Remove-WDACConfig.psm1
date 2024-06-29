Function Remove-WDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = 'Signed Base',
        SupportsShouldProcess = $true,
        PositionalBinding = $False,
        ConfirmImpact = 'High'
    )]
    [OutputType([System.String])]
    Param(
        [Alias('S')]
        [Parameter(Mandatory = $False, ParameterSetName = 'Signed Base')][System.Management.Automation.SwitchParameter]$SignedBase,
        [Alias('U')]
        [Parameter(Mandatory = $False, ParameterSetName = 'Unsigned Or Supplemental')][System.Management.Automation.SwitchParameter]$UnsignedOrSupplemental,

        [ValidateScript({

                # Validate each Policy file in PolicyPaths parameter to make sure the user isn't accidentally trying to remove an Unsigned policy
                $_ | ForEach-Object -Process {
                    [System.Xml.XmlDocument]$XmlTest = Get-Content -Path $_
                    [System.String]$RedFlag1 = $XmlTest.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
                    [System.String]$RedFlag2 = $XmlTest.SiPolicy.UpdatePolicySigners.UpdatePolicySigner.SignerId

                    if ($RedFlag1 -or $RedFlag2) {

                        # Ensure the selected base policy xml file is valid
                        if ( Test-CiPolicy -XmlFile $_ ) {
                            return $True
                        }
                    }
                }
            }, ErrorMessage = 'One of the selected XML policy files is unsigned. Please use Remove-WDACConfig cmdlet with -UnsignedOrSupplemental parameter instead.')]
        [parameter(Mandatory = $true, ParameterSetName = 'Signed Base', ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo[]]$PolicyPaths,

        [ValidateSet([CertCNz])]
        [parameter(Mandatory = $False, ParameterSetName = 'Signed Base', ValueFromPipelineByPropertyName = $true)]
        [System.String]$CertCN,

        [ArgumentCompleter({
                # Define the parameters that this script block will accept.
                param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)

                # Get a list of policies using the CiTool, excluding system policies and policies that aren't on disk.
                # by adding "{ $_.FriendlyName }" we make sure the auto completion works when at least one of the policies doesn't have a friendly name
                $Policies = foreach ($Item in (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies) {
                    if (($Item.IsOnDisk -eq 'True') -and ($Item.IsSystemPolicy -ne 'True') -and $Item.FriendlyName) {
                        $Item
                    }
                }

                # Create a hashtable mapping policy names to policy IDs. This will be used later to check if a policy ID already exists.
                [System.Collections.Hashtable]$NameIDMap = @{}
                foreach ($Policy in $Policies) {
                    $NameIDMap[$Policy.Friendlyname] = $Policy.policyID
                }

                # Get the IDs of existing policies that are already being used in the current command.
                $ExistingIDs = $FakeBoundParameters['PolicyIDs']

                # Get the policy names that are currently being used in the command. This is done by looking at the abstract syntax tree (AST)
                # of the command and finding all string literals, which are assumed to be policy names.
                $Existing = $CommandAst.FindAll({
                        $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    }, $False).Value

                # Filter out the policy names that are already being used or whose corresponding policy IDs are already being used.
                # The resulting list of policy names is what will be shown as autocomplete suggestions.
                $Candidates = foreach ($Item in $Policies.Friendlyname) {
                    if ($Item -notin $Existing -and $NameIDMap[$Item] -notin $ExistingIDs) {
                        $Item
                    }
                }

                # Additionally, if the policy name contains spaces, it's enclosed in single quotes to ensure it's treated as a single argument.
                # This is achieved using the Compare-Object cmdlet to compare the existing and candidate values, and outputting the resulting matches.
                # For each resulting match, it checks if the match contains a space, if so, it's enclosed in single quotes, if not, it's returned as is.
                foreach ($Item in (Compare-Object -ReferenceObject $Candidates -DifferenceObject $Existing -PassThru)) {
                    if ($Item.SideIndicator -eq '<=') {
                        if ($Item -match ' ') {
                            "'{0}'" -f $Item
                        }
                        else {
                            $Item
                        }
                    }
                }
            })]
        [ValidateScript({
                if (
                    !([System.Collections.Generic.HashSet[System.String]]@([PolicyNamezx]::new().GetValidValues())).Contains($_)
                ) {
                    throw "Invalid policy name: $_"
                }
                $true
            })]
        [Parameter(Mandatory = $False, ParameterSetName = 'Unsigned Or Supplemental')]
        [System.String[]]$PolicyNames,

        [ArgumentCompleter({
                param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)

                # Get a list of policies using the CiTool, excluding system policies and policies that aren't on disk.
                $Policies = foreach ($Item in (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies) {
                    if (($Item.IsOnDisk -eq 'True') -and ($Item.IsSystemPolicy -ne 'True')) {
                        $Item
                    }
                }

                # Create a hashtable mapping policy IDs to policy names. This will be used later to check if a policy name already exists.
                [System.Collections.Hashtable]$IDNameMap = @{}
                foreach ($Policy in $Policies) {
                    $IDNameMap[$Policy.policyID] = $Policy.Friendlyname
                }

                # Get the names of existing policies that are already being used in the current command.
                $ExistingNames = $FakeBoundParameters['PolicyNames']

                # Get the policy IDs that are currently being used in the command. This is done by looking at the abstract syntax tree (AST)
                # of the command and finding all string literals, which are assumed to be policy IDs.
                $Existing = $CommandAst.FindAll({
                        $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    }, $False).Value

                # Filter out the policy IDs that are already being used or whose corresponding policy names are already being used.
                # The resulting list of policy IDs is what will be shown as autocomplete suggestions.
                $Candidates = foreach ($Item in $Policies.policyID) {
                    if ($Item -notin $Existing -and $IDNameMap[$Item] -notin $ExistingNames) {
                        $Item
                    }
                }

                # Return the candidates
                return $Candidates
            })]
        [ValidateScript({
                if ($_ -notin [PolicyIDzx]::new().GetValidValues()) { throw "Invalid policy ID: $_" }
                $true
            })]
        [Parameter(Mandatory = $False, ParameterSetName = 'Unsigned Or Supplemental')]
        [System.String[]]$PolicyIDs,

        [parameter(Mandatory = $False, ParameterSetName = 'Signed Base', ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo]$SignToolPath,

        [Parameter(Mandatory = $False)][System.Management.Automation.SwitchParameter]$Force,

        [Parameter(Mandatory = $False)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )
    Begin {
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $False
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -Force -FullyQualifiedName @(
            "$ModuleRootPath\Shared\Update-Self.psm1",
            "$ModuleRootPath\Shared\Get-SignTool.psm1",
            "$ModuleRootPath\Shared\Write-ColorfulText.psm1",
            "$ModuleRootPath\Shared\Remove-SupplementalSigners.psm1"
            "$ModuleRootPath\Shared\Invoke-CiSigning.psm1"
        )

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-Self -InvocationStatement $MyInvocation.Statement }

        [System.IO.DirectoryInfo]$StagingArea = [WDACConfig.StagingArea]::NewStagingArea('Remove-WDACConfig')

        #Region User-Configurations-Processing-Validation
        Write-Verbose -Message 'Validating and processing user configurations'

        if ($PSCmdlet.ParameterSetName -eq 'Signed Base') {

            # Get SignToolPath from user parameter or user config file or auto-detect it
            if ($SignToolPath) {
                [System.IO.FileInfo]$SignToolPathFinal = Get-SignTool -SignToolExePathInput $SignToolPath
            } # If it is null, then Get-SignTool will behave the same as if it was called without any arguments.
            else {
                [System.IO.FileInfo]$SignToolPathFinal = Get-SignTool -SignToolExePathInput (Get-CommonWDACConfig -SignToolPath)
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
        }
        #Endregion User-Configurations-Processing-Validation

        # ValidateSet for Policy names
        Class PolicyNamezx : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {

                $PolicyNamezx = [System.Collections.Generic.HashSet[System.String]]@(foreach ($Policy in (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies) {
                        if ( ($Policy.IsOnDisk -eq 'True') -and ($Policy.IsSystemPolicy -ne 'True')) {
                            $Policy.Friendlyname
                        }
                    })
                return $PolicyNamezx
            }
        }

        # ValidateSet for Policy IDs
        Class PolicyIDzx : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {

                [System.String[]]$PolicyIDzx = foreach ($Item in (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies) {
                    if (($Item.IsOnDisk -eq 'True') -and ($Item.IsSystemPolicy -ne 'True')) {
                        $Item.PolicyID
                    }
                }

                return $PolicyIDzx
            }
        }

        # Detecting if Confirm switch is used to bypass the confirmation prompts
        if ($Force -and -Not $Confirm) {
            $ConfirmPreference = 'None'
        }
    }

    process {

        Try {

            # If a signed policy is being removed
            if ($SignedBase) {

                Write-Verbose -Message 'Looping over each selected policy XML file'
                foreach ($PolicyPath in $PolicyPaths) {

                    # The total number of the main steps for the progress bar to render
                    $TotalSteps = 3us
                    $CurrentStep = 0us

                    $CurrentStep++
                    Write-Progress -Id 18 -Activity 'Parsing the XML Policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Converting the XML file to an XML object'
                    [System.Xml.XmlDocument]$Xml = Get-Content -Path $PolicyPath

                    Write-Verbose -Message 'Extracting the Policy ID from the XML object'
                    [System.String]$PolicyID = $Xml.SiPolicy.PolicyID
                    Write-Verbose -Message "The policy ID of the currently processing xml file is $PolicyID"

                    # Extracting the policy name from the selected XML policy file
                    [System.String]$PolicyName = foreach ($Item in $Xml.SiPolicy.Settings.Setting) {
                        if ($Item.Provider -eq 'PolicyInfo' -and $Item.ValueName -eq 'Name' -and $Item.Key -eq 'Information') {
                            $Item.Value.String
                        }
                    }

                    # Prevent users from accidentally attempting to remove policies that aren't even deployed on the system
                    Write-Verbose -Message 'Making sure the selected XML policy is deployed on the system'

                    Try {
                        [System.Guid[]]$CurrentPolicyIDs = foreach ($Item in (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies) {
                            if ($Item.IsSystemPolicy -ne 'True') {
                                "{$($Item.PolicyID)}"
                            }
                        }
                    }
                    catch {
                        Throw 'No policy is deployed on the system.'
                    }

                    if ($CurrentPolicyIDs -notcontains $PolicyID) {
                        Throw 'The selected policy file is not deployed on the system.'
                    }

                    $CurrentStep++
                    Write-Progress -Id 18 -Activity 'Processing the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Making sure SupplementalPolicySigners do not exist in the XML policy'
                    Remove-SupplementalSigners -Path $PolicyPath

                    Set-CiRuleOptions -FilePath $PolicyPath -RulesToAdd 'Enabled:Unsigned System Integrity Policy'

                    [System.IO.FileInfo]$PolicyCIPPath = Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip"

                    # Converting the Policy XML file to CIP binary file
                    $null = ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath $PolicyCIPPath

                    $CurrentStep++
                    Write-Progress -Id 18 -Activity 'Signing the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Push-Location -Path $StagingArea
                    Invoke-CiSigning -CiPath $PolicyCIPPath -SignToolPathFinal $SignToolPathFinal -CertCN $CertCN
                    Pop-Location

                    # Fixing the extension name of the newly signed CIP file
                    Move-Item -Path (Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip.p7") -Destination $PolicyCIPPath -Force

                    # Deploying the newly signed CIP file

                    # Prompt for confirmation before proceeding
                    if ($PSCmdlet.ShouldProcess('This PC', 'Deploying the signed policy')) {

                        Write-Verbose -Message 'Deploying the newly signed CIP file'
                        $null = &'C:\Windows\System32\CiTool.exe' --update-policy $PolicyCIPPath -json

                        Write-ColorfulText -Color Lavender -InputText "Policy with the following details has been Re-signed and Re-deployed in Unsigned mode.`nPlease restart your system."
                        Write-ColorfulText -Color MintGreen -InputText "PolicyName = $PolicyName"
                        Write-ColorfulText -Color MintGreen -InputText "PolicyGUID = $PolicyID"
                    }
                    Write-Progress -Id 18 -Activity 'Complete.' -Completed
                }
            }

            # If an unsigned policy is being removed
            if ($UnsignedOrSupplemental) {

                # If IDs were supplied by user
                foreach ($ID in $PolicyIDs ) {
                    $null = &'C:\Windows\System32\CiTool.exe' --remove-policy "{$ID}" -json
                    Write-ColorfulText -Color Lavender -InputText "Policy with the ID $ID has been successfully removed."
                }

                # If names were supplied by user
                # HashSet to store Unique Policy IDs based on the input name, this will take care of the situations where multiple policies with the same name are deployed
                $NameID = [System.Collections.Generic.HashSet[System.String]]@(foreach ($PolicyName in $PolicyNames) {
                        foreach ($Item in (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies ) {
                            if (($Item.IsOnDisk -eq 'True') -and ($Item.FriendlyName -eq $PolicyName)) {
                                $Item.PolicyID
                            }
                        }
                    })

                Write-Verbose -Message "$($NameID.count) policy IDs have been gathered from the supplied policy names and are going to be removed from the system"

                foreach ($ID in $NameID) {
                    $null = &'C:\Windows\System32\CiTool.exe' --remove-policy "{$ID}" -json
                    Write-ColorfulText -Color Lavender -InputText "Policy with the ID $ID has been successfully removed."
                }
            }
        }
        Finally {
            # Clean up the staging area
            Remove-Item -Path $StagingArea -Recurse -Force
        }
    }

    <#
.SYNOPSIS
    Removes Signed and unsigned deployed WDAC policies (Windows Defender Application Control)
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Remove-WDACConfig
.DESCRIPTION
    Using official Microsoft methods, Removes Signed and unsigned deployed WDAC policies (Windows Defender Application Control)
.COMPONENT
    Windows Defender Application Control, ConfigCI PowerShell module
.FUNCTIONALITY
    Using official Microsoft methods, Removes Signed and unsigned deployed WDAC policies (Windows Defender Application Control)
.PARAMETER PolicyNames
    Names of the deployed policies to be removed
    https://stackoverflow.com/questions/76143006/how-to-prevent-powershell-validateset-argument-completer-from-suggesting-the-sam/76143269
    https://stackoverflow.com/questions/76267235/powershell-how-to-cross-reference-parameters-between-2-argument-completers
.PARAMETER PolicyIDs
    IDs of the deployed policies to be removed
    https://stackoverflow.com/questions/76143006/how-to-prevent-powershell-validateset-argument-completer-from-suggesting-the-sam/76143269
    https://stackoverflow.com/questions/76267235/powershell-how-to-cross-reference-parameters-between-2-argument-completers
.PARAMETER SignedBase
    Remove Signed Base WDAC Policies
.PARAMETER PolicyPaths
    Path to the XML policy file(s) of the deployed policies to be removed
.PARAMETER CertCN
    Certificate common name to be used to sign the policy file(s) that are going to be removed in unsigned mode
.PARAMETER SignToolPath
    Path to the SignTool.exe
.PARAMETER UnsignedOrSupplemental
    Remove Unsigned deployed WDAC policies as well as Signed deployed Supplemental WDAC policies
.PARAMETER Force
    Bypasses the confirmation prompt
.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases
.PARAMETER Verbose
    Shows verbose output
.INPUTS
    System.String
    System.String[]
    System.IO.FileInfo
    System.IO.FileInfo[]
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
#>
}
Register-ArgumentCompleter -CommandName 'Remove-WDACConfig' -ParameterName 'PolicyPaths' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterMultipleXmlFilePathsPicker)
Register-ArgumentCompleter -CommandName 'Remove-WDACConfig' -ParameterName 'SignToolPath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterExeFilePathsPicker)

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBLrCNAAUz6ABDO
# ggKEEFyo2HcRzOCmBTAcOz1SeDbFcKCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgTLHYhCkPnyX6sxoKk+VoMpeQ4sd3sAFiYDz0jL6UOHUwDQYJKoZIhvcNAQEB
# BQAEggIAfZKhkZuSmOw+2844ZJ7pZ9l3NlAS/cykTzCsXdQgoz8q73XUi0eGvSpA
# PM6YVaQn32d0Ymfp9aRMFVm7mcl1ciW+oyYff8ixKdhW2IDiD1P4nXevNVAbUntz
# Gg8NInijtywvyifzll3a9rWCJUCeiNEmTbueiR9xk0A7pSNNyWkWi2GD+pVvRezy
# O7usg5ahCCj+5RhnAxSRhbyJckKRXUrQcyXHxctItU6bgrv7FB3uTzh3SAHIVeNX
# G8X4M7R2zZ9TSVVlNAzoPHWUIZEOKDwDjzY+7rSVCy7H1ryZTyDNO2c6KOhLh/9J
# R5HnfZ9rF88GdVVphx4YxNw8zBZwScCcW4Bsn7VVc1MtRtVLeAS78dfv0C6HzA5a
# gyewZq2NamQnnufmkcFCoSVKFt/rDGpa38KWfP5gUL2w7racw69ZN7yWMvnpdGLc
# HZX8nbezJC6ZnDibxWdfkJdHnEkR2nIpw85+R2rpVAV9QWBgu5/j7pomev6kb18h
# OiG80hkiPNLOcMrP5qA+0InF/ma9m4ZOZlcp1A/nWcbC002IfCYEGM7I2CArtL0X
# 2O3xFaWKvzm8vxmluVYPdvTTWZ4y0dUNDQd02JvIcocxIJlViuCJGwKT9l9VSj/q
# 39YfMB2Nb7oaJgJpk+AW/pNlyD3o6gfaA8MorkHRXMgVvmroD7A=
# SIG # End signature block
