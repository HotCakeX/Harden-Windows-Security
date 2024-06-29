# Classes will be available process-wide and therefore also in other runspaces, defining them with the [NoRunspaceAffinity()] attribute.
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_classes#exporting-classes-with-type-accelerators

# argument tab auto-completion and ValidateSet for Levels and Fallbacks parameters in the entire module
[NoRunspaceAffinity()]
Class ScanLevelz : System.Management.Automation.IValidateSetValuesGenerator {
    [System.String[]] GetValidValues() {
        $ScanLevelz = ('Hash', 'FileName', 'SignedVersion', 'Publisher', 'FilePublisher', 'LeafCertificate', 'PcaCertificate', 'RootCertificate', 'WHQL', 'WHQLPublisher', 'WHQLFilePublisher', 'PFN', 'FilePath', 'None')
        return [System.String[]]$ScanLevelz
    }

    [System.Void] NewEmptyMethod() {
        # This is an empty method
    }
}

# argument tab auto-completion and ValidateSet for Non-System Policy names
[NoRunspaceAffinity()]
Class BasePolicyNamez : System.Management.Automation.IValidateSetValuesGenerator {
    [System.String[]] GetValidValues() {

        [System.String[]]$BasePolicyNamez = foreach ($Policy in (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies) {
            if ($Policy.IsSystemPolicy -ne 'True') {
                if ($Policy.PolicyID -eq $Policy.BasePolicyID) {
                    $Policy.FriendlyName
                }
            }
        }
        return $BasePolicyNamez
    }

    [System.Void] NewEmptyMethod() {
        # This is an empty method
    }
}

# Argument completer and ValidateSet for CertCNs
[NoRunspaceAffinity()]
Class CertCNz : System.Management.Automation.IValidateSetValuesGenerator {
    [System.String[]] GetValidValues() {

        $Output = [System.Collections.Generic.HashSet[System.String]]@()

        # Loop through each certificate in the current user's personal store
        foreach ($Cert in (Get-ChildItem -Path 'Cert:\CurrentUser\My')) {

            # Make sure it uses RSA algorithm (Because ECDSA is not supported for signing WDAC policies)
            if ($Cert.PublicKey.Oid.FriendlyName -eq 'RSA') {

                # Get its Subject Common Name (CN)
                $CN = [WDACConfig.CryptoAPI]::GetNameString($Cert.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $false)

                # Add the CN to the output set and warn if there is already CN with the same name in the HashSet
                if (!$Output.Add($CN)) {
                    Write-Warning -Message "There are more than 1 certificates with the common name '$CN' in the Personal certificate store of the Current User, delete one of them if you want to use it."
                }
            }
        }
        # The ValidateSet attribute expects a unique set of values, and it will throw an error if there are duplicates
        Return $Output
    }

    [System.Void] NewEmptyMethod() {
        # This is an empty method
    }
}

# a class to define valid policy rule options
[NoRunspaceAffinity()]
Class RuleOptionsx : System.Management.Automation.IValidateSetValuesGenerator {
    [System.String[]] GetValidValues() {

        #Region Validating current Intel data
        # Get the CI Schema content
        [System.Xml.XmlDocument]$SchemaData = Get-Content -Path $global:CISchemaPath
        [System.Collections.Hashtable]$Intel = ConvertFrom-Json -AsHashtable -InputObject (Get-Content -Path "$global:ModuleRootPath\Resources\PolicyRuleOptions.Json" -Raw -Force)

        # Get the valid rule options from the schema
        $ValidOptions = [System.Collections.Generic.HashSet[System.String]] @(($SchemaData.schema.simpleType | Where-Object -FilterScript { $_.name -eq 'OptionType' }).restriction.enumeration.Value)

        # Perform validation to make sure the current intel is valid in the CI Schema
        foreach ($Key in $Intel.Values) {
            if (-NOT $ValidOptions.Contains($Key)) {
                Throw "Invalid Policy Rule Option detected that is not part of the Code Integrity Schema: $Key"
            }
        }

        foreach ($Option in $ValidOptions) {
            if (-NOT $Intel.Values.Contains($Option)) {
                Write-Verbose -Message "Set-CiRuleOptions: Rule option '$Option' exists in the Code Integrity Schema but not being used by the module."
            }
        }
        #Endregion Validating current Intel data

        $RuleOptionsx = @($Intel.Values)
        return [System.String[]]$RuleOptionsx
    }

    [System.Void] NewEmptyMethod() {
        # This is an empty method
    }
}

# Define the types to export with type accelerators.
[System.Reflection.TypeInfo[]]$ExportableTypes = @(
    [ScanLevelz]
    [CertCNz]
    [BasePolicyNamez]
    [RuleOptionsx]
)

# Get the non-public TypeAccelerators class for defining new accelerators.
[System.Reflection.TypeInfo]$TypeAcceleratorsClass = [psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')

# Add type accelerators for every exportable type.
$ExistingTypeAccelerators = $TypeAcceleratorsClass::Get

foreach ($Type in $ExportableTypes) {

    # !! $TypeAcceleratorsClass::Add() quietly ignores attempts to redefine existing
    # !! accelerators with different target types, so we check explicitly.
    $Existing = $ExistingTypeAccelerators[$Type.FullName]

    if (($null -ne $Existing) -and ($Existing -ne $Type)) {
        throw "Unable to register type accelerator [$($Type.FullName)], because it is already defined with a different type ([$Existing])."
    }
    $TypeAcceleratorsClass::Add($Type.FullName, $Type)
}

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAKovV9drbbmi6R
# vWWuPH7eR+kECfHfPJx2D8WH7tOHgqCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgmToubimJODIOzUFcYrEZrOm8vGkvNBzFA77a/ZMnJhowDQYJKoZIhvcNAQEB
# BQAEggIAJcyALumppFgXXb2RKu6aGrRw3rToPv1RcWjnFGrTEPFKV0Law8APJfAE
# TRiAs0KcWC+o8s3dgTPKSWG7IH64migICa0IrPw14AOMUHZW14/QskADwbeJA3ip
# c9QDDz3x2BuNIR5Z9QXEzwemHS9s2MhPEIpacDCxy+qD+6FyNRonA4Wq1dHJrn9r
# UnF+rKG+jNd9XLI84SmA+lpI/Ety6O0bBbxj6qvY0NjBp4nQHHImp/tyIDnI/39O
# Ak03Rdy3BAU9AR4eATWk89uo+6oc9jD86x09MJ97oz6k5x7/cc9GU8iIJWyk/Aul
# rTZ96ZbOs6xg62ylL2s20DuFO+tG3DGL7UiutSZyCmr74ZQ0LSdlRCHhKqiTCUcF
# zVMqowYyUf4j9svteeKo6PwGfAmskrpJPiptEwqz5McUUCWAE/IxOPpqRN1VJNMe
# 2H4a1w4eahKvRPd8cBKoFz0iW+FgqetrItIfLHj0QEX3Y2/rFpkQhs5TV+Xudxxl
# K89qNjnPDM7EVuShPAg0KzCkP51Um6vsbqFrI3FFEt4xNcMh/GBIr/n6Blnwr+1u
# IuIBeveO9gNGhn7PW/qEP06Kh7KtJokwNzmS6Kjcf4yk96PM64TZK+5CzkAUrI9T
# HyFHTzTwgh438xq/reXqMDUJ2pC4+Uvrr/cMCxrFTFwDHhf0fYk=
# SIG # End signature block
