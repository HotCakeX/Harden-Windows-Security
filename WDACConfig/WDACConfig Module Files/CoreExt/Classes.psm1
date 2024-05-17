# Classes will be available process-wide and therefore also in other runspaces, defining them with the [NoRunspaceAffinity()] attribute.
# https://stackoverflow.com/a/78078461/21243735
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_classes#exporting-classes-with-type-accelerators

# argument tab auto-completion and ValidateSet for Levels and Fallbacks parameters in the entire module
[NoRunspaceAffinity()]
Class ScanLevelz : System.Management.Automation.IValidateSetValuesGenerator {
    [System.String[]] GetValidValues() {
        $ScanLevelz = ('Hash', 'FileName', 'SignedVersion', 'Publisher', 'FilePublisher', 'LeafCertificate', 'PcaCertificate', 'RootCertificate', 'WHQL', 'WHQLPublisher', 'WHQLFilePublisher', 'PFN', 'FilePath', 'None')
        return [System.String[]]$ScanLevelz
    }
}

# argument tab auto-completion and ValidateSet for Non-System Policy names
[NoRunspaceAffinity()]
Class BasePolicyNamez : System.Management.Automation.IValidateSetValuesGenerator {
    [System.String[]] GetValidValues() {
        $BasePolicyNamez = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' } | Where-Object -FilterScript { $_.PolicyID -eq $_.BasePolicyID }).Friendlyname
        return [System.String[]]$BasePolicyNamez
    }
}

# Argument completer and ValidateSet for CertCNs
[NoRunspaceAffinity()]
Class CertCNz : System.Management.Automation.IValidateSetValuesGenerator {
    [System.String[]] GetValidValues() {
        # Cannot define the custom type 'WDACConfig.CryptoAPI' since we're in a class definition and it does not support it, hence using Add-Type with -PassThru
        $CryptoAPI = Add-Type -Path "$global:ModuleRootPath\C#\Crypt32CertCN.cs" -PassThru

        [System.String[]]$Output = @()

        # Loop through each certificate that uses RSA algorithm (Because ECDSA is not supported for signing WDAC policies) in the current user's personal store and extract the relevant properties
        foreach ($Cert in (Get-ChildItem -Path 'Cert:\CurrentUser\My' | Where-Object -FilterScript { $_.PublicKey.Oid.FriendlyName -eq 'RSA' })) {

            $CN = $CryptoAPI::GetNameString($Cert.Handle, $CryptoAPI::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $false)

            if ($CN -in $Output) {
                Write-Warning -Message "There are more than 1 certificates with the common name '$CN' in the Personal certificate store of the Current User, delete one of them if you want to use it."
            }
            $Output += $CN
        }
        # The ValidateSet attribute expects a unique set of values, and it will throw an error if there are duplicates
        Return ($Output | Select-Object -Unique)
    }
}

# a class to throw a custom exception when the certificate collection cannot be obtained during WDAC Simulation
[NoRunspaceAffinity()]
class ExceptionFailedToGetCertificateCollection : System.Exception {
    [System.String]$AdditionalData

    ExceptionFailedToGetCertificateCollection([System.String]$Message, [System.String]$AdditionalData) : base($Message) {
        $This.additionalData = $AdditionalData
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
                Write-Verbose -Message "Set-CiRuleOptions: Rule option '$Option' exists in the Code Integrity Schema but not being used by the module." -Verbose
            }
        }
        #Endregion Validating current Intel data

        $RuleOptionsx = @($Intel.Values)
        return [System.String[]]$RuleOptionsx
    }
}

Class CertificateDetailsCreator {
    [System.String]$IntermediateCertTBS
    [System.String]$IntermediateCertName
    [System.String]$LeafCertTBS
    [System.String]$LeafCertName
}

Class FilePublisherSignerCreator {
    [CertificateDetailsCreator[]]$CertificateDetails
    [System.Version]$FileVersion
    [System.String]$FileDescription
    [System.String]$InternalName
    [System.String]$OriginalFileName
    [System.String]$PackageFamilyName
    [System.String]$ProductName
    [System.String]$FileName
    [System.String]$AuthenticodeSHA256
    [System.String]$AuthenticodeSHA1
    [System.Int32]$SiSigningScenario
}

Class PublisherSignerCreator {
    [CertificateDetailsCreator[]]$CertificateDetails
    [System.String]$FileName
    [System.String]$AuthenticodeSHA256
    [System.String]$AuthenticodeSHA1
    [System.Int32]$SiSigningScenario
}

Class HashCreator {
    [System.String]$AuthenticodeSHA256
    [System.String]$AuthenticodeSHA1
    [System.String]$FileName
    [System.Int32]$SiSigningScenario
}

class FindWDACCompliantFiles {   
    static [System.String[]]
    SearchFiles([System.String[]] $Paths) {
        [System.String[]]$Extensions = @('*.sys', '*.exe', '*.com', '*.dll', '*.rll', '*.ocx', '*.msp', '*.mst', '*.msi', '*.js', '*.vbs', '*.ps1', '*.appx', '*.bin', '*.bat', '*.hxs', '*.mui', '*.lex', '*.mof')
        $Output = Get-ChildItem -Recurse -File -LiteralPath $Paths -Include $Extensions -Force
        Return ($Output ? [System.String[]]$Output : $null)
    }
}

# Define the types to export with type accelerators.
[System.Reflection.TypeInfo[]]$ExportableTypes = @(
    [ScanLevelz]
    [CertCNz]
    [BasePolicyNamez]
    [ExceptionFailedToGetCertificateCollection]
    [RuleOptionsx]
    [CertificateDetailsCreator]
    [FilePublisherSignerCreator]
    [PublisherSignerCreator]
    [HashCreator]
    [FindWDACCompliantFiles]
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD9KheC+QwZeAmF
# g1xWldilCpuou3ANAFzVdOww8fsLfqCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgZTNa0z12p9az8IOjAJiT4XpvYLnXqt8aiW9MKW2WVWcwDQYJKoZIhvcNAQEB
# BQAEggIAC8es3LEoc9OZMX7URFE6PSF3M5df1l8BL0Qz5T9mWyexJdgUmA7hxBKL
# 9lseS1K8PBxx3vgrdCT5DyGwRrDSOfHumUxQWTkMna339bFalBgV0LXMb7bzqtaQ
# s91nEa7zyhIOPbKvi4cREoAi32qCjW9/YeJIEfrkp7aaGuzX45UsRi6pLfqPWS1F
# vt3mhhsbLLfe607O9jJpNTc3B277AcQMojrYVBVaAmpc+YyCf14tx/RQ1XzRvMKl
# c3QbenLoMUXPuN0tJvbxPZy1YTf7CdgCAUxsiI31DyaGUo7Yk4w+Qld3ltI+LIb8
# Ggj9eUYxZYPnRuwJNg6Hkub26M2cnO0RGASkVhg2w85UObYMS5w1yBWRuxFj2mnC
# MA68wPL+gnTAfrginETHUmIuAisRvuvB4CgeTkYTF2ANCIJbUNlR60LHYf8nqq91
# fxv7FnFu99K12bQba7BBR1aFia1ZipANcwfqJvA7/7l5/gkQNWDxr4PG82MqbjIo
# LD8L2Fu6Qit+MtWq/mdE47nXiABTUehadm9CkvCUuA0Eoa3jxpknpz0g3GJEs/Pu
# 4xYmbzJpfwgA7wkRhxOvMwU3lx1Jkf66pQKGnIo4tCkQULE1YVr59Dgx4QvvF0ug
# Cp/Ucn88TkGO3Sk50bMmrCO4SCUUNrot65olABvbcwuKOwEZnZU=
# SIG # End signature block
