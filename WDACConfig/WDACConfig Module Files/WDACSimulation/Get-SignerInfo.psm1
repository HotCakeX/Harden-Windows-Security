# Importing the $PSDefaultParameterValues to the current session, prior to everything else
. "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

# Defining the class
Add-Type -Language CSharp -TypeDefinition @'
namespace WDACConfig
{
    public class SignerClass
    {
        // Adding public getters and setters for the properties
        public string ID { get; set; }
        public string Name { get; set; }
        public string CertRoot { get; set; }
        public string CertPublisher { get; set; }

        // Adding a constructor to initialize the properties
        public SignerClass(string id, string name, string certRoot, string certPublisher)
        {
            ID = id;
            Name = name;
            CertRoot = certRoot;
            CertPublisher = certPublisher;
        }
    }
}
'@

Function Get-SignerInfo {
    <#
    .SYNOPSIS
        Function that takes an XML file path as input and returns an array of Signer objects
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        Signer[]
    .PARAMETER XmlFilePath
        The XML file path that the user selected for WDAC simulation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath
    )
    begin {
        # Load the XML file
        $Xml = [System.Xml.XmlDocument](Get-Content -Path $XmlFilePath)
    }
    process {
        # Select the Signer nodes
        [System.Object[]]$Signers = $Xml.SiPolicy.Signers.Signer

        # Create an empty array to store the output
        [WDACConfig.SignerClass[]]$Output = @()

        # Loop through each Signer node and extract the information
        foreach ($Signer in $Signers) {

            # Create a new instance of the SignerClass class in the WDACConfig Namespace
            [WDACConfig.SignerClass]$SignerObj = New-Object -TypeName WDACConfig.SignerClass -ArgumentList ($Signer.ID, $Signer.Name, $Signer.CertRoot.Value, $Signer.CertPublisher.Value)

            # Add the Signer object to the output array
            $Output += $SignerObj
        }
    }
    end {
        # Return the output array
        return $Output
    }
}

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCALGrB7tReMnRb5
# 8ERlJ66a2eSHbhHsMevPksHuUqKv/qCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQguVHWGhzVO2b40sYvjxs/O6SDLAQjc9nkV/T5rY1OLI0wDQYJKoZIhvcNAQEB
# BQAEggIAbxvjOuG4ut/beYIll7IU43uIQXK1An/6pkfLG2gQM0FqOF8klJh+qd2K
# CTCHefK0f8LQWzytdW8criEl9x7EXPDy4WWJZSqeuLAZ/5Uy/nLN2NF4KR5GvyTK
# A5iH8RBdxRoPFgFWyXVUgD29NbqzSNckUOKZS4cgxA8ILGsXvr/1Sqhgq5eCeZnB
# o2CPprkO6Vf4/g/BNL85xEDfiF59cNZFrvQ6uNstbe0FMH6SNpumeUpUKqqYwvZi
# HAbQSAaOhkNIjCvxyaCXCvk4IW5NYDiSFpenAY1sztsIGfsk35/cCgyhw6ShcEyJ
# 6VAvlESM/2/4fVDwxP8KCI/J84PlDb/J0eoRHzv8t/+0Fpa13RFnC2dQwE2dIRHy
# zF/wTol2dXlmec14HDht78n8NdiLE86+xwesrcubSdYoUL5DsbDZfgGsoek5Wbkp
# N9YNUw3zA/00U+DZFdXEQZZ+XeIoE/AWPHaikpo/52OiKl4NbLal8+J26JmYqZT+
# C7MC7YjQB4lddrTF0lzHGmKaIAusKu/3eIfdXbNZLUOBOnW8LHNBOxyjy498T0sM
# 2M6rKaWixfiucE/vQqIn/DUr6VyD8YTxbOE+EGSlWUgBgbM7haPwKWBcRJ/44IN1
# 0v+tVhZrzsGS8dh7B5kEy1ux1QKj3Z41Gr28SbQ9x2IcijaW+cU=
# SIG # End signature block
