# Import the System.Formats.Asn1 namespaces
# This allows you to use the AsnReader and AsnWriter classes
using namespace System.Formats.Asn1

Function Convert-HexToOID {
  [CmdletBinding()]
  [OutputType([System.String])]
  Param (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [ValidateNotNullOrEmpty()][System.String]$Hex
  )
  <#
.SYNOPSIS
  Converts a hexadecimal string to an OID
.DESCRIPTION
  Used for converting hexadecimal values found in the EKU sections of the WDAC policies to their respective OIDs.
.PARAMETER Hex
  The hexadecimal string to convert to an OID
.EXAMPLE
  Convert-HexToOID -Hex '010a2b0601040182374c0301'

  Returns '1.3.6.1.4.1.311.76.3.1'
.INPUTS
  System.String
.OUTPUTS
  System.String
  #>

  begin {
    # Convert the hexadecimal string to a byte array by looping through the string in pairs of two characters
    # and converting each pair to a byte using the base 16 (hexadecimal) system
    [System.Byte[]]$NumArray = for ($Index = 0; $Index -lt $Hex.Length; $Index += 2) {
      [System.Convert]::ToByte($Hex.Substring($Index, 2), 16)
    }
  }

  process {
    # Change the first byte from 1 to 6 because the hexadecimal string is missing the tag and length bytes
    # that are required for the ASN.1 encoding of an OID
    # The tag byte indicates the type of the data, and for an OID it is 6
    # The length byte indicates the number of bytes that follow the tag byte
    # and for this example it is 10 (0A in hexadecimal)
    $NumArray[0] = 6

    # Create an AsnReader object with the default encoding rules
    # This is a class that can read the ASN.1 BER, CER, and DER data formats
    # BER (Basic Encoding Rules) is the most flexible and widely used encoding rule
    # CER (Canonical Encoding Rules) is a subset of BER that ensures a unique encoding
    # DER (Distinguished Encoding Rules) is a subset of CER that ensures a deterministic encoding
    # The AsnReader object takes the byte array as input and the encoding rule as an argument
    [AsnReader]$AsnReader = New-Object -TypeName AsnReader -ArgumentList ($NumArray, [AsnEncodingRules]::BER)

    # Read the OID as an ObjectIdentifier
    # This is a method of the AsnReader class that returns the OID as a string
    # The first two numbers are derived from the first byte of the encoded data
    # The rest of the numbers are derived from the subsequent bytes using a base 128 (variable-length) system
    [System.String]$OID = $AsnReader.ReadObjectIdentifier()
  }

  End {
    # Return the OID value as string
    return $OID
  }
}
Export-ModuleMember -Function 'Convert-HexToOID'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAJcL/FZWmK9dJs
# uAfJ0B/JLGdr0JlXF3trbMFig76ACKCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgJSf8qTUTfqqGPFspNPyaEIkZ4i7mz6y53FeRC4xnd1gwDQYJKoZIhvcNAQEB
# BQAEggIAP8EmX49teJwH+tSAJb3F0fwOPOsCE3IkLNARqjgs2lcOwSPwOkVQyxav
# EVqAO6l0vdWK95rTUR+RdyxifPMpvN705BFIIwJ9KcarxKrJmVTpkP9cz/crwA7d
# NRPKuex7npEjmSQNQ8g8czlg6YH+7V2aM7rnjn+7HFc7yYHbADwLW2XBeNKNIJUj
# ie6eiyA8xxgND67AtqSE2iG9il3s5kA9V7NJyyGhSZVKTtCojhRQDurOaYgouML2
# MsqGvlq/DvmGgk2KZV/dhQwwFDFEUmf8KuqAZXac7KStd4mulgQX87X3TyZgq0pr
# tBHRsf1BpgYUcaDd3qDF9IhdOVnC/RAOsd257VgfZS2FpRyq0Fr5tCIXNItqWrGw
# KndPEFqfk6IcYc3/F470X5QO1soUwFPqlOcJdoNJ4iY3TaG8JFTvb74hcANJXOYT
# O7ow2YKNtzQdyBm6jAyUTiMtFiZcJXdojsimbiZWUDgTDkBja4jYEsmkspNmrC64
# mYdb/g2uLP2idcf4ACieCg7PIPmt+0WnJRYMorH4/GI8jQCvAqbKwhKO+X9nGbkr
# RMPebFwr65XrO23pM0X6FX/vNUc+zw2a/IXpzsNy3mrsevLPXVarS4RtMUE8ckI6
# /7D5aQY4h0iLN2syPYIJA9FwwsaYHKOTqZeF4FGTEyXXby64+wM=
# SIG # End signature block
