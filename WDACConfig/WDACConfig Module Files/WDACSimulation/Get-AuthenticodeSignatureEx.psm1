# Importing the $PSDefaultParameterValues to the current session, prior to everything else
. "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

Function Get-AuthenticodeSignatureEx {
    <#
    .SYNOPSIS
        Helps to get the 2nd aka nested signer/signature of the dual signed files
    .NOTES
        This function is used in a very minimum capacity by the WDACConfig module and it's modified to meet the WDACConfig's requirements
    .LINK
        https://www.sysadmins.lv/blog-en/reading-multiple-signatures-from-signed-file-with-powershell.aspx
        https://www.sysadmins.lv/disclaimer.aspx
    .PARAMETER FilePath
        The path of the file(s) to get the signature of
    .INPUTS
        System.String[]
    .OUTPUTS
        System.Management.Automation.Signature
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String[]]$FilePath
    )

    begin {

        # Define the signature of the Crypt32.dll library functions to use
        [System.String]$Signature = @'
    [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool CryptQueryObject(
        int dwObjectType,
        [MarshalAs(UnmanagedType.LPWStr)]
        string pvObject,
        int dwExpectedContentTypeFlags,
        int dwExpectedFormatTypeFlags,
        int dwFlags,
        ref int pdwMsgAndCertEncodingType,
        ref int pdwContentType,
        ref int pdwFormatType,
        ref IntPtr phCertStore,
        ref IntPtr phMsg,
        ref IntPtr ppvContext
    );
    [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool CryptMsgGetParam(
        IntPtr hCryptMsg,
        int dwParamType,
        int dwIndex,
        byte[] pvData,
        ref int pcbData
    );
    [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool CryptMsgClose(
        IntPtr hCryptMsg
    );
    [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool CertCloseStore(
        IntPtr hCertStore,
        int dwFlags
    );
'@

        # Load the System.Security assembly to use the SignedCms class
        Add-Type -AssemblyName 'System.Security' -ErrorAction SilentlyContinue
        # Add the Crypt32.dll library functions as a type
        Add-Type -MemberDefinition $Signature -Namespace 'PKI' -Name 'Crypt32' -Language CSharp -ErrorAction SilentlyContinue

        # Define some constants for the CryptQueryObject function parameters
        [System.Int16]$CERT_QUERY_OBJECT_FILE = 0x1
        [System.Int32]$CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 0x400
        [System.Int16]$CERT_QUERY_FORMAT_FLAG_BINARY = 0x2

        # Define a helper function to get the timestamps of the countersigners
        function Get-TimeStamps {
            param (
                $SignerInfo
            )

            [System.Object[]]$RetValue = @()

            foreach ($CounterSignerInfos in $Infos.CounterSignerInfos) {
                # Get the signing time attribute from the countersigner info object
                $STime = ($CounterSignerInfos.SignedAttributes | Where-Object -FilterScript { $_.Oid.Value -eq '1.2.840.113549.1.9.5' }).Values | `
                    Where-Object -FilterScript { $null -ne $_.SigningTime }
                # Create a custom object with the countersigner certificate and signing time properties
                $TsObject = New-Object psobject -Property @{
                    Certificate = $CounterSignerInfos.Certificate
                    SigningTime = $STime.SigningTime.ToLocalTime()
                }
                # Add the custom object to the return value array
                $RetValue += $TsObject
            }
            # Return the array of custom objects with countersigner info
            $RetValue

        }
    }
    process {
        # For each file path, get the authenticode signature using the built-in cmdlet
        foreach ($Output in Get-AuthenticodeSignature $FilePath) {

            # Initialize some variables to store the output parameters of the CryptQueryObject function
            [System.Int64]$PdwMsgAndCertEncodingType = 0
            [System.Int64]$PdwContentType = 0
            [System.Int64]$PdwFormatType = 0
            [System.IntPtr]$PhCertStore = [System.IntPtr]::Zero
            [System.IntPtr]$PhMsg = [System.IntPtr]::Zero
            [System.IntPtr]$PpvContext = [System.IntPtr]::Zero

            # Call the CryptQueryObject function to get the handle of the PKCS #7 message from the file path
            $Return = [PKI.Crypt32]::CryptQueryObject(
                $CERT_QUERY_OBJECT_FILE,
                $Output.Path,
                $CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                $CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                [ref]$pdwMsgAndCertEncodingType,
                [ref]$pdwContentType,
                [ref]$pdwFormatType,
                [ref]$phCertStore,
                [ref]$phMsg,
                [ref]$ppvContext
            )
            # If the function fails, return nothing
            if (!$Return) { return }

            # Initialize a variable to store the size of the PKCS #7 message data
            [System.Int64]$PcbData = 0

            # Call the CryptMsgGetParam function to get the size of the PKCS #7 message data
            $Return = [PKI.Crypt32]::CryptMsgGetParam($phMsg, 29, 0, $null, [ref]$PcbData)

            # If the function fails, return nothing
            if (!$Return) { return }

            # Create a byte array to store the PKCS #7 message data
            $PvData = New-Object -TypeName 'System.Byte[]' -ArgumentList $PcbData

            # Call the CryptMsgGetParam function again to get the PKCS #7 message data
            $Return = [PKI.Crypt32]::CryptMsgGetParam($PhMsg, 29, 0, $PvData, [System.Management.Automation.PSReference]$PcbData)

            # Create a SignedCms object to decode the PKCS #7 message data
            [System.Security.Cryptography.Pkcs.SignedCms]$SignedCms = New-Object -TypeName 'Security.Cryptography.Pkcs.SignedCms'

            # Decode the PKCS #7 message data and populate the SignedCms object properties
            $SignedCms.Decode($PvData)

            # Get the first signer info object from the SignedCms object
            $Infos = $SignedCms.SignerInfos[0]

            # Add some properties to the output object, such as TimeStamps, DigestAlgorithm and NestedSignature
            $Output | Add-Member -MemberType NoteProperty -Name TimeStamps -Value $null
            $Output | Add-Member -MemberType NoteProperty -Name DigestAlgorithm -Value $Infos.DigestAlgorithm.FriendlyName

            # Call the helper function to get the timestamps of the countersigners and assign it to the TimeStamps property
            $Output.TimeStamps = Get-TimeStamps -SignerInfo $Infos

            # Check if there is a nested signature attribute in the signer info object by looking for the OID 1.3.6.1.4.1.311.2.4.1
            $second = $Infos.UnsignedAttributes | Where-Object -FilterScript { $_.Oid.Value -eq '1.3.6.1.4.1.311.2.4.1' }

            if ($Second) {

                # If there is a nested signature attribute
                # Get the value of the nested signature attribute as a raw data byte array
                $value = $Second.Values | Where-Object -FilterScript { $_.Oid.Value -eq '1.3.6.1.4.1.311.2.4.1' }

                # Create another SignedCms object to decode the nested signature data
                [System.Security.Cryptography.Pkcs.SignedCms]$SignedCms2 = New-Object -TypeName 'Security.Cryptography.Pkcs.SignedCms'

                # Decode the nested signature data and populate the SignedCms object properties
                $SignedCms2.Decode($value.RawData)
                $Output | Add-Member -MemberType NoteProperty -Name NestedSignature -Value $null

                # Get the first signer info object from the nested signature SignedCms object
                $Infos = $SignedCms2.SignerInfos[0]

                # Create a custom object with some properties of the nested signature, such as signer certificate, digest algorithm and timestamps
                $Nested = New-Object -TypeName 'psobject' -Property @{
                    SignerCertificate = $Infos.Certificate
                    DigestAlgorithm   = $Infos.DigestAlgorithm.FriendlyName
                    TimeStamps        = Get-TimeStamps -SignerInfo $Infos
                }
                # Assign the custom object to the NestedSignature property of the output object
                $Output.NestedSignature = $Nested
            }
            # Return the output object with the added properties
            $Output

            # Close the handles of the PKCS #7 message and the certificate store
            [void][PKI.Crypt32]::CryptMsgClose($PhMsg)
            [void][PKI.Crypt32]::CertCloseStore($PhCertStore, 0)
        }
    }
    end {}
}
Export-ModuleMember -Function 'Get-AuthenticodeSignatureEx'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAL7zoA7fc/1S+o
# flCAMcQ1KGnu3dUPl8UjcoubuDNWsqCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgrBh2TAyE2VZZd1YAsFvva6YTVuyPu3suvnJh8HkCoAMwDQYJKoZIhvcNAQEB
# BQAEggIAR0bzsZW3FsPmI2bt4ys0kchjqu6+Srybb4Fmg2SfHlI2Yp3TM9tgpJ9O
# TAZNbsPgvaf9uEQngUajw2nKkn7gE8bBWdT4ZClOdy2jejGPhAOgnwfgtvAILkvJ
# JVjIpZzcsVBjpCA1PhPN3TLWFOuzs/pmxm0UcPE4+eqKCvsUp+XAAYtnxw1A/S1u
# JlD3iCGQH6RMtEXleM63GtPeslqVPrA7Rvjw/pkWvcr1rvWEDAd7hiDNwzSh0T43
# gKBrpM0DOE+6IHoFAxn8OR5bQNCbNW2EZpbjcacs5c9xAB7BCFy8mrvIn5Y3qO5P
# IWX6j1SPYGWudx2a4h60zpFtWtb2uPFNw5K4obRKhZ6VRK22B9IQJGKKqTORDXY8
# lEBZ2SBqWxNYngygE9UUYMnPLu6YTIQ3KoN0q7aPScolC5jD9O7X9BKhFs2a+3lL
# kbpe2V4UCiGUUIakOoo3FlXYJrjyuSQ9iyzpEwp4mLfHk4R+CWcWdX2TlyFjEUvd
# qiPSNKlZKUhS80lVu5nmtyRXWwLb+JiJ9/BtIW+P1exHUKx258gfhCvhBtLTeA8E
# XUENqVCn6Cm0AGLVnyjHQF8hPqLMvWuinhbIZMmraRoLoVEbVr6NOA5KfFLnxYgj
# Wh60nTSl4G+G7hyu4t1JNfD+3y3/dRevKbbtP3AroBc3Ik6IMn8=
# SIG # End signature block
