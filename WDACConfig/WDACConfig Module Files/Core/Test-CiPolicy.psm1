Function Test-CiPolicy {
    [CmdletBinding()]
    [OutputType([System.Boolean], [System.Security.Cryptography.X509Certificates.X509Certificate2[]])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'XML File')]
        [System.IO.FileInfo]$XmlFile,

        [ValidateScript({ Test-Path -LiteralPath $_ -PathType 'Leaf' })]
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'CIP File')]
        [System.IO.FileInfo]$CipFile
    )
    Begin {
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"
    }

    process {

        # If a CI XML file is being tested
        if ($PSCmdlet.ParameterSetName -eq 'XML File' -and $PSBoundParameters.ContainsKey('XmlFile')) {

            # Check if the schema file exists in the system drive
            if (-NOT (Test-Path -LiteralPath $CISchemaPath)) {
                Throw "The Code Integrity Schema file could not be found at: $CISchemaPath"
            }

            # Check if the XML file exists - performing this check here instead of ValidateScript of the parameter produces a better error message when this function is called from within other main cmdlets' parameters.
            if (-NOT (Test-Path -LiteralPath $XmlFile -PathType 'Leaf')) {
                Throw "The file $XmlFile does not exist."
            }

            # Assign the schema file path to a variable
            [System.IO.FileInfo]$SchemaFilePath = $CISchemaPath
            # Define a script block to handle validation errors
            [System.Management.Automation.ScriptBlock]$ValidationEventHandler = { Throw $args[1].Exception }

            # Create an XML reader object from the schema file path
            [System.Xml.XmlReader]$XmlReader = [System.Xml.XmlReader]::Create($SchemaFilePath)
            # Read the schema object from the XML reader
            [System.Xml.Schema.XmlSchemaObject]$XmlSchemaObject = [System.Xml.Schema.XmlSchema]::Read($XmlReader, $ValidationEventHandler)

            # Create a variable to store the validation result
            [System.Boolean]$IsValid = $false

            try {
                # Create an XML document object
                [System.Xml.XmlDocument]$Xml = New-Object -TypeName System.Xml.XmlDocument
                # Add the schema object to the XML document
                $Xml.Schemas.Add($XmlSchemaObject) | Out-Null
                # Load the XML file to the XML document
                $Xml.Load($XmlFile)
                # Validate the XML document against the schema object
                $Xml.Validate({
                        # Throw an exception if the validation fails
                        Throw ([PsCustomObject] @{
                                XmlFile   = $XmlFile
                                Exception = $args[1].Exception
                            })
                    })

                # If the validation succeeds, set the IsValid variable to $true
                $IsValid = $true
            }
            catch {
                # Rethrow the exception
                Throw $_
            }
            finally {
                # Close the XML reader object
                $XmlReader.Close()
            }

            # Return the validation result
            Return $IsValid
        }

        # If a CI binary is being tested
        elseif ($PSCmdlet.ParameterSetName -eq 'CIP File' -and $PSBoundParameters.ContainsKey('CipFile')) {

            try {

                # Create a new SignedCms object to store the signed message
                [System.Security.Cryptography.Pkcs.SignedCms]$SignedCryptoMsgSyntax = New-Object -TypeName System.Security.Cryptography.Pkcs.SignedCms

                # Decode the signed message from the file specified by $CipFile
                # The file is read as a byte array because the SignedCms.Decode() method expects a byte array as input
                # https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.signedcms.decode
                $SignedCryptoMsgSyntax.Decode((Get-Content -LiteralPath $CipFile -AsByteStream -Raw))

                # Return an array of X509Certificate2 objects that represent the certificates used to sign the message
                Return [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$SignedCryptoMsgSyntax.Certificates

            }
            catch {
                Write-Verbose -Message "The file $CipFile does not contain a valid signature." -Verbose
                Return $null
            }
        }
    }
    <#
.SYNOPSIS
    Tests the Code Integrity Policy XML file against the Code Integrity Schema.
    It can also display the signer information from a signed Code Integrity policy .CIP binary file. Get-AuthenticodeSignature cmdlet does not show signers in .CIP files.
.DESCRIPTION
    The Test-CiPolicy cmdlet can test a Code Integrity (WDAC) Policy.
    If you input a XML file, it will validate it against the Schema file located at: "$Env:SystemDrive\Windows\schemas\CodeIntegrity\cipolicy.xsd"
    and returns a boolean value indicating whether the XML file is valid or not.

    If you input a signed binary Code Integrity Policy file, it will return the signer information from the file.
.PARAMETER XmlFile
    The Code Integrity Policy XML file to test. Supports file picker GUI.
.PARAMETER CipFile
    The binary Code Integrity Policy file to test for signers. Supports file picker GUI.
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Test-CiPolicy
.INPUTS
    [System.IO.FileInfo]
.OUTPUTS
    System.Boolean
    System.Security.Cryptography.X509Certificates.X509Certificate2[]
.EXAMPLE
    Test-CiPolicy -XmlFile "C:\path\to\policy.xml"
.EXAMPLE
    Test-CiPolicy -CipFile "C:\Users\Admin\{C5F45D1A-97F7-42CF-84F1-40755F1AEB97}.cip"
    #>
}

Register-ArgumentCompleter -CommandName 'Test-CiPolicy' -ParameterName 'XmlFile' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterXmlFilePathsPicker)
Register-ArgumentCompleter -CommandName 'Test-CiPolicy' -ParameterName 'CipFile' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterAnyFilePathsPicker)

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB4SIyH5b+sVRuA
# bSxyCw2d6rf6fhSzQ2U1JVK5oqyu1qCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgSbUazFxpQJ34FlHJzPlNHaE82kaX++JgJrG9Hqu18NowDQYJKoZIhvcNAQEB
# BQAEggIAAmlzIigASW5RZIAJ06gwxtkpUqkqm/hXWqQhn865I67J0jPqVoYiE3Xy
# VKO9WCNyPpzqs2LO2UjU/o0KpRr2xTQnTNCpCepJSJ7kvbp/ThJTAvnzeNjlVSP/
# ztrVVldujvv7vuqwcukHGXUiYxviiTiB3nE1A6K1M46u3JZpuPYh7si3u1PA33pj
# fiOc8mB7BR7I3RBKxtJHwge6WHX/DdHpklOnRQiLEpuwQLk7etYE/WjB5XAGKSEG
# cJ4jePeMSPFMvaR09TNqOHW+2if5SwyQOYjIasZYoyvPzF92Jf49vkL9YYLfsIiH
# bvS/AKbHG7ooKLR6IUDs3edqCW9lSC9iDQJ6+J3BdftzOMZZEjfb9xT9kZ6mvbDO
# Wep1Yut3anjFYp+e6yhJKmEoEyxYiiWfQA2lIR1mjQGL7LOkaP+bh7PG9VAaHDvk
# 5/24ZraZj02BqVypOzmObx2MfzzeeuRZxCufaF2/7zy6g/Cge++oSCpZwhGSiYai
# CTDbSCg3nJnwWJDyhHmJd6HS2xRkqE+UdINcO7PJeaGzfnEkp1Y31/v5CtYawOx6
# QiWz2pnAv9nOxEbajqCIi9DJfSWXjBebPNUjW+g1J+uiLHzjor76k19zB7uXuaV/
# JYh3LDdO9OzQ5+QQej+Bt2GVimYnp1SmE+SgvuFZADLDbP1Vuh8=
# SIG # End signature block
