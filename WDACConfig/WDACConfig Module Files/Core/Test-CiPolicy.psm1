Function Test-CiPolicy {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [System.IO.FileInfo]$XmlFile
    )

    begin {
        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null

        # Check if the schema file exists in the system drive
        if (-NOT (Test-Path -Path $CISchemaPath)) {
            Throw "The Code Integrity Schema file could not be found at: $CISchemaPath"
        }

        # Assign the schema file path to a variable
        [System.IO.FileInfo]$SchemaFilePath = $CISchemaPath
        # Define a script block to handle validation errors
        [System.Management.Automation.ScriptBlock]$ValidationEventHandler = { Throw $args[1].Exception }
    }

    process {
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
    }
    End {
        # Return the validation result
        Return $IsValid
    }
    <#
.SYNOPSIS
    Tests the Code Integrity Policy XML file against the Code Integrity Schema file.
.DESCRIPTION
    The Test-CiPolicy cmdlet tests a Code Integrity (WDAC) Policy XML file against the Schema file located at: "$Env:SystemDrive\Windows\schemas\CodeIntegrity\cipolicy.xsd"
    It returns a boolean value indicating whether the XML file is valid or not.
.PARAMETER XmlFile
    The Code Integrity Policy XML file to test. Supports file picker GUI.
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Test-CiPolicy
.INPUTS
    [System.IO.FileInfo]
.OUTPUTS
    System.Boolean
.EXAMPLE
    Test-CiPolicy -XmlFile "C:\path\to\policy.xml"
    #>
}

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\Resources\ArgumentCompleters.ps1"

Register-ArgumentCompleter -CommandName 'Test-CiPolicy' -ParameterName 'XmlFile' -ScriptBlock $ArgumentCompleterXmlFilePathsPicker

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDZl8yYCNRU2fdk
# O429hUnCZoYD//+otXyNQ/SZZDQhhKCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgq/5/8FCoby+iqSpBilh5ky6i8g9AlbJsMj0f01/iWWAwDQYJKoZIhvcNAQEB
# BQAEggIAnKxvt/8WKRvOv4hzj+CtUdBBUh16Fv4rgWEb3nQ2CyJkErRVULeXUHuq
# o3vTYkc2qB9BzdXYwSM6Sy8bJDlSQsNVXy715ihE44tR8Op87AxvG5Nkfy4nQ/s7
# hQxcXmedGXOMJmy+AuVmUIXE8BW/QDSg/ME4v1vmstcm/antQPJWzKTwLUpfgtYC
# g9bjllvP8YbPNhyI/jS9mMAnQRR01c++85+uiy3/dWVb/7J/PgnT74J/Tv8RbcY7
# M2cFUu3eO6krAv2MIVyLdKETtgJwRafB5L8zYK6MXX1Xlu2cNB0Vjt3XvEOB+PKE
# Rgzk69CuaeZEx3iJDV3QdFL0hZhh38U3mr89k3yRWZgnlKxg1Pe2YkQRKffvNj+R
# vyQNHlIzLlfglVYDZIX2XjSSFcAy28YAHXliKtM7HndHczSB+DAJ21i3eKco85gJ
# WMIqfHC/CVreMeoWqZjRZdXt6ztAhfsi+FphaLhUnZX0LnOnEnt5IkfKBjrEQFVl
# xJpeEEFImt6uw3bgn+UQz+uv7NezSKcZyZ3ESGmdsQ8NJi8fEu0e84Na3OaJ6Lk9
# 0IDccONP5V4D4KN5tRPZWQI1oP59gj0s0bje3MI+hJ6idhLUWbTjuTT0fnMezCcR
# jJKPqkTTt7soDtPxW8DfDh+s3To4bBHs5kU4FAIKc3pOZFQcIOs=
# SIG # End signature block
