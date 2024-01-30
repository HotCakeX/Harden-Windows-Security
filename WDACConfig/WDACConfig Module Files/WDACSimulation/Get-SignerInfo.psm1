# Importing the $PSDefaultParameterValues to the current session, prior to everything else
. "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

# Defining the Signer class from the WDACConfig Namespace if it doesn't already exist
if (-NOT ('WDACConfig.Signer' -as [System.Type]) ) {
    Add-Type -Path "$ModuleRootPath\C#\Signer.cs"
}
Function Get-SignerInfo {
    <#
    .SYNOPSIS
        Function that takes an XML file path as input and returns an array of Signer objects
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        WDACConfig.Signer[]
    .PARAMETER XmlFilePath
        The XML file path that the user selected for WDAC simulation.
    #>
    [CmdletBinding()]
    [OutputType([WDACConfig.Signer[]])]
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
        [WDACConfig.Signer[]]$Output = @()

        # Loop through each Signer node and extract the information
        foreach ($Signer in $Signers) {
            
            # Replacing Wellknown root IDs with their corresponding TBS values
            if ($Signer.CertRoot.Value -in ('03', '04', '05', '06', '07', '09', '0A', '0E', '0G', '0H', '0I')) {
                switch ($Signer.CertRoot.Value) {
                    '03' { 
                        $Signer.CertRoot.Value = 'D67576F5521D1CCAB52E9215E0F9F743'
                        $Signer.Name = 'Microsoft Authenticode(tm) Root Authority'
                        break 
                    }
                    '04' {
                        $Signer.CertRoot.Value = '8B3C3087B7056F5EC5DDBA91A1B901F0'
                        $Signer.Name = 'Microsoft Root Authority'                   
                        break 
                    }
                    '05' {
                        $Signer.CertRoot.Value = '391BE92883D52509155BFEAE27B9BD340170B76B'
                        $Signer.Name = 'Microsoft Root Certificate Authority'
                        break 
                    }
                    '06' { 
                        $Signer.CertRoot.Value = '121AF4B922A74247EA49DF50DE37609CC1451A1FE06B2CB7E1E079B492BD8195'
                        $Signer.Name = 'Microsoft Code Signing PCA 2010'
                        break 
                    }
                    '07' {
                        $Signer.CertRoot.Value = 'F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E'
                        $Signer.Name = 'Microsoft Code Signing PCA 2011'
                        break 
                    }
                    '09' {
                        $Signer.CertRoot.Value = '09CBAFBD98E81B4D6BAAAB32B8B2F5D7'
                        $Signer.Name = 'Microsoft Test Root Authority'
                        break 
                    }
                    '0A' { 
                        $Signer.CertRoot.Value = '7A4D9890B0F9006A6F77472D50D83CA54975FCC2B7EA0563490134E19B78782A'
                        $Signer.Name = 'Microsoft Testing Root Certificate Authority 2010'
                        break 
                    }
                    '0E' { 
                        $Signer.CertRoot.Value = 'ED55F82E1444F79CA9DCE826846FDC4E0EA3859E3D26EFEF412D2FFF0C7C8E6C'
                        $Signer.Name = 'Microsoft Development Root Certificate Authority 2014'
                        break 
                    }
                    '0G' {
                        $Signer.CertRoot.Value = '68D221D720E975DB5CD14B24F2970F86A5B8605A2A1BC784A17B83F7CF500A70EB177CE228273B8540A800178F23EAC8'
                        $Signer.Name = 'Microsoft ECC Testing Root Certificate Authority 2017'
                        break 
                    }
                    '0H' {
                        $Signer.CertRoot.Value = '214592CB01B59104195F80AF2886DBF85771AF42A3821D104BF18F415158C49CBC233511672CD6C432351AC9228E3E75'
                        $Signer.Name = 'Microsoft ECC Development Root Certificate Authority 2018'
                        break 
                    }
                    '0I' {
                        $Signer.CertRoot.Value = '32991981BF1575A1A5303BB93A381723EA346B9EC130FDB596A75BA1D7CE0B0A06570BB985D25841E23BE944E8FF118F'
                        $Signer.Name = 'Microsoft ECC Product Root Certificate Authority 2018'
                        break 
                    }
                }               
            }

            # Create a new instance of the Signer class in the WDACConfig Namespace
            [WDACConfig.Signer]$SignerObj = New-Object -TypeName WDACConfig.Signer -ArgumentList ($Signer.ID, $Signer.Name, $Signer.CertRoot.Value, $Signer.CertPublisher.Value)

            # Add the Signer object to the output array
            $Output += $SignerObj
        }
    }
    end {
        # Return the output array
        return $Output
    }
}
Export-ModuleMember -Function 'Get-SignerInfo'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDApimZfjaPVouH
# k4LfiyLodW7Msn8Fv3cRCl65Gty/taCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgHMrEKSmH7vZa0e/bFjHuH1QCOZD8o1RY4k83W8kcW3swDQYJKoZIhvcNAQEB
# BQAEggIAI+nEpiaTQcIxRkrKvzVl3v2eRQCYZLunB10rmOVJ54zH8tgnqxq1W62j
# SFALqFgoK4YW4yJn07j9WVxVqOW+zWl889HY8UTfby4PxxkqnyAtdEjJqZuUiGXz
# D2iBkXNz+7oNcNcCXgg85YH42kf/i581svFisAoKEeRN4uV24iK+FJ641Oy+17Ft
# d+EOznq/DLP2toMTAfcr3lXKA6cVmBVY/t3TOdLjRh33uXYkBabeoqxMrJkTnOYS
# 2pbsfq5xZ6gfDSt1OdEnLwHs/sqgvU/3l0SAHGOb5g5jk8sGt1g5BT8/6Behnada
# veHFfv23Ixar92lrjWiaqNSsoF5LLHCZPbFFkRFTsujtJMMwiAO9WonfFA3YwUFl
# h1Tci3HPrZXgTX748u1ubwnS1j+vVfSVWkI4RrkCpA/EA0f7YGmcPoQePMYYXdUH
# pRY8WJp2dCyY7WQHRRV41tE50EsfZceCkmRLg9PODufCIlcCYCIA3PkOwQsqsGyr
# ZfXI83qX7lmG80Zr1ii8Gz/vajSrsEfjTk4sR6M5CgToXaWSNKj6GMdkjgmZhheV
# aGeI+bB5NzmUUUVEb6Eqj5xjXdYmWw5h1NLBp9xXuN4XE9QwROrWZ/DrwxtIlQnE
# mtrK97GMim7hzvOayYcjDlaGbP+Oltvwi929TXNsJyBUWmS8tEU=
# SIG # End signature block
