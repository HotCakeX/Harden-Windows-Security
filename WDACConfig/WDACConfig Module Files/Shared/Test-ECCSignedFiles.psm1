Function Test-ECCSignedFiles {
    <#
.SYNOPSIS
    This function gets list of directories or files
    Then it checks if the files are WDAC compliant
    If they are, it checks if they are signed with ECC
    If they are, it returns an array of them if -Process parameter is not used

    With -Progress parameter, the function creates Hash level rules for each ECC file
    puts them in a separate XML policy file and returns the path to it
.PARAMETER Directory
    The directories to process
.PARAMETER File
    The files to process
.PARAMETER Process
    Indicates that instead of returning list of ECC Signed files, the function
    will create Hash Level rules for them
.PARAMETER ECCSignedFilesTempPolicy
    The path to the temporary policy file where the Hash Level rules will be stored.
.INPUTS
    System.IO.DirectoryInfo[]
    System.IO.FileInfo[]
.OUTPUTS
    System.String[]
    System.IO.FileInfo
.NOTES
    The OID of the ECC algorithm for public keys is '1.2.840.10045.2.1'
#>
    Param (
        [ValidateScript({ [System.IO.Directory]::Exists($_) })]
        [Parameter(Mandatory = $false)][System.IO.DirectoryInfo[]]$Directory,

        [Parameter(Mandatory = $false)][System.IO.FileInfo[]]$File,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$Process,
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$ECCSignedFilesTempPolicy
    )
    Begin {
        Write-Verbose -Message 'Test-ECCSignedFiles: Importing the required sub-modules'
        Import-Module -Force -FullyQualifiedName @(
            "$ModuleRootPath\Shared\Get-KernelModeDrivers.psm1",
            "$ModuleRootPath\XMLOps\New-HashLevelRules.psm1",
            "$ModuleRootPath\XMLOps\Clear-CiPolicy_Semantic.psm1"
        ) -Verbose:$false

        $WDACSupportedFiles = [System.Collections.Generic.HashSet[System.String]]@()

        # Get the compliant WDAC files from the File and Directory parameters and add them to the HashSet
        $WDACSupportedFiles.UnionWith([System.String[]](([WDACConfig.FileUtility]::GetFilesFast($Directory, $File, $null))))
    }
    Process {
        Write-Verbose -Message "Test-ECCSignedFiles: Processing $($WDACSupportedFiles.Count) WDAC compliant files to check for ECC signatures."
        # The check for existence is mainly for the files detected in audit logs that no longer exist on the disk
        # Audit logs or MDE data simply don't have the data related to the file's signature algorithm, so only local files can be checked

        $ECCSignedFiles = [System.Collections.Generic.HashSet[System.String]]@(
            foreach ($Path in $WDACSupportedFiles) {

                if (([System.IO.FileInfo]$Path).Exists -eq $true) {

                    $AuthResult = Get-AuthenticodeSignature -LiteralPath $Path

                    if ($AuthResult.Status -ieq 'Valid') {

                        if (($AuthResult.SignerCertificate.PublicKey.Oid.Value).Contains('1.2.840.10045.2.1')) {
                            #  Write-Verbose -Message "Test-ECCSignedFiles: The file '$Path' is signed with ECC algorithm. Will create Hash Level rules for it."
                            $Path
                        }
                    }
                }
            }
        )
    }
    End {
        if (-NOT $Process) {
            Return ($ECCSignedFiles.Count -gt 0 ? $ECCSignedFiles : $null)
        }
        else {

            if (($null -ne $ECCSignedFiles) -and ($ECCSignedFiles.Count -gt 0)) {

                $CompleteHashes = New-Object -TypeName 'System.Collections.Generic.List[WDACConfig.HashCreator]'

                foreach ($ECCSignedFile in $ECCSignedFiles) {

                    [WDACConfig.AuthenticodePageHashes]$HashOutput = [WDACConfig.AuthPageHash]::GetCiFileHashes($ECCSignedFile)

                    $CompleteHashes.Add([WDACConfig.HashCreator]::New(
                            $HashOutput.SHA256Authenticode,
                            $HashOutput.SHA1Authenticode,
                        ([System.IO.FileInfo]$ECCSignedFile).Name,
                            # Check if the file is kernel-mode or user-mode -- Don't need the verbose output of the cmdlet when using it in embedded mode
                        ($null -eq (Get-KernelModeDrivers -File $ECCSignedFile 4>$null)) ? 1 : 0
                        )
                    )
                }

                Copy-Item -LiteralPath 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml' -Destination $ECCSignedFilesTempPolicy -Force
                Clear-CiPolicy_Semantic -Path $ECCSignedFilesTempPolicy

                New-HashLevelRules -Hashes $CompleteHashes -XmlFilePath $ECCSignedFilesTempPolicy

                Return $ECCSignedFilesTempPolicy
            }
            else {
                Write-Verbose -Message 'Test-ECCSignedFiles: No ECC signed files found. Exiting the function.'
                Return $null
            }
        }
    }
}
Export-ModuleMember -Function 'Test-ECCSignedFiles'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBGrSXCW8yZa3OL
# jqKvP0s5vqUrsqH48BsBnCJPq+nN2aCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQg/b/hpjGTT/ObdmBcmEzUQN/ZqTmDW6Xm/tdNSZwsi1QwDQYJKoZIhvcNAQEB
# BQAEggIAj1idLXglZ/ffBrdoVmokmI7Nj/5XJ2pcAdlaOXlQG2N046E6Jj8PiP0J
# nmrQlfL3+vPI+R8e50wgoRZOQCIeB74Xp+wUccoUbfa5PINRJubKtgwYfSUifnK3
# dQgWjGEPPGAVxpZeX0JZUjo4U0adVd1tuEsUCTqcEGFi4W92qsv9cmBO8xOm9XRI
# JUV/IqAAM5nOTHI9R2B4b+lvUPmOECrCXPi+YTZq0MAzy6Z4vQSCqbn3PW1QTNqv
# oruNvqaywrzSRxbklvkuAXZxzmcPtRxnl9A+/mJ2ZgOHLXbLJYKvEaxajiHPDWv/
# 95A9Y1ekIMZFM1u5iheDberkEKlIcCN1SRk16UIFYD8lolQLIpkBbNJTExjB09JG
# pAJOaYRwvHMNOKts/rY1IrCIPJjpzGsQy1XAycncn+YYL48FubrSDlxwz1MBgXto
# is181beGFVXboPYh2QRLeO9twuPBAkzRyJQCzvMkBD3844vpQjsfnBqZLPqat7fi
# 3Zw5h9gWywK9pCrywBMyh+ai3VVn6VvhW8WPsIWK3MyUNPqfSSQA5iQxSGYNaUZu
# xOgSaGvHKj6u4XCca/MnPASzgF8uZgi6V+X9eYE+orzRSoR6J5KK1roXrGktXZE5
# nhd8E3V4LxfOBOvNFouLYREmbX4C7p92yc/mzATpmgIQn+WkkOA=
# SIG # End signature block
