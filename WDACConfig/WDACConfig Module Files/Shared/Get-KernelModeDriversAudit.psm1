Function Get-KernelModeDriversAudit {
    <#
    .DESCRIPTION
        This function will scan the Code Integrity event logs for kernel mode drivers that have been loaded since the audit mode policy has been deployed
        and will return a folder containing symbolic links to the driver files.
    .INPUTS
        None
    .OUTPUTS
        System.IO.DirectoryInfo
    .NOTES
        Get-SystemDriver only includes .sys files when -UserPEs parameter is not used, but Get-KernelModeDriversAudit function includes .dll files as well just in case

        When Get-SystemDriver -UserPEs is used, Dlls and .exe files are included as well
    #>
    [CmdletBinding()]
    [OutputType([System.IO.DirectoryInfo])]
    param()

    begin {
        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Importing the required sub-modules
        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Receive-CodeIntegrityLogs.psm1" -Force

        [System.IO.FileInfo[]]$KernelModeDriversPaths = @()
    }

    process {

        # Get the Code Integrity event logs for kernel mode drivers that have been loaded since the audit mode policy has been deployed
        [System.Object[]]$RawData = Receive-CodeIntegrityLogs -Date (Get-CommonWDACConfig -StrictKernelModePolicyTimeOfDeployment)

        Write-Verbose -Message "RawData count: $($RawData.count)"

        Write-Verbose -Message 'Saving the file paths to a variable'
        [System.IO.FileInfo[]]$KernelModeDriversPaths = $RawData.'File Name'

        Write-Verbose -Message 'Filtering based on files that exist with .sys and .dll extensions'
        $KernelModeDriversPaths = $KernelModeDriversPaths | Where-Object -FilterScript { ($_.Extension -in ('.sys', '.dll')) -and ($_.Exists) }

        Write-Verbose -Message "KernelModeDriversPaths count after filtering based on files that exist with .sys and .dll extensions: $($KernelModeDriversPaths.count)"

        Write-Verbose -Message 'Removing duplicates based on file path'
        $KernelModeDriversPaths = $KernelModeDriversPaths | Group-Object -Property 'FullName' | ForEach-Object -Process { $_.Group[0] }

        Write-Verbose -Message "KernelModeDriversPaths count after deduplication based on file path: $($KernelModeDriversPaths.count)"

        Write-Verbose -Message 'Creating a temporary folder to store the symbolic links to the driver files'
        [System.IO.DirectoryInfo]$SymLinksStorage = New-Item -Path ($UserTempDirectoryPath + 'SymLinkStorage' + $(New-Guid)) -ItemType Directory -Force

        Write-Verbose -Message 'Creating symbolic links to the driver files'
        Foreach ($File in $KernelModeDriversPaths) {
            New-Item -ItemType SymbolicLink -Path "$SymLinksStorage\$($File.Name)" -Target $File.FullName | Out-Null
        }
    }
    end {
        Write-Verbose -Message 'Returning the folder containing the symbolic links to driver files'
        return [System.IO.DirectoryInfo]$SymLinksStorage
    }
}
Export-ModuleMember -Function 'Get-KernelModeDriversAudit'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD0+GCu9qoVzNTu
# yVOOCDea8QxQx6yXcFJ/3kM5IA7aSqCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgkshB9w369+5KJWGjiUM/aOAxKjDIl0mvFvcJt4aquvgwDQYJKoZIhvcNAQEB
# BQAEggIAZsaZruNsmpaYTn83ft9xTThhd4Tikh71PshCSyZrVoTSWCuP5QB69BK5
# fPMoWUn+f1TaPMwyCzvp9AOzLESSs4UDtBKVjpZoeWRrC6M/DMewZXlnj70efzPI
# v0G7VFHAIA8PjRdwToe2PR6OxVANNIjn5Vm4Rt+qhO8tSoyLKcUVVT3geUtvcIcy
# ZXvty4SRTBzRL3UEuFR4ch0bCt0BfhBK9knUSQprDaS3q1z3WXo8STtcHDoEG1Fl
# Y0ONofussvtPgAvUwzfAwWYy1YVIGrPwnH7CuRuQUwjg/scAeswAFIU5jK2DnM85
# WobBWOq4Q8BUAezPKw6stRPUZM+RV03efRWI08bLfwCNeJioUkcG1IjBkkwxyWhJ
# ePvAzz58eXIa3pN0/NgXo4skKIBty4saJqhR3au6/zqc2Mu2ln0Ua2lVVDM7kSVb
# 1z3jahd2J2OitE4PhVuQ5sTIOe7j7d14CjZOvY77uLhBtMmihHjmA9Nuo7eZ5+ej
# hUqPRi0DCxvi343Uumc31vSbv9jEKcwuz86XApcsKYx96mCGeq9Zq5/62IGMR5Ci
# FJz3nKYg/wGVPKPAxJ/W79ubbtuGDi1ydLijMBvJ2iRMe/Z6ucnAAghxJ/DnUW1Q
# u/ydCDntW1K3QVrRIjP9PW4FcpOl9HRn5TmUV/IbQ9XLwFvwiTM=
# SIG # End signature block
