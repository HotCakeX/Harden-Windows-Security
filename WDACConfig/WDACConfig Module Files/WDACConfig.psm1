<# -------- Guidance for code readers --------
The module uses tight import/export control, no internal function is exposed on the console/to the user.
The $PSDefaultParameterValues located in "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1" is imported via dot-sourcing to the current session of each main cmdlet/internal function that calls any (other) internal function or uses any of the cmdlets defined in that file, prior to everything else.
At the beginning of each main cmdlet, 2 custom $Verbose and/or $Debug variables are defined which help to take actions based on Verbose/Debug preferences and also pass the $VerbosePreference and $DebugPreference to the subsequent sub-functions/modules being called from the main cmdlets.
#>

# Stopping the module process if any error occurs
$global:ErrorActionPreference = 'Stop'

# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadLineKeyHandler -Key 'Tab' -Function 'MenuComplete'

# Enables additional progress indicators for Windows Terminal and Windows
$PSStyle.Progress.UseOSCIndicator = $true

# Import the public global modules
Import-Module -FullyQualifiedName (Get-ChildItem -File -LiteralPath "$ModuleRootPath\Public" -Filter '*.psm1').FullName -Force -Global

# Import the classes
Import-Module -FullyQualifiedName "$ModuleRootPath\CoreExt\Classes.psm1" -Force

#Region C# code imports

# Defining the WinTrust class from the WDACConfig Namespace if it doesn't already exist
if (-NOT ('WDACConfig.WinTrust' -as [System.Type]) ) {
    Add-Type -Path "$ModuleRootPath\C#\AuthenticodeHashCalc.cs"
}

# Defining the PageHashCalculator class from the WDACConfig Namespace if it doesn't already exist
if (-NOT ('WDACConfig.PageHashCalculator' -as [System.Type]) ) {
    Add-Type -Path "$ModuleRootPath\C#\PageHashCalc.cs"
}

# Import the kernel32.dll functions using P/Invoke if they don't exist
if (-NOT ('WDACConfig.Win32Utils' -as [System.Type]) ) {
    Add-Type -Path "$ModuleRootPath\C#\Kernel32dll.cs"
}

# Defining the Signer class from the WDACConfig Namespace if it doesn't already exist
if (-NOT ('WDACConfig.Signer' -as [System.Type]) ) {
    Add-Type -Path "$ModuleRootPath\C#\Signer.cs"
}

# Add the Crypt32.dll library functions as a type if they don't exist
if (-NOT ('WDACConfig.Crypt32DLL' -as [System.Type]) ) {
    Add-Type -Path "$ModuleRootPath\C#\Crypt32dll.cs"
}

# Defining the CryptoAPI class from the WDACConfig Namespace if it doesn't already exist
if (-NOT ('WDACConfig.CryptoAPI' -as [System.Type]) ) {
    Add-Type -Path "$ModuleRootPath\C#\Crypt32CertCN.cs"
}

if (-NOT ('WDACConfig.PolicyHashObj' -as [System.Type]) ) {
    Add-Type -Path "$ModuleRootPath\C#\PolicyHashObj.cs"
}

if (-NOT ('WDACConfig.SimulationInput' -as [System.Type]) ) {
    Add-Type -Path "$ModuleRootPath\C#\SimulationInput.cs"
}

if (-NOT ('WDACConfig.CertificateHelper' -as [System.Type]) ) {
    Add-Type -Path "$ModuleRootPath\C#\CertificateHelper.cs"
}

#Endregion C# code imports

<#
# Loop through all the relevant files in the module
foreach ($File in (Get-FilesFast -Directory $ModuleRootPath -ExtensionsToFilterBy '.ps1', '.psm1')) {
    # Get the signature of the current file
    [System.Management.Automation.Signature]$Signature = Get-AuthenticodeSignature -FilePath $File
    # Ensure that they are code signed properly and have not been tampered with.
    if (($Signature.SignerCertificate.Thumbprint -eq '1c1c9082551b43eec17c0301bfb2f27031a4d8c8') -and ($Signature.Status -in 'Valid', 'UnknownError')) {
        # If the file is signed properly, then continue to the next file
    }
    else {
        Throw [System.Security.SecurityException] "The module has been tampered with, signature status of the file $($File.FullName) is $($Signature.Status)"
    }
}
#>

<#
The reason behind this:

https://github.com/MicrosoftDocs/WDAC-Toolkit/pull/365
https://github.com/MicrosoftDocs/WDAC-Toolkit/issues/362

Features:

Short-circuits the cmdlet and finishes in 2 seconds.
put in the preloader script so it only runs once in the runspace.
No output is shown whatsoever (warning, error etc.)
Any subsequent attempts to run New-CiPolicy cmdlet will work normally without any errors or warnings.
The path I chose exists in Windows by default, and it contains very few PEs, something that is required for that error to be produced.
Test-Path is used for more resiliency.
-PathToCatroot is used and set to the same path as -ScanPath, this combination causes the operation to gracefully end prematurely.
The XML file is never created.
XML file is created but then immediately deleted. Its file name is random to minimize name collisions.
#>

if (Test-Path -LiteralPath 'C:\Program Files\Windows Defender\Offline' -PathType Container) {
    [System.String]$RandomGUID = [System.Guid]::NewGuid().ToString()
    New-CIPolicy -UserPEs -ScanPath 'C:\Program Files\Windows Defender\Offline' -Level hash -FilePath ".\$RandomGUID.xml" -NoShadowCopy -PathToCatroot 'C:\Program Files\Windows Defender\Offline' -WarningAction SilentlyContinue
    Remove-Item -LiteralPath ".\$RandomGUID.xml" -Force
}


# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBs+s+MhJCPIoXj
# hWFd9YeUkfI6MAsELSSIA5GODJG6cqCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgQbHB6/51JMeRGGTIj39CJC8YUDI56PNcd6tYx9n/TcAwDQYJKoZIhvcNAQEB
# BQAEggIAl7Kk3uKo+8a0zSEisQPKkO5OGg5I6R3TL+iz01k6h8vTwuX/o4rdB/Ia
# hKazvTnCrxFyLuhgVEqmmHJFwb+xvuXnwhanu/etcDKQDBAxkeGSAaQ/WZrCMiNK
# 25/Fqrpw6Xp7JCh791fH9lgKeCdNs0TOLjdipYBlLzIkJ3dWHMndvbRw92IGi/sE
# bjQXCGRWSl19qxftU2OmCkjW3Sag/bKdfXaQaPWXW6xVjik0MLCRzy5HiDTB3mnb
# z9noV7qzL3bQ43Tg97kY0tOddw4H+YTsp/BZAgd+pyXsXUaCU2yijU1NeQXrW9ox
# BK5OTb4kJJiiXVpyqIlnWHKErpbj9ww9eFCLvGZ0TjeDrhLBLaNjjHFhqF/209k8
# g5Naf50JZEXLLK/RqRMMeqz1niHTusvP3h76hrDlmrgslrnTaj+OIXSsG8hRMzK3
# XbMLRw7B6dt/r94DicwsMxCLxfEWonVBvyxRIjYXx7axiv/5laoO1omSp8DB8IR3
# 0OC0RV1Od2a3cWFNQNTQCl3VVEIAzAZNCTHIA9/rn9/3czk/0E7Yx7EmVEe7Bo3O
# d1epawFsEAI4fDj4tGLEbGwdF5blIbwsNtkBm6wNyKugLudXQAt4eO6bttll/rYK
# mYlKlWw80erD2IAtCa2s4zLxJ4ZA7jsWkZMky1Dvoh4UeyoAbME=
# SIG # End signature block
