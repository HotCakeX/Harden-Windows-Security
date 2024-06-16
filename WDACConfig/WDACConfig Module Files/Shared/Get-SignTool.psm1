Function Get-SignTool {
    <#
    .SYNOPSIS
        Gets the path to SignTool.exe and verifies it to make sure it's not tampered
        If the SignTool.exe path is not provided by parameter, it will try to detect it automatically, either by checking if Windows SDK is installed or by reading the user configs (this part actually happens in the main cmdlet that calls Get-SignTool function)
        If the SignTool.exe path is not provided by parameter and it could not be detected automatically, it will ask the user to try to download it from NuGet
    .PARAMETER SignToolExePathInput
        Path to the SignTool.exe
        It's optional
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.IO.FileInfo
    #>
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo])]
    param(
        [parameter(Mandatory = $false)][System.IO.FileInfo]$SignToolExePathInput
    )
    Begin {
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\New-StagingArea.psm1" -Force

        [System.IO.DirectoryInfo]$StagingArea = New-StagingArea -CmdletName 'Get-SignTool'
    }

    Process {

        Try {

            # If Sign tool path wasn't provided by parameter, try to detect it automatically
            if (!$SignToolExePathInput) {

                Write-Verbose -Message 'SignTool.exe path was not provided by parameter, trying to detect it automatically'

                try {
                    if ($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64') {
                        if ( Test-Path -Path 'C:\Program Files (x86)\Windows Kits\*\bin\*\x64\signtool.exe') {
                            $SignToolExePathOutput = 'C:\Program Files (x86)\Windows Kits\*\bin\*\x64\signtool.exe'
                        }
                        else {
                            Throw [System.IO.FileNotFoundException] 'signtool.exe could not be found'
                        }
                    }
                    elseif ($Env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
                        if (Test-Path -Path 'C:\Program Files (x86)\Windows Kits\*\bin\*\arm64\signtool.exe') {
                            $SignToolExePathOutput = 'C:\Program Files (x86)\Windows Kits\*\bin\*\arm64\signtool.exe'
                        }
                        else {
                            Throw [System.IO.FileNotFoundException] 'signtool.exe could not be found'
                        }
                    }
                }
                catch [System.IO.FileNotFoundException] {

                    # If Sign tool path wasn't provided by parameter and couldn't be detected automatically, try to download it from NuGet, if fails or user declines this, stop the operation

                    if ($PSCmdlet.ShouldContinue('Would you like to try to download it from the official Microsoft server? It will be saved in the WDACConfig directory in Program Files.', 'SignTool.exe path was not provided, it could not be automatically detected on the system, nor could it be found in the common WDAC user configurations.')) {

                        if (-NOT (Get-PackageSource | Where-Object -FilterScript { $_.Name -ieq 'nuget.org' })) {
                            Write-Verbose -Message 'Registering the nuget.org package source because it was not found in the system.'
                            $null = Register-PackageSource -Name 'nuget.org' -ProviderName 'NuGet' -Location 'https://api.nuget.org/v3/index.json'
                        }

                        Write-Verbose -Message 'Finding the latest version of the Microsoft.Windows.SDK.BuildTools package from NuGet'

                        # Use a script block to convert the Version property to a semantic version object for proper sorting based on the version number
                        [Microsoft.PackageManagement.Packaging.SoftwareIdentity[]]$Package = Find-Package -Name 'Microsoft.Windows.SDK.BuildTools' -Source 'nuget.org' -AllVersions -Force -MinimumVersion '10.0.22621.3233'

                        [Microsoft.PackageManagement.Packaging.SoftwareIdentity]$Package = $Package | Sort-Object -Property { [System.Version]$_.Version } -Descending | Select-Object -First 1

                        Write-Verbose -Message 'Downloading SignTool.exe from NuGet...'
                        Save-Package -InputObject $Package -Path $StagingArea -Force | Out-Null

                        Write-Verbose -Message 'Extracting the nupkg'
                        Expand-Archive -Path "$StagingArea\*.nupkg" -DestinationPath $StagingArea -Force

                        Write-Verbose -Message 'Detecting the CPU Arch'
                        switch ($Env:PROCESSOR_ARCHITECTURE) {
                            'AMD64' { [System.String]$CPUArch = 'x64' }
                            'ARM64' { [System.String]$CPUArch = 'arm64' }
                            default { Throw [System.PlatformNotSupportedException] 'Only AMD64 and ARM64 architectures are supported.' }
                        }
                        # Defining the final path to return for SignTool.exe
                        [System.IO.FileInfo]$SignToolExePathOutput = Join-Path -Path $UserConfigDir -ChildPath 'SignTool.exe'

                        # Move the SignTool.exe from the temp directory to the User Config directory
                        Move-Item -Path "$StagingArea\bin\*\$CPUArch\signtool.exe" -Destination $SignToolExePathOutput -Force
                    }
                    else {
                        Throw [System.IO.FileNotFoundException] 'signtool.exe could not be found and an attempt to download it was declined.'
                    }
                }
            }
            # If Sign tool path was provided by parameter, use it
            else {
                Write-Verbose -Message 'SignTool.exe path was provided by parameter'
                $SignToolExePathOutput = $SignToolExePathInput
            }

            # Since WDAC Simulation doesn't support path with wildcards and accepts them literally, doing this to make sure the path is valid when automatically detected from Windows SDK installations which is a wildcard path
            [System.IO.FileInfo]$SignToolExePathOutput = (Resolve-Path -Path $SignToolExePathOutput).Path

            # At this point the SignTool.exe path was either provided by user, was found in the user configs, was detected automatically or was downloaded from NuGet
            try {
                # Validate the SignTool executable
                Write-Verbose -Message "Validating the SignTool executable: $SignToolExePathOutput"
                # Setting the minimum version of SignTool that is allowed to be executed
                [System.Version]$WindowsSdkVersion = '10.0.22621.2428'
                [System.Boolean]$GreenFlag1 = (((Get-Item -Path $SignToolExePathOutput).VersionInfo).ProductVersionRaw -ge $WindowsSdkVersion)
                [System.Boolean]$GreenFlag2 = (((Get-Item -Path $SignToolExePathOutput).VersionInfo).FileVersionRaw -ge $WindowsSdkVersion)
                [System.Boolean]$GreenFlag3 = ((Get-Item -Path $SignToolExePathOutput).VersionInfo).CompanyName -eq 'Microsoft Corporation'
                [System.Boolean]$GreenFlag4 = ((Get-AuthenticodeSignature -FilePath $SignToolExePathOutput).Status -eq 'Valid')
                [System.Boolean]$GreenFlag5 = ((Get-AuthenticodeSignature -FilePath $SignToolExePathOutput).StatusMessage -eq 'Signature verified.')
            }
            catch {
                # Display an extra error message to provide more information to the user
                if ($SignToolExePathInput) {
                    Write-Error -Message 'The SignTool.exe path that was provided by parameter or found in user configuration could not be validated.' -ErrorAction Continue
                }
                Throw $_
            }
            # If any of the 5 checks above fails, the operation stops
            if (!$GreenFlag1 -or !$GreenFlag2 -or !$GreenFlag3 -or !$GreenFlag4 -or !$GreenFlag5) {
                Throw [System.Security.VerificationException] 'The SignTool executable was found but could not be verified. Please download the latest Windows SDK to get the newest SignTool executable. Official download link: http://aka.ms/WinSDK'
            }
            else {
                Write-Verbose -Message 'SignTool executable was found and verified successfully.'

                Write-Verbose -Message 'Setting the SignTool path in the common WDAC user configurations'
                Set-CommonWDACConfig -SignToolPath $SignToolExePathOutput | Out-Null

                return $SignToolExePathOutput
            }
        }
        Finally {
            Remove-Item -Path $StagingArea -Recurse -Force
        }
    }
}
Export-ModuleMember -Function 'Get-SignTool'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDpXlXAw7vyUs4s
# QbGk+OWIGCDd1hBfJItO+pMb6wXevqCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgRQwq0H49srX5lfoOHyqTmfrjbHlkfWtIsUGD6+1/SaQwDQYJKoZIhvcNAQEB
# BQAEggIAHlqc55fYzrNj2zD6lHhhSu4idbBo815nyWGz2WknUD/SZhexMqEp/Bps
# +lmD2/kJ06rJW1QazzdePvdeGaj2pBTZQ8+/hPOOP9ElOZWLRI5CGpxnpz7ItPM+
# 9nBwfiwSlMEALyUSQQUsCybCwl7GnOffznqdHuwt+Y0uYgChHJD1fdexPKgViTf9
# w5RGccV6ufFCO168nG1oykMKFoINjMvFqNG1U3l5Q87RPN9PtDgMR+C5I8xnDjny
# c3pZ5z2cFadFfbV/bXqfQTWHDGjRBeHJ86ji/grzipr51OVEICb645QQrLFN8occ
# IWL9X5fDl/Slsg7wE6Sy2oOJOKikwAAu/fjQZq4YDbbqIVBTE9wV496Ihcq0ma+Y
# 9M+F1FEudRYhvGw9R3r2aB5RKlDY2cO071q3OhbSW4bmDfjDKyx/ko4Ow/ziF5Ch
# zzr8RTHBkvjh3U1qVCvFtuA/dpHFdyX2YyhUXWa1Jncgmifz/i9FvmmFau4rytnz
# tfePWcZU95jeEwtjr/rykDcLxcF9JrxXVTFaRcapibYcNh8w1OiRn0N3iFK/NKbp
# D4wkxzVv2bLNzogNe5iKSYx3eHMI2EzKCurqnuAWGBvlDWEGQfqdvCedZl5w8JFq
# oUc+Tf7NtJJhpl83PxSJHnJaKhH4jEC+7Mzoi0z8SvKNQqIUsZI=
# SIG # End signature block
