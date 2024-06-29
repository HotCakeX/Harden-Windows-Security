Function Write-ColorfulText {
    <#
    .SYNOPSIS
        Function to write modern colorful text
    .PARAMETER Color
        Color of the text to be written using custom RGB values
    .PARAMETER InputText
        Text to be written
    .INPUTS
        System.String
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    [Alias('WCT')]

    param (
        [Parameter(Mandatory = $True)]
        [Alias('C')]
        [ValidateSet('Fuchsia', 'Orange', 'NeonGreen', 'MintGreen', 'PinkBoldBlink', 'PinkBold', 'Rainbow' , 'Gold', 'TeaGreen', 'Lavender', 'PinkNoNewLine', 'VioletNoNewLine', 'Violet', 'Pink', 'HotPink')]
        [System.String]$Color,

        [parameter(Mandatory = $True)]
        [Alias('I')]
        [System.String]$InputText
    )

    switch ($Color) {
        'Fuchsia' { Write-Host "$($PSStyle.Foreground.FromRGB(236,68,155))$InputText$($PSStyle.Reset)"; break }
        'Orange' { Write-Host "$($PSStyle.Foreground.FromRGB(255,165,0))$InputText$($PSStyle.Reset)"; break }
        'NeonGreen' { Write-Host "$($PSStyle.Foreground.FromRGB(153,244,67))$InputText$($PSStyle.Reset)"; break }
        'MintGreen' { Write-Host "$($PSStyle.Foreground.FromRGB(152,255,152))$InputText$($PSStyle.Reset)"; break }
        'PinkBoldBlink' { Write-Host "$($PSStyle.Foreground.FromRgb(255,192,203))$($PSStyle.Bold)$($PSStyle.Blink)$InputText$($PSStyle.Reset)"; break }
        'PinkBold' { Write-Host "$($PSStyle.Foreground.FromRgb(255,192,203))$($PSStyle.Bold)$($PSStyle.Reverse)$InputText$($PSStyle.Reset)"; break }
        'Gold' { Write-Host "$($PSStyle.Foreground.FromRgb(255,215,0))$InputText$($PSStyle.Reset)"; break }
        'VioletNoNewLine' { Write-Host "$($PSStyle.Foreground.FromRGB(153,0,255))$InputText$($PSStyle.Reset)" -NoNewline; break }
        'PinkNoNewLine' { Write-Host "$($PSStyle.Foreground.FromRGB(255,0,230))$InputText$($PSStyle.Reset)" -NoNewline; break }
        'Violet' { Write-Host "$($PSStyle.Foreground.FromRGB(153,0,255))$InputText$($PSStyle.Reset)"; break }
        'Pink' { Write-Host "$($PSStyle.Foreground.FromRGB(255,0,230))$InputText$($PSStyle.Reset)"; break }
        'Lavender' { Write-Host "$($PSStyle.Foreground.FromRgb(255,179,255))$InputText$($PSStyle.Reset)"; break }
        'TeaGreen' { Write-Host "$($PSStyle.Foreground.FromRgb(133, 222, 119))$InputText$($PSStyle.Reset)"; break }
        'HotPink' { Write-Host "$($PSStyle.Foreground.FromRGB(255,105,180))$InputText$($PSStyle.Reset)"; break }
        'Rainbow' {
            [System.Drawing.Color[]]$Colors = @(
                [System.Drawing.Color]::Pink,
                [System.Drawing.Color]::HotPink,
                [System.Drawing.Color]::SkyBlue,
                [System.Drawing.Color]::HotPink,
                [System.Drawing.Color]::SkyBlue,
                [System.Drawing.Color]::LightSkyBlue,
                [System.Drawing.Color]::LightGreen,
                [System.Drawing.Color]::Coral,
                [System.Drawing.Color]::Plum,
                [System.Drawing.Color]::Gold
            )

            $StringBuilder = New-Object -TypeName System.Text.StringBuilder
            for ($I = 0; $I -lt $InputText.Length; $I++) {
                $CurrentColor = $Colors[$I % $Colors.Length]
                [System.Void]$StringBuilder.Append("$($PSStyle.Foreground.FromRGB($CurrentColor.R, $CurrentColor.G, $CurrentColor.B))$($PSStyle.Blink)$($InputText[$I])$($PSStyle.BlinkOff)$($PSStyle.Reset)")
            }
            Write-Output -InputObject $StringBuilder.ToString()
            break
        }

        Default { Throw 'Unspecified Color' }
    }
}
Export-ModuleMember -Function 'Write-ColorfulText'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCTd+6SSNHHgF0k
# ZPRhzeXI82bFZ4twb5VypU2av8jja6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgBZHkLx7KNUBSfRGuqLQ6rH56CobeEE89kSFS9z6pu/UwDQYJKoZIhvcNAQEB
# BQAEggIAFwRWqyVXxWsErH1aem0jc07GNIfwED78hR92CZa5OBgPKc6XlO6iVpRF
# XHz2vDIabdr3IlHPw/D6CDUe8Kufd0Jth+Tv/IQ4LKY/9IEkWOvjOnEv5gNKE3w6
# 5n+5AUORIK8HM2mlWrwZG1NpYyLu6+WP3IoGGq7xbV39cd3Op8gj7WmkIW6Oz+sZ
# mPRay06/bz3FQrLpseqmQ4hXNdqf428PXoBGjXXXXJU4RQt5WXjaepkxDPeohzdr
# SNwV4xi4oXHx+8iZiiRMdImnzp6cNjb7TIJXiVjrVcpSIytLdOf5kQbg7zMIahjq
# z5CiH6jP+/ooJZVTbflyOzjb71VFOULGvDVG8l/q/AAM6OH34HMFgvzU2X60uhIs
# AAs0+EVTOJJuR52lMj2iLCtcsSpsp+5zpwYXZIv59aIiCTKQR6vCoqx/MwAugH73
# sVHr7iATyrNi2q/u/B3YLRTWtexK43y6Q3ZvOmMe1HHW8tjdGffFokuaVUsZFTdi
# KfAcOroBBJZe8dg9lVJjCpYixDT3Rnj8aDCLP6zBVOWcl3E1eU9KeJxXCPLkjc4Q
# g0NTgmYJrkj7qLYbK1ownurHkYUQ+vjEHSF4yw4Opp8XB2+V2RkmmAnCRIYRlQoH
# eSbmNbJUHeISb+/JpavW4BFfuX0G0Ovsxku1AHvGGmKQmf/QMco=
# SIG # End signature block
