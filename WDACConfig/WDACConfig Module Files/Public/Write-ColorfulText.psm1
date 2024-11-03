Function Write-ColorfulTextWDACConfig {
    <#
    .SYNOPSIS
        Function to write modern colorful text
    #>
    [CmdletBinding()]
    [Alias('WCT')]
    param (
        [Parameter(Mandatory = $True)][Alias('C')]
        [ValidateSet('Fuchsia', 'Orange', 'NeonGreen', 'MintGreen', 'PinkBoldBlink', 'PinkBold', 'Rainbow' , 'Gold', 'TeaGreen', 'Lavender', 'PinkNoNewLine', 'VioletNoNewLine', 'Violet', 'Pink', 'HotPink')]
        [System.String]$Color,

        [parameter(Mandatory = $True)][Alias('I')][System.String]$InputText
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