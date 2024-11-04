Function Write-ColorfulTextWDACConfig {
    param (
        [Parameter(Mandatory = $True)][ValidateSet('MintGreen', 'TeaGreen', 'Lavender', 'Pink', 'HotPink')][System.String]$Color,
        [parameter(Mandatory = $True)][System.String]$InputText
    )
    switch ($Color) {
        'MintGreen' { Write-Host "$($PSStyle.Foreground.FromRGB(152,255,152))$InputText$($PSStyle.Reset)"; break }
        'Pink' { Write-Host "$($PSStyle.Foreground.FromRGB(255,0,230))$InputText$($PSStyle.Reset)"; break }
        'Lavender' { Write-Host "$($PSStyle.Foreground.FromRgb(255,179,255))$InputText$($PSStyle.Reset)"; break }
        'TeaGreen' { Write-Host "$($PSStyle.Foreground.FromRgb(133, 222, 119))$InputText$($PSStyle.Reset)"; break }
        'HotPink' { Write-Host "$($PSStyle.Foreground.FromRGB(255,105,180))$InputText$($PSStyle.Reset)"; break }
        Default { Throw 'Unspecified Color' }
    }
}