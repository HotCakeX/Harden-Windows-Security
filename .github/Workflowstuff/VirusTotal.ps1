if ( Get-Module -ListAvailable 'VirusTotalAnalyzer') {
    Import-Module VirusTotalAnalyzer -Force
}
else {
    Install-Module -Name VirusTotalAnalyzer -AllowClobber -Force -Scope CurrentUser
    Import-Module VirusTotalAnalyzer -Force
}

$VTApi = $env:VTAPIsecret

# Submit
$Output = New-VirusScan -ApiKey $VTApi -File '.\Harden-Windows-Security Module\Main files\Resources\Security-Baselines-X.zip'

# Wait
Do {
    $OutputScan = Get-VirusReport -ApiKey $VTApi -AnalysisId $Output.data.id
    if ($OutputScan.data.attributes.status -eq 'queued') {
        Write-Host "Waiting... $($OutputScan.data.attributes.status)" -ForegroundColor Gray
        Start-Sleep 10
    }
}
until($OutputScan.data.attributes.status -eq 'completed')

# Result
Write-Host 'Analyze completed' -ForegroundColor DarkMagenta
if ($OutputScan.data.attributes.stats.suspicious -gt 0 -or $OutputScan.data.attributes.stats.malicious -gt 0) {
    Write-Host ("sha256: {0}`nUndetected: {1}`nSuspicious: {2}`nMalicious: {3}`nURL: {4}" -f `
            $OutputScan.meta.file_info.sha256, `
            $OutputScan.data.attributes.stats.undetected, `
            $OutputScan.data.attributes.stats.suspicious, `
            $OutputScan.data.attributes.stats.malicious,
        "https://www.virustotal.com/gui/file/$($OutputScan.meta.file_info.sha256)"
    ) -ForegroundColor Red

}
else {
    Write-Host ("sha256: {0}`nUndetected: {1}`nSuspicious: {2}`nMalicious: {3}`nURL: {4}" -f `
            $OutputScan.meta.file_info.sha256, `
            $OutputScan.data.attributes.stats.undetected, `
            $OutputScan.data.attributes.stats.suspicious, `
            $OutputScan.data.attributes.stats.malicious,
        "https://www.virustotal.com/gui/file/$($OutputScan.meta.file_info.sha256)"
    ) -ForegroundColor Green

}

$SecurityBaselinesXvar = "https://www.virustotal.com/gui/file/$($OutputScan.meta.file_info.sha256)"

# Submit
$Output = New-VirusScan -ApiKey $VTApi -File '.\Harden-Windows-Security Module\Main files\Resources\EventViewerCustomViews.zip'

# Wait
Do {
    $OutputScan = Get-VirusReport -ApiKey $VTApi -AnalysisId $Output.data.id
    if ($OutputScan.data.attributes.status -eq 'queued') {
        Write-Host "Waiting... $($OutputScan.data.attributes.status)" -ForegroundColor Gray
        Start-Sleep 10
    }
}
until($OutputScan.data.attributes.status -eq 'completed')

# Result
Write-Host 'Analyze completed' -ForegroundColor DarkMagenta
if ($OutputScan.data.attributes.stats.suspicious -gt 0 -or $OutputScan.data.attributes.stats.malicious -gt 0) {
    Write-Host ("sha256: {0}`nUndetected: {1}`nSuspicious: {2}`nMalicious: {3}`nURL: {4}" -f `
            $OutputScan.meta.file_info.sha256, `
            $OutputScan.data.attributes.stats.undetected, `
            $OutputScan.data.attributes.stats.suspicious, `
            $OutputScan.data.attributes.stats.malicious,
        "https://www.virustotal.com/gui/file/$($OutputScan.meta.file_info.sha256)"
    ) -ForegroundColor Red
}
else {
    Write-Host ("sha256: {0}`nUndetected: {1}`nSuspicious: {2}`nMalicious: {3}`nURL: {4}" -f `
            $OutputScan.meta.file_info.sha256, `
            $OutputScan.data.attributes.stats.undetected, `
            $OutputScan.data.attributes.stats.suspicious, `
            $OutputScan.data.attributes.stats.malicious,
        "https://www.virustotal.com/gui/file/$($OutputScan.meta.file_info.sha256)"
    ) -ForegroundColor Green
}

$EventViewerCustomViewsvar = "https://www.virustotal.com/gui/file/$($OutputScan.meta.file_info.sha256)"

$SecurityBaselinesXVT = "<a href='$SecurityBaselinesXvar'>Virus Total scan results of Security-Baselines-X.zip</a>"
$EventViewerCustomViewsVT = "<a href='$($EventViewerCustomViewsvar)'>Virus Total scan results of EventViewerCustomViews.zip</a>"
$readme = Get-Content -Raw -Path 'README.md'
$readme = $readme -replace '(?s)(?<=<!-- Security-Baselines-X-VT:START -->).*(?=<!-- Security-Baselines-X-VT:END -->)', $SecurityBaselinesXVT
$readme = $readme -replace '(?s)(?<=<!-- EventViewer-CustomViews-VT:START -->).*(?=<!-- EventViewer-CustomViews-VT:END -->)', $EventViewerCustomViewsVT
Set-Content -Path 'README.md' -Value $readme.TrimEnd() -Force

# Committing the changes back to the repository
git config --global user.email 'spynetgirl@outlook.com'
git config --global user.name 'HotCakeX'
git add 'README.md'
git commit -m 'Updating VT Scan Results'
git push
