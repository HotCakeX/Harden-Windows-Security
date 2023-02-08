if ( Get-Module -ListAvailable "VirusTotalAnalyzer") {
    Import-Module VirusTotalAnalyzer -Force
} else {
    Install-Module -Name VirusTotalAnalyzer -AllowClobber -Force -Scope CurrentUser
    Import-Module VirusTotalAnalyzer -Force
}
$VTApi = ${{ secrets.VTAPI }}

# Submit
$Output = New-VirusScan -ApiKey $VTApi -File "FILE_HERE"
$Output | Format-List

# Wait
Do {
    $OutputScan = Get-VirusReport -ApiKey $VTApi -AnalysisId $Output.data.id
    if ($OutputScan.data.attributes.status -eq 'queued') {
        Write-Host "Waiting..." -ForegroundColor Gray
        Start-Sleep 10
    }
}
until($OutputScan.data.attributes.status -eq 'completed')

# Result
Write-Host "Analyze completed" -ForegroundColor DarkMagenta
if ($OutputScan.data.attributes.stats.suspicious -gt 0 -or $OutputScan.data.attributes.stats.malicious -gt 0) {
    Write-Host ("sha256: {0}`nUndetected: {1}`nSuspicious: {2}`nMalicious: {3}`nURL: {4}" -f `
            $OutputScan.meta.file_info.sha256, `
            $OutputScan.data.attributes.stats.undetected, `
            $OutputScan.data.attributes.stats.suspicious, `
            $OutputScan.data.attributes.stats.malicious,
        "https://www.virustotal.com/gui/file/$($OutputScan.meta.file_info.sha256)"
    ) -ForegroundColor Red
    Exit 1
} else {
    Write-Host ("sha256: {0}`nUndetected: {1}`nSuspicious: {2}`nMalicious: {3}`nURL: {4}" -f `
            $OutputScan.meta.file_info.sha256, `
            $OutputScan.data.attributes.stats.undetected, `
            $OutputScan.data.attributes.stats.suspicious, `
            $OutputScan.data.attributes.stats.malicious,
        "https://www.virustotal.com/gui/file/$($OutputScan.meta.file_info.sha256)"
    ) -ForegroundColor Green
    Exit 0
}
