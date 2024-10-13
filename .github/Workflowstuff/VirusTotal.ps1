# Import the VirusTotalAnalyzer module
if (Get-Module -ListAvailable 'VirusTotalAnalyzer') {
    Import-Module VirusTotalAnalyzer -Force
} else {
    Install-Module -Name VirusTotalAnalyzer -AllowClobber -Force -Scope CurrentUser
    Import-Module VirusTotalAnalyzer -Force
}

# VirusTotal API Key
$VTApi = $env:VTAPIsecret

# Submit the ZIP of the repository to VirusTotal
$repoZip = ".\repository.zip"
$Output = New-VirusScan -ApiKey $VTApi -File $repoZip

# Wait for the result of the repository ZIP scan
Do {
    $OutputScan = Get-VirusReport -ApiKey $VTApi -AnalysisId $Output.data.id
    if ($OutputScan.data.attributes.status -eq 'queued') {
        Write-Host "Waiting... $($OutputScan.data.attributes.status)" -ForegroundColor Gray
        Start-Sleep 10
    }
} until ($OutputScan.data.attributes.status -eq 'completed')

# Print results for the repository ZIP
Write-Host 'Repository ZIP analysis completed' -ForegroundColor DarkMagenta
if ($OutputScan.data.attributes.stats.suspicious -gt 0 -or $OutputScan.data.attributes.stats.malicious -gt 0) {
    Write-Host ("sha256: {0}`nUndetected: {1}`nSuspicious: {2}`nMalicious: {3}`nURL: {4}" -f `
        $OutputScan.meta.file_info.sha256, 
        $OutputScan.data.attributes.stats.undetected,
        $OutputScan.data.attributes.stats.suspicious,
        $OutputScan.data.attributes.stats.malicious,
        "https://www.virustotal.com/gui/file/$($OutputScan.meta.file_info.sha256)"
    ) -ForegroundColor Red
} else {
    Write-Host ("sha256: {0}`nUndetected: {1}`nSuspicious: {2}`nMalicious: {3}`nURL: {4}" -f `
        $OutputScan.meta.file_info.sha256, 
        $OutputScan.data.attributes.stats.undetected,
        $OutputScan.data.attributes.stats.suspicious,
        $OutputScan.data.attributes.stats.malicious,
        "https://www.virustotal.com/gui/file/$($OutputScan.meta.file_info.sha256)"
    ) -ForegroundColor Green
}

# Submit each release file in the release_assets folder
$releaseFiles = Get-ChildItem -Path './release_assets' -File

foreach ($file in $releaseFiles) {
    # Submit each file to VirusTotal
    $Output = New-VirusScan -ApiKey $VTApi -File $file.FullName

    # Wait for the result of each file scan
    Do {
        $OutputScan = Get-VirusReport -ApiKey $VTApi -AnalysisId $Output.data.id
        if ($OutputScan.data.attributes.status -eq 'queued') {
            Write-Host "Waiting... $($OutputScan.data.attributes.status)" -ForegroundColor Gray
            Start-Sleep 10
        }
    } until ($OutputScan.data.attributes.status -eq 'completed')

    # Print results for each release file
    Write-Host 'Analyze completed' -ForegroundColor DarkMagenta
    if ($OutputScan.data.attributes.stats.suspicious -gt 0 -or $OutputScan.data.attributes.stats.malicious -gt 0) {
        Write-Host ("File: {0}`nsha256: {1}`nUndetected: {2}`nSuspicious: {3}`nMalicious: {4}`nURL: {5}" -f `
            $file.Name,
            $OutputScan.meta.file_info.sha256, 
            $OutputScan.data.attributes.stats.undetected,
            $OutputScan.data.attributes.stats.suspicious,
            $OutputScan.data.attributes.stats.malicious,
            "https://www.virustotal.com/gui/file/$($OutputScan.meta.file_info.sha256)"
        ) -ForegroundColor Red
    } else {
        Write-Host ("File: {0}`nsha256: {1}`nUndetected: {2}`nSuspicious: {3}`nMalicious: {4}`nURL: {5}" -f `
            $file.Name,
            $OutputScan.meta.file_info.sha256, 
            $OutputScan.data.attributes.stats.undetected,
            $OutputScan.data.attributes.stats.suspicious,
            $OutputScan.data.attributes.stats.malicious,
            "https://www.virustotal.com/gui/file/$($OutputScan.meta.file_info.sha256)"
        ) -ForegroundColor Green
    }
}
