# Function to upload file to VirusTotal
function Upload-FileToVirusTotal {
    param (
        [System.String]$FilePath,
        [System.String]$ApiKey
    )

    # Headers for the VirusTotal API request
    [System.Collections.Hashtable]$Headers = @{}
    $Headers.Add('accept', 'application/json')
    $Headers.Add('x-apikey', $ApiKey)
    $Headers.Add('content-type', 'multipart/form-data')

    # Prepare the file for upload
    [System.Collections.Hashtable]$Form = @{
        file = Get-Item -Path $FilePath
    }

    # Check if file size is greater than 20MB (20 * 1024 * 1024 bytes)
    if ($FileItem.Length -gt (20 * 1024 * 1024)) {
        Write-Host 'File is larger than 20MB. Using big file upload URL.' -ForegroundColor Cyan

        # https://docs.virustotal.com/reference/files-upload-url

        [System.Collections.Hashtable]$BigFileUploadHeaders = @{}
        $BigFileUploadHeaders.Add('accept', 'application/json')
        $BigFileUploadHeaders.Add('x-apikey', $ApiKey)
        $BigFileUploadResponse = Invoke-WebRequest -Uri 'https://www.virustotal.com/api/v3/files/upload_url' -Method GET -Headers $BigFileUploadHeaders

        $BigFileUploadResponseJSON = $BigFileUploadResponse.Content | ConvertFrom-Json
        [System.String]$UploadUrl = $BigFileUploadResponseJSON.data
    }
    else {
        [System.String]$UploadUrl = 'https://www.virustotal.com/api/v3/files'
    }

    # Upload the file to VirusTotal
    try {

        Write-Host "Uploading file to VirusTotal: $FilePath" -ForegroundColor Yellow
        $Response = Invoke-WebRequest -Uri $UploadUrl -Method Post -Headers $Headers -Form $Form
        $Json = $Response.Content | ConvertFrom-Json

        # Return the analysis ID and URL
        return [PSCustomObject]@{
            ID  = $Json.data.id
            URL = $Json.data.links.self
        }
        Write-Host 'Upload completed.' -ForegroundColor Yellow
    }
    catch {
        Write-Host "Error uploading file: $_" -ForegroundColor Red
        exit 1
    }
}

# Function to get the VirusTotal scan report
function Get-VirusTotalReport {
    param (
        [System.String]$FilePath,
        [System.String]$ApiKey
    )

    # Set headers for the report request
    [System.Collections.Hashtable]$Headers = @{}
    $Headers.Add('accept', 'application/json')
    $Headers.Add('x-apikey', $ApiKey)

    # Upload the file to virus total
    $AnalysisData = Upload-FileToVirusTotal -filePath $FilePath -apiKey $ApiKey

    # Fetch the report from VirusTotal
    do {
        $Response = Invoke-WebRequest -Uri $AnalysisData.URL -Method Get -Headers $Headers
        $JsonResponse = $Response.Content | ConvertFrom-Json

        if ($JsonResponse.data.attributes.status -eq 'queued') {
            Write-Host "Waiting 10 more seconds. Status: $($JsonResponse.data.attributes.status)" -ForegroundColor Blue
            Start-Sleep 10
        }
    }
    until ($JsonResponse.data.attributes.status -eq 'completed')

    Write-Host "Status is now: $($JsonResponse.data.attributes.status)" -ForegroundColor Blue

    # Display detailed report
    Write-Host -Object "Results URL: https://www.virustotal.com/gui/file/$($JsonResponse.meta.file_info.sha256)" -ForegroundColor Magenta

    [System.Int32]$Undetected = $JsonResponse.data.attributes.stats.undetected
    [System.Int32]$Suspicious = $JsonResponse.data.attributes.stats.suspicious
    [System.Int32]$Malicious = $JsonResponse.data.attributes.stats.malicious

    Write-Host -Object "Undetected Result: $Undetected" -ForegroundColor Green
    Write-Host -Object "Suspicious Result: $Suspicious" -ForegroundColor Yellow
    Write-Host -Object "Malicious Result: $Malicious" -ForegroundColor Red

    #  $JsonResponse.meta.file_info | Format-List *
    #  $JsonResponse.data.attributes | Format-List *
    #  $JsonResponse.data.attributes.stats | Format-List *
    #  $JsonResponse.data.attributes.status | Format-List *
    #  $JsonResponse.data.attributes.results | Format-List *
    #  $JsonResponse.data.attributes.results.Microsoft | Format-List *
}

# VirusTotal API Key
$VTApi = $env:VTAPIsecret

# Submit the ZIP of the repository to VirusTotal
$RepoZip = '.\repository.zip'

Get-VirusTotalReport -FilePath $RepoZip -ApiKey $VTApi

# Submit each release file in the release_assets folder
$ReleaseFiles = Get-ChildItem -Path './release_assets' -File

foreach ($file in $ReleaseFiles) {
    # Submit each file to VirusTotal
    Get-VirusTotalReport -FilePath $file.FullName -ApiKey $VTApi
}
