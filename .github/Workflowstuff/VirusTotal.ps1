$ErrorActionPreference = 'Stop'

# Function to upload file to VirusTotal
function Upload-FileToVirusTotal {
    param (
        [System.String]$FilePath,
        [System.String]$ApiKey
    )

    [System.IO.FileInfo]$FileToUpload = Get-Item -Path $FilePath

    # Check if file size is greater than 20MB (20 * 1024 * 1024 bytes)
    if ($FileToUpload.Length -gt (20 * 1024 * 1024)) {
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

        # cURL handles multipart uploads nicely
        $Response = curl --request POST `
            --url $UploadUrl `
            --header 'accept: application/json' `
            --header 'content-type: multipart/form-data' `
            --header "x-apikey: $ApiKey" `
            --form file="@$FilePath"

        $Json = $Response | ConvertFrom-Json

        Write-Host 'Upload completed.' -ForegroundColor Yellow

        # Return the analysis ID and URL
        return [PSCustomObject]@{
            ID  = $Json.data.id
            URL = $Json.data.links.self
        }
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
        [System.String]$ApiKey,
        [System.String]$Comments
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
            Write-Host "Status: $($JsonResponse.data.attributes.status). Waiting 10 more seconds..." -ForegroundColor Blue
            Start-Sleep -Seconds 10
        }
    }
    until ($JsonResponse.data.attributes.status -eq 'completed')

    Write-Host "Status is now: $($JsonResponse.data.attributes.status)" -ForegroundColor Blue

    [System.String]$FileURLOnVirusTotal = "https://www.virustotal.com/gui/file/$($JsonResponse.meta.file_info.sha256)"

    # Display detailed report
    Write-Host -Object "Results URL: $FileURLOnVirusTotal" -ForegroundColor Magenta

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


    # If comments or votes exist, we see error which can be safely ignored
    try {
        # Add comment to the file
        [System.String]$CommentsSubmitURL = "https://www.virustotal.com/api/v3/files/$($JsonResponse.meta.file_info.sha256)/comments"
        [System.Collections.Hashtable]$CommentsSubmitHeaders = @{}
        $CommentsSubmitHeaders.Add('accept', 'application/json')
        $CommentsSubmitHeaders.Add('x-apikey', $ApiKey)
        $CommentsSubmitHeaders.Add('content-type', 'application/json')
        $CommentsSubmitResponse = Invoke-WebRequest -Uri $CommentsSubmitURL -Method POST -Headers $CommentsSubmitHeaders -ContentType 'application/json' -Body "{`"data`":{`"type`":`"comment`",`"attributes`":{`"text`":`"$Comments`"}}}"
        if ($CommentsSubmitResponse.StatusCode -ne '200') {
            Write-Host "Error submitting comment. Status Code: $($CommentsSubmitResponse.StatusCode)`n Error: $($CommentsSubmitResponse.Content)" -ForegroundColor Red
        }
    }

    catch {
        Write-Host "Error submitting comment: $_" -ForegroundColor Red
    }


    try {

        # Add 'harmless' verdict/vote to the file
        [System.String]$VoteURL = "https://www.virustotal.com/api/v3/files/$($JsonResponse.meta.file_info.sha256)/votes"
        [System.Collections.Hashtable]$VoteHeaders = @{}
        $VoteHeaders.Add('accept', 'application/json')
        $VoteHeaders.Add('x-apikey', $ApiKey)
        $VoteHeaders.Add('content-type', 'application/json')
        $VoteResponse = Invoke-WebRequest -Uri $VoteURL -Method POST -Headers $VoteHeaders -ContentType 'application/json' -Body '{"data":{"type":"vote","attributes":{"verdict":"harmless"}}}'
        if ($VoteResponse.StatusCode -ne '200') {
            Write-Host "Error submitting vote. Status Code: $($VoteResponse.StatusCode)`n Error: $($VoteResponse.Content)" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Error submitting vote: $_" -ForegroundColor Red
    }
}

# VirusTotal API Key
$VTApi = $env:VTAPIsecret

# Submit the ZIP of the repository to VirusTotal
$RepoZip = '.\Harden-Windows-Security-Repository.zip'

Get-VirusTotalReport -FilePath $RepoZip -ApiKey $VTApi -Comments "Harden Windows Security GitHub Repository Upload at $(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'). #HotCakeX #Security #Windows #SpyNetGirl"

# Submit each release file in the release_assets folder
$ReleaseFiles = Get-ChildItem -Path '.\release_assets' -File -Force

foreach ($File in $ReleaseFiles) {
    # Submit each file to VirusTotal
    Get-VirusTotalReport -FilePath $File.FullName -ApiKey $VTApi -Comments "Harden Windows Security GitHub Release File Upload named $($File.Name) at $(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'). #HotCakeX #Security #Windows #SpyNetGirl"
}
