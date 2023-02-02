$wc = [System.Net.WebClient]::new()
$pkgurl = 'https://github.com/HotCakeX/Harden-Windows-Security/raw/main/GroupPolicy/Security-Baselines-X.zip'
$FileHashSHA256 = Get-FileHash -Algorithm SHA256 -InputStream ($wc.OpenRead($pkgurl))
$FileHashSHA512 = Get-FileHash -Algorithm SHA512 -InputStream ($wc.OpenRead($pkgurl))

$FileHashSHA256 = $FileHashSHA256.Hash
$FileHashSHA512 = $FileHashSHA512.Hash



$SHA256 = @"

``````
$FileHashSHA256
``````

"@

$readme = Get-Content -raw -path "README.md"
$readme = $readme -replace "(?s)(?<=<!-- SHA-256-Hash:START -->).*(?=<!-- SHA-256-Hash:END -->)", $SHA256
 set-Content -path "README.md" -Value $readme.TrimEnd()






$SHA512 = @"

``````
$FileHashSHA512
``````

"@

$readme = Get-Content -raw -path "README.md"
$readme = $readme -replace "(?s)(?<=<!-- SHA-512-Hash:START -->).*(?=<!-- SHA-512-Hash:END -->)", $SHA512
 set-Content -path "README.md" -Value $readme.TrimEnd()
 




 




<#//////////////////////#>



$SHA256 = @"

``````
$FileHashSHA256
``````

"@





 
$HashVerification = @"

``````PowerShell
`$WebClient = [System.Net.WebClient]::new()
`$PackageURL = 'https://github.com/HotCakeX/Harden-Windows-Security/raw/main/GroupPolicy/Security-Baselines-X.zip'
`$publishedHashSHA256 = `'$FileHashSHA256`'
`$publishedHashSHA512 = `'$FileHashSHA512`'
`$SHA256Hash = Get-FileHash -Algorithm SHA256 -InputStream (`$WebClient.OpenRead(`$PackageURL))
`$SHA512Hash = Get-FileHash -Algorithm SHA512 -InputStream (`$WebClient.OpenRead(`$PackageURL))
`$SHA256Hash.Hash -eq `$publishedHashSHA256 -and `$SHA512Hash.Hash -eq `$publishedHashSHA512
``````

"@





$readme = Get-Content -raw -path "README.md"
$readme = $readme -replace "(?s)(?<=<!-- Hash-Verification:START -->).*(?=<!-- Hash-Verification:END -->)", $HashVerification
 set-Content -path "README.md" -Value $readme.TrimEnd()
