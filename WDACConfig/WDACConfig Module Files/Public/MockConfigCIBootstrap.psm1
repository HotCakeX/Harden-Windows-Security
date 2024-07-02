Function Invoke-MockConfigCIBootstrap {
    <#
The reason behind this:

https://github.com/MicrosoftDocs/WDAC-Toolkit/pull/365
https://github.com/MicrosoftDocs/WDAC-Toolkit/issues/362

Features:

Short-circuits the cmdlet and finishes in 2 seconds.
put in the preloader script so it only runs once in the runspace.
No output is shown whatsoever (warning, error etc.)
Any subsequent attempts to run New-CiPolicy cmdlet will work normally without any errors or warnings.
The path I chose exists in Windows by default, and it contains very few PEs, something that is required for that error to be produced.
-PathToCatroot is used and set to the same path as -ScanPath, this combination causes the operation to gracefully end prematurely.
The XML file is never created.
XML file is created but then immediately deleted. Its file name is random to minimize name collisions.
#>
    if ([System.IO.Directory]::Exists('C:\Program Files\Windows Defender\Offline')) {
        [System.String]$RandomGUID = [System.Guid]::NewGuid().ToString()
        New-CIPolicy -UserPEs -ScanPath 'C:\Program Files\Windows Defender\Offline' -Level hash -FilePath ".\$RandomGUID.xml" -NoShadowCopy -PathToCatroot 'C:\Program Files\Windows Defender\Offline' -WarningAction SilentlyContinue
        Remove-Item -LiteralPath ".\$RandomGUID.xml" -Force
    }
}