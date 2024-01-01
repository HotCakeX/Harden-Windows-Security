# This file is for launching WDACConfig module in VS Code so that it can attach its debugger to the process

# Get the current folder of this script file
[System.String]$ScriptFilePath = ($MyInvocation.MyCommand.path | Split-Path -Parent)

# Import the module into the current scope using the relative path of the module itself
Import-Module -FullyQualifiedName "$ScriptFilePath\..\WDACConfig Module Files\WDACConfig.psd1" -Force

# This section is for cryptographically signing the files - you should keep it as is when debugging the module
<#

[System.IO.FileInfo[]]$Files = Get-ChildItem -Recurse -File -Path "$ScriptFilePath\..\WDACConfig Module Files\" -Include '*.ps1', '*.psm1'
[System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert | Where-Object -FilterScript { $_.Thumbprint -eq '1c1c9082551b43eec17c0301bfb2f27031a4d8c8' }
foreach ($File in $Files) {
    Set-AuthenticodeSignature -FilePath $File -Certificate $Certificate | Format-List -Property *
}

#>

# Replace with any cmdlet of the WDACConfig module that is going to be debugged
# Assert-WDACConfigIntegrity -SaveLocally -Verbose
