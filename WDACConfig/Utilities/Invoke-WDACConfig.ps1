# This file is for launching WDACConfig module in VS Code so that it can attach its debugger to the process

# Get the current folder of this script file
[System.String]$ScriptFilePath = ($MyInvocation.MyCommand.path | Split-Path -Parent)

# Import the module into the current scope using the relative path of the module itself
Import-Module -FullyQualifiedName "$ScriptFilePath\..\WDACConfig Module Files\WDACConfig.psd1" -Force

# To cryptographically sign the files - you should comment this section when debugging the module
[System.IO.FileInfo[]]$Files = Get-ChildItem -Recurse -File -Path "$ScriptFilePath\..\WDACConfig Module Files\" -Include '*.ps1', '*.psm1', '*.psd1*'
[System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Thumbprint -eq 'D478B987FC25FB1786CBDF54C409F58A1753319B' }
foreach ($File in $Files) {
    Set-AuthenticodeSignature -FilePath $File -Certificate $Certificate | Format-List -Property *
}

# Replace with any cmdlet of the WDACConfig module that is going to be debugged
Assert-WDACConfigIntegrity -SaveLocally -Verbose
