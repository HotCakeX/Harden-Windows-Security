# Specifies that the WDACConfig module requires Administrator privileges
#Requires -RunAsAdministrator

# Create tamper resistant global variables (if they don't already exist) for Microsoft block rules URLs
try {
    if ((Test-Path -Path 'Variable:\MSFTRecommendeBlockRulesURL') -eq $false) { New-Variable -Name 'MSFTRecommendeBlockRulesURL' -Value 'https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac.md' -Option 'Constant' -Scope 'Global' }
    if ((Test-Path -Path 'Variable:\MSFTRecommendeDriverBlockRulesURL') -eq $false) { New-Variable -Name 'MSFTRecommendeDriverBlockRulesURL' -Value 'https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md' -Option 'Constant' -Scope 'Global' }
}
catch {
    Throw 'Could not set the required global variables.'
}
