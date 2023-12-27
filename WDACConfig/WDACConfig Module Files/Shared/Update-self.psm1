Function Update-self {
    <#
    .SYNOPSIS
        Make sure the latest version of the module is installed and if not, automatically update it, clean up any old versions
    .PARAMETER InvocationStatement
        The command that was used to invoke the main function/cmdlet that invoked the Update-self function, this is used to re-run the command after the module has been updated.
        It checks to make sure the Update-self function was called by an authorized command, that is one of the main cmdlets of the WDACConfig module, otherwise it will throw an error.
        The parameter also shouldn't contain any backtick or semicolon characters used to chain commands together.
    .NOTES
        Even if the main cmdlets of the module are called with semicolons like this: Get-Date;New-WDACConfig -GetDriverBlockRules -Verbose -Deploy;Get-Host
        Since the Update-self function only receives the invocation statement from the main cmdlet/function, anything before or after the semicolons are automatically dropped and will not run after the module is auto updated.
        So from the example above, only this part gets executed after auto update: New-WDACConfig -GetDriverBlockRules -Verbose -Deploy
        The ValidatePattern attribute is just an extra layer of security.
    .INPUTS
        System.String
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [ValidatePattern('^(Confirm-WDACConfig|Deploy-SignedWDACConfig|Edit-SignedWDACConfig|Edit-WDACConfig|Invoke-WDACSimulation|New-DenyWDACConfig|New-KernelModeWDACConfig|New-SupplementalWDACConfig|New-WDACConfig|Remove-WDACConfig|Assert-WDACConfigIntegrity)(?!.*[;`]).*$', ErrorMessage = 'Either Update-self function was called with an unauthorized command or it contains semicolon and/or backtick')]
        [System.String]$InvocationStatement
    )
    # Importing the $PSDefaultParameterValues to the current session, prior to everything else
    . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

    try {
        # Get the last update check time
        Write-Verbose -Message 'Getting the last update check time'
        [System.DateTime]$UserConfigDate = Get-CommonWDACConfig -LastUpdateCheck
    }
    catch {
        # If the User Config file doesn't exist then set this flag to perform online update check
        Write-Verbose -Message 'No LastUpdateCheck was found in the user configurations, will perform online update check'
        [System.Boolean]$PerformOnlineUpdateCheck = $true
    }

    # Ensure these are run only if the User Config file exists and contains a date for last update check
    if (!$PerformOnlineUpdateCheck) {
        # Get the current time
        [System.DateTime]$CurrentDateTime = Get-Date
        # Calculate the minutes elapsed since the last online update check
        [System.Int64]$TimeDiff = ($CurrentDateTime - $UserConfigDate).TotalMinutes
    }

    # Only check for updates if the last attempt occurred more than 10 minutes ago or the User Config file for last update check doesn't exist
    # This prevents the module from constantly doing an update check by fetching the version file from GitHub
    if (($TimeDiff -gt 10) -or $PerformOnlineUpdateCheck) {

        Write-Verbose -Message 'Performing online update check'

        [System.Version]$CurrentVersion = (Test-ModuleManifest -Path "$ModuleRootPath\WDACConfig.psd1").Version.ToString()
        try {
            # First try the GitHub source
            [System.Version]$LatestVersion = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/WDACConfig/version.txt' -ProgressAction SilentlyContinue
        }
        catch {
            try {
                # If GitHub source is unavailable, use the Azure DevOps source
                [System.Version]$LatestVersion = Invoke-RestMethod -Uri 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/WDACConfig/version.txt' -ProgressAction SilentlyContinue
            }
            catch {
                Throw [System.Security.VerificationException] 'Could not verify if the latest version of the module is installed, please check your Internet connection. You can optionally bypass the online check by using -SkipVersionCheck parameter.'
            }
        }

        # Reset the last update timer to the current time
        Write-Verbose -Message 'Resetting the last update timer to the current time'
        Set-CommonWDACConfig -LastUpdateCheck $(Get-Date) | Out-Null

        if ($CurrentVersion -lt $LatestVersion) {

            Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(255,0,230))The currently installed module's version is $CurrentVersion while the latest version is $LatestVersion - Auto Updating the module... 💓$($PSStyle.Reset)"

            # Remove the old module version from the current session
            Remove-Module -Name 'WDACConfig' -Force

            # Do this if the module was installed properly using Install-module cmdlet
            try {
                Uninstall-Module -Name 'WDACConfig' -AllVersions -Force -ErrorAction Stop
                Install-Module -Name 'WDACConfig' -RequiredVersion $LatestVersion -Force
                # Will not import the new module version in the current session because of the constant variables. New version is automatically imported when the main cmdlet is run in a new session.
            }
            # Do this if module files/folder was just copied to Documents folder and not properly installed - Should rarely happen
            catch {
                Install-Module -Name 'WDACConfig' -RequiredVersion $LatestVersion -Force
                # Will not import the new module version in the current session because of the constant variables. New version is automatically imported when the main cmdlet is run in a new session.
            }
            # Make sure the old version isn't run after update
            Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(152,255,152))Update has been successful, running your command now$($PSStyle.Reset)"

            try {
                # Try to re-run the command that invoked the Update-self function in a new session after the module is updated.
                pwsh.exe -NoLogo -NoExit -command $InvocationStatement
            }
            catch {
                Throw 'Could not relaunch PowerShell after update. Please close and reopen PowerShell to run your command again.'
            }
        }
    }
    else {
        Write-Verbose -Message "Skipping online update check because the last update check was performed $TimeDiff minutes ago"
    }
}

# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'Update-self'

# SIG # Begin signature block
# MIILhgYJKoZIhvcNAQcCoIILdzCCC3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCcqaKt74nz/gtV
# ZbdjO9C89dR1V2FIQzGidMUq4VdAe6CCB88wggfLMIIFs6ADAgECAhNUAAAABzgp
# /t9ITGbLAAAAAAAHMA0GCSqGSIb3DQEBDQUAMEQxEzARBgoJkiaJk/IsZAEZFgNj
# b20xFDASBgoJkiaJk/IsZAEZFgRCaW5nMRcwFQYDVQQDEw5CaW5nLVNFUlZFUi1D
# QTAgFw0yMzEyMjcwODI4MDlaGA8yMTMzMTIyNzA4MzgwOVoweDELMAkGA1UEBhMC
# VUsxFjAUBgNVBAoTDVNweU5ldEdpcmwgQ28xKjAoBgNVBAMTIUhvdENha2VYIENv
# ZGUgU2lnbmluZyBDZXJ0aWZpY2F0ZTElMCMGCSqGSIb3DQEJARYWU3B5bmV0Z2ly
# bEBvdXRsb29rLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANsD
# szHV9Ea21AhOw4a35P1R30HHtmz+DlWKk/a4FvYQivl9dd+f+SZaybl0O96H6YNp
# qLnx7KD9TSEBbB+HxjE39GfWoX2R1VlPaDqkbGMA0XmnUB+/5CsbhktY4gbvJpW5
# LWXk0xUmCSvLMs7eiuBOGNs3zw5xVVNhsES6/aYMCWREI9YPTVbh7En6P4uZOisy
# K2tZtkSe/TXabfr1KtNhELr3DpTNtJBMBLzhz8d6ztJExKebFqpiaNqF7TpTOTRI
# 4P02k6u6lsWMz/rH9mMHdGSyBJ3DEyJGL9QT4jO4BFLHsxHuWTpjxnqxZNjwLTjB
# NEhH+VcKIIy2iWHfWwK2Nwr/3hzDbfqsWrMrXvvCqGpei+aZTxyplbMPpmd5myKo
# qLI58zc7cMi/HuAbbjo1YWxd/J1shHifMfhXfuncjHr7RTGC3BaEzwirQ12t1Z2K
# Zn2AhLnhSElbgZppt+WS4bmzT6L693srDxSMcBpRcu8NyDteLVCmgfBGXDdfAKEZ
# KXPi9liV0b66YQWnBp9/3bYwtYTh5VwjfSVAMfWsrMpIeGmvGUcsnQCqCxCulHKX
# onoYmbyotyOiXObXVgzB2G0k+VjxiFTSb1ENf3GJV1FJbzbch/p/tASY9w2L7kT/
# l+/Nnp4XOuPDYhm/0KWgEH7mUyq4KkP/BG/on7Q5AgMBAAGjggJ+MIICejA8Bgkr
# BgEEAYI3FQcELzAtBiUrBgEEAYI3FQjinCqC5rhWgdmZEIP42AqB4MldgT6G3Kk+
# mJFMAgFkAgEOMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDAM
# BgNVHRMBAf8EAjAAMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYBBQUHAwMwHQYDVR0O
# BBYEFFr7G/HfmP3Om/RStyhaEtEFmSYKMB8GA1UdEQQYMBaBFEhvdGNha2V4QG91
# dGxvb2suY29tMB8GA1UdIwQYMBaAFChQ2b1sdIHklqMDHsFKcUCX6YREMIHIBgNV
# HR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPUJpbmctU0VSVkVSLUNBLENO
# PVNlcnZlcixDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2Vy
# dmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1CaW5nLERDPWNvbT9jZXJ0aWZpY2F0
# ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9u
# UG9pbnQwgb0GCCsGAQUFBwEBBIGwMIGtMIGqBggrBgEFBQcwAoaBnWxkYXA6Ly8v
# Q049QmluZy1TRVJWRVItQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZp
# Y2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9QmluZyxEQz1jb20/
# Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRo
# b3JpdHkwDQYJKoZIhvcNAQENBQADggIBAE/AISQevRj/RFQdRbaA0Ffk3Ywg4Zui
# +OVuCHrswpja/4twBwz4M58aqBSoR/r9GZo69latO74VMmki83TX+Pzso3cG5vPD
# +NLxwAQUo9b81T08ZYYpdWKv7f+9Des4WbBaW9AGmX+jJn+JLAFp+8V+nBkN2rS9
# 47seK4lwtfs+rVMGBxquc786fXBAMRdk/+t8G58MZixX8MRggHhVeGc5ecCRTDhg
# nN68MhJjpwqsu0sY2NeKz5gMSk6wvt+NDPcfSZyNo1uSEMKTl/w5UH7mnrv0D4fZ
# UOY3cpIwbIagwdBuFupKG/m1I2LXZdLgGfOtZyZyw+c5Kd0KlMxonBiVoqN7PvoA
# 7sfwDI7PMLMQ3mseFbIpSUQGXHGeyouN1jF5ciySfHnW1goiG8tfDKNAT7WEz+ZT
# c1iIH+lCDUV/LmFD1Bvj2A9Q01C9BsScH+9vb2CnIwaSmfFRI6PY9cKOEHdy/ULi
# hp72QBd6W6ZQMZWXI5m48DdiKlQGA1aCdNN6+C0of43a7L0rAtLPYKySpd6gc34I
# h7/DgGLqXg0CO4KtbGdEWfKHqvh0qYLRmo/obhyVMYib4ceKrCcdc9aVlng/25nE
# ExvokF0vVXKSZkRUAfNHmmfP3lqbjABHC2slbStolocXwh8CoN8o2iOEMnY/xez0
# gxGYBY5UvhGKMYIDDTCCAwkCAQEwWzBEMRMwEQYKCZImiZPyLGQBGRYDY29tMRQw
# EgYKCZImiZPyLGQBGRYEQmluZzEXMBUGA1UEAxMOQmluZy1TRVJWRVItQ0ECE1QA
# AAAHOCn+30hMZssAAAAAAAcwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIB
# DDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEE
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgPlFaz6AA4HuZ
# dh/xuRPo81PNbNYpgb71NLvTNkDHO94wDQYJKoZIhvcNAQEBBQAEggIAq+gwonLu
# o1LHNpWfh3wCoz+GtNTrug1Y7gHfciWn3EDWqn0ld6jjvSPvQwq8ELztVmVSrWh5
# /exe93nWyB2KC6glve4t1PZgq6mtkrkdZriWHRpFqRLIMEGGOiisiakkUcJgKvGb
# M0Iq6DNsk+Z0Kt1584z3O7cMY3HGR9u4GRzo/UAxho2HTq8vqP43ffVXyiK2zBWB
# 33ApWDXo8T8diCSuNyx1VAuOMjLQIxn0ROJnfYZRRNm4cqxBQTN13W0HLufAZ6MM
# geQVX5ia0cGF5a7O04xSKqRItNgVYcPD0pFtNnuviBkAKzWPHFNXL88wfEveNwRj
# jsKLGHxP20ueNSTtowizUTcTgR1sH1V0iwxaBQdM3YnIlH3UrbJTbi/W0lRMzYCJ
# ghaxBpebL/PCLhBYGxa6IssXhy7uQQV+mKTb8ZDTyRjVNdsFT/dMbLLsp3ah+dFp
# Fd6LyKnkQSPxbgFUu9xZiuPUUrzpWi3C8BdE4uV/PC7GY0mSC7/2w2/nJFhAk7Va
# jzlbJmt1Gm8AlApypU1n76Jt5F87ZfETRTsn3sZM7Sq6OBSjVa5n/WSY50ZtVv3+
# urnUhIdPjA0zydWrXgNQGjQuyIHQcHcOcXOb4QTAD8ygT4lgwONqag0wuRDlEhSs
# pTiQz1DcVrnViKFfoLsHe0l+e7r3kJCHjOM=
# SIG # End signature block
