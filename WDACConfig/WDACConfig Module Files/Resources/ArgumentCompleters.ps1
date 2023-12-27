<#
# argument tab auto-completion for CertPath param to show only .cer files in current directory and 2 sub-directories recursively
[System.Management.Automation.ScriptBlock]$ArgumentCompleterCertPath = {
    # Note the use of -Depth 1
    # Enclosing the $Results = ... assignment in (...) also passes the value through.
    ($Results = Get-ChildItem -Depth 2 -Filter *.cer | ForEach-Object -Process { "`"$_`"" })
    if (-not $Results) {
        # No results?
        $null # Dummy response that prevents fallback to the default file-name completion.
    }
}
#>

# Importing the $PSDefaultParameterValues to the current session, prior to everything else
. "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

# argument tab auto-completion for Policy Paths to show only .xml files and only suggest files that haven't been already selected by user
# https://stackoverflow.com/questions/76141864/how-to-make-a-powershell-argument-completer-that-only-suggests-files-not-already/76142865
[System.Management.Automation.ScriptBlock]$ArgumentCompleterPolicyPaths = {
    # Get the current command and the already bound parameters
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    # Find all string constants in the AST that end in ".xml"
    $Existing = $commandAst.FindAll({
            $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
            $args[0].Value -like '*.xml'
        },
        $false
    ).Value

    # Get the xml files in the current directory
    Get-ChildItem -File -Filter *.xml | ForEach-Object -Process {
        # Check if the file is already selected
        if ($_.FullName -notin $Existing) {
            # Return the file name with quotes
            "`"$_`""
        }
    }
}

# argument tab auto-completion for Certificate common name
[System.Management.Automation.ScriptBlock]$ArgumentCompleterCertificateCN = {
    # Create an empty array to store the output objects
    [System.String[]]$Output = @()

    # Loop through each certificate that uses RSA algorithm (Because ECDSA is not supported for signing WDAC policies) in the current user's personal store and extract the relevant properties
    foreach ($Cert in (Get-ChildItem -Path 'Cert:\CurrentUser\My' | Where-Object -FilterScript { $_.PublicKey.Oid.FriendlyName -eq 'RSA' })) {

        # Takes care of certificate subjects that include comma in their CN
        # Determine if the subject contains a comma
        if ($Cert.Subject -match 'CN=(?<RegexTest>.*?),.*') {
            # If the CN value contains double quotes, use split to get the value between the quotes
            if ($matches['RegexTest'] -like '*"*') {
                $SubjectCN = ($Element.Certificate.Subject -split 'CN="(.+?)"')[1]
            }
            # Otherwise, use the named group RegexTest to get the CN value
            else {
                $SubjectCN = $matches['RegexTest']
            }
        }
        # If the subject does not contain a comma, use a lookbehind to get the CN value
        elseif ($Cert.Subject -match '(?<=CN=).*') {
            $SubjectCN = $matches[0]
        }

        $Output += $SubjectCN
    }

    $Output | ForEach-Object -Process { return "`"$_`"" }
}

# Argument tab auto-completion for installed Appx package names
[System.Management.Automation.ScriptBlock]$ArgumentCompleterAppxPackageNames = {
    # Get the current command and the already bound parameters
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    # Get the app package names that match the word to complete
    Get-AppxPackage -Name *$wordToComplete* | ForEach-Object -Process {
        "`"$($_.Name)`""
    }
}

# argument tab auto-completion for Base Policy Paths to show only .xml files and only suggest files that haven't been already selected by user
[System.Management.Automation.ScriptBlock]$ArgumentCompleterPolicyPathsBasePoliciesOnly = {
    # Get the current command and the already bound parameters
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    # Find all string constants in the AST that end in ".xml"
    $Existing = $commandAst.FindAll({
            $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
            $args[0].Value -like '*.xml'
        },
        $false
    ).Value

    # Get the xml files in the current directory
    Get-ChildItem -File | Where-Object -FilterScript { $_.extension -like '*.xml' } | ForEach-Object -Process {

        $XmlItem = [System.Xml.XmlDocument](Get-Content -Path $_)
        $PolicyType = $XmlItem.SiPolicy.PolicyType

        if ($PolicyType -eq 'Base Policy') {

            # Check if the file is already selected
            if ($_.FullName -notin $Existing) {
                # Return the file name with quotes
                "`"$_`""
            }
        }
    }
}

# argument tab auto-completion for Supplemental Policy Paths to show only .xml files and only suggest files that haven't been already selected by user
[System.Management.Automation.ScriptBlock]$ArgumentCompleterPolicyPathsSupplementalPoliciesOnly = {
    # Get the current command and the already bound parameters
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    # Find all string constants in the AST that end in ".xml"
    $Existing = $commandAst.FindAll({
            $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
            $args[0].Value -like '*.xml'
        },
        $false
    ).Value

    # Get the xml files in the current directory
    Get-ChildItem -File | Where-Object -FilterScript { $_.extension -like '*.xml' } | ForEach-Object -Process {

        $XmlItem = [System.Xml.XmlDocument](Get-Content -Path $_)
        $PolicyType = $XmlItem.SiPolicy.PolicyType

        if ($PolicyType -eq 'Supplemental Policy') {

            # Check if the file is already selected
            if ($_.FullName -notin $Existing) {
                # Return the file name with quotes
                "`"$_`""
            }
        }
    }
}

# Opens Folder picker GUI so that user can select folders to be processed
[System.Management.Automation.ScriptBlock]$ArgumentCompleterFolderPathsPicker = {
    # Load the System.Windows.Forms assembly
    Add-Type -AssemblyName 'System.Windows.Forms'
    # non-top-most, works better with window focus
    [System.Windows.Forms.FolderBrowserDialog]$Browser = New-Object -TypeName 'System.Windows.Forms.FolderBrowserDialog'
    $null = $Browser.ShowDialog()
    # Add quotes around the selected path
    return "`"$($Browser.SelectedPath)`""
}

# Opens File picker GUI so that user can select an .exe file - for SignTool.exe
[System.Management.Automation.ScriptBlock]$ArgumentCompleterExeFilePathsPicker = {
    # Load the System.Windows.Forms assembly
    Add-Type -AssemblyName 'System.Windows.Forms'
    # Create a new OpenFileDialog object
    [System.Windows.Forms.OpenFileDialog]$Dialog = New-Object -TypeName 'System.Windows.Forms.OpenFileDialog'
    # Set the filter to show only executable files
    $Dialog.Filter = 'Executable files (*.exe)|*.exe'
    # Show the dialog and get the result
    [System.String]$Result = $Dialog.ShowDialog()
    # If the user clicked OK, return the selected file path
    if ($Result -eq 'OK') {
        return "`"$($Dialog.FileName)`""
    }
}

# Opens File picker GUI so that user can select a .cer file
[System.Management.Automation.ScriptBlock]$ArgumentCompleterCerFilePathsPicker = {
    # Load the System.Windows.Forms assembly
    Add-Type -AssemblyName 'System.Windows.Forms'
    # Create a new OpenFileDialog object
    [System.Windows.Forms.OpenFileDialog]$Dialog = New-Object -TypeName 'System.Windows.Forms.OpenFileDialog'
    # Set the filter to show only certificate files
    $Dialog.Filter = 'Certificate files (*.cer)|*.cer'
    # Show the dialog and get the result
    [System.String]$Result = $Dialog.ShowDialog()
    # If the user clicked OK, return the selected file path
    if ($Result -eq 'OK') {
        return "`"$($Dialog.FileName)`""
    }
}

# Opens File picker GUI so that user can select a .xml file
[System.Management.Automation.ScriptBlock]$ArgumentCompleterXmlFilePathsPicker = {
    # Load the System.Windows.Forms assembly
    Add-Type -AssemblyName 'System.Windows.Forms'
    # Create a new OpenFileDialog object
    [System.Windows.Forms.OpenFileDialog]$Dialog = New-Object -TypeName 'System.Windows.Forms.OpenFileDialog'
    # Set the filter to show only XML files
    $Dialog.Filter = 'XML files (*.xml)|*.xml'
    # Show the dialog and get the result
    [System.String]$Result = $Dialog.ShowDialog()
    # If the user clicked OK, return the selected file path
    if ($Result -eq 'OK') {
        return "`"$($Dialog.FileName)`""
    }
}

# Opens Folder picker GUI so that user can select folders to be processed
# WildCard file paths
[System.Management.Automation.ScriptBlock]$ArgumentCompleterFolderPathsPickerWildCards = {
    # Load the System.Windows.Forms assembly
    Add-Type -AssemblyName 'System.Windows.Forms'
    # non-top-most, works better with window focus
    [System.Windows.Forms.FolderBrowserDialog]$Browser = New-Object -TypeName 'System.Windows.Forms.FolderBrowserDialog'
    $null = $Browser.ShowDialog()
    # Add quotes around the selected path and a wildcard character at the end
    return "`"$($Browser.SelectedPath)\*`""
}
# SIG # Begin signature block
# MIILhgYJKoZIhvcNAQcCoIILdzCCC3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCACQVo42pIDlP//
# hc3sso4pGXKcc7j7FtBlqDgHV6T5l6CCB88wggfLMIIFs6ADAgECAhNUAAAABzgp
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
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg7MQMaZTl51at
# qz8nhBzT0CXoT51gzjRrpjpaOSZ3+CswDQYJKoZIhvcNAQEBBQAEggIAXSrO7Vkb
# kNlpSlV5TWl/wGPNsqCthjGYN9XvwlJNmTBCV6ZWfY/Pc3dC+lYDjVTSgVCURZbw
# 3E0sJpS8U3cPGuG/hH4ezdTbs0HoI0hqFE3rJ517Q589/4zwLGMQGCBdy2oqDzeT
# VNhBKeDrMeWyLuOftwHhHp4jSV/3ds52mxYvSTOTQ9LC0iQ32fWc6tHC+4z/e4K/
# nf6MQia9Mv3j5AMr4rIIpU0aTyCgxVn4yvbaiUvrYaX/Vj33oWGsusS+K/PMSgj3
# 527IODRNrAOSEjLCNUrqp1rBaNNo+heYzuKXIvGowR5km9y/Jc1NQBGXCgQaGPTU
# 58Cocd8dvazMM6ZutHNx3hBohC4tFXdKCQzGGRMnMk7EVLpbMbjRRT5AwN8jtiKB
# 1Uh2hOBKo8Zynp9y+eEUtgU874+Qqa8RIGTpLNHUpRueOlTDm8blH6XaIN2OG8W5
# JfXCwNCoR63IZGxmb0T+UyCzfSThUNWCujl7KTsJDvkC2EqRxq3OMK9YTmRq6UBw
# XVK57/u2vgVUDl7Ii2DO0Yv+IcUBXZMLN38kLJ9kLFJLB1hti3Rv140j7lCZ9ZaF
# LqjiNCaixfUyTi80aaP6gnw2T/CDXGj25b9S+WiEHCb8wQqs/QCOYzrN6hpwWegr
# k0TZBQeJHAEFqNzrKvdbwEC1M8kSw5ija5s=
# SIG # End signature block
