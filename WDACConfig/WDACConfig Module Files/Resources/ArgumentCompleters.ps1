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
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCACQVo42pIDlP//
# hc3sso4pGXKcc7j7FtBlqDgHV6T5l6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
# LDQz/68TAAAAAAAEMA0GCSqGSIb3DQEBDQUAME8xEzARBgoJkiaJk/IsZAEZFgNj
# b20xIjAgBgoJkiaJk/IsZAEZFhJIT1RDQUtFWC1DQS1Eb21haW4xFDASBgNVBAMT
# C0hPVENBS0VYLUNBMCAXDTIzMTIyNzExMjkyOVoYDzIyMDgxMTEyMTEyOTI5WjB5
# MQswCQYDVQQGEwJVSzEeMBwGA1UEAxMVSG90Q2FrZVggQ29kZSBTaWduaW5nMSMw
# IQYJKoZIhvcNAQkBFhRob3RjYWtleEBvdXRsb29rLmNvbTElMCMGCSqGSIb3DQEJ
# ARYWU3B5bmV0Z2lybEBvdXRsb29rLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAKb1BJzTrpu1ERiwr7ivp0UuJ1GmNmmZ65eckLpGSF+2r22+7Tgm
# pEifj9NhPw0X60F9HhdSM+2XeuikmaNMvq8XRDUFoenv9P1ZU1wli5WTKHJ5ayDW
# k2NP22G9IPRnIpizkHkQnCwctx0AFJx1qvvd+EFlG6ihM0fKGG+DwMaFqsKCGh+M
# rb1bKKtY7UEnEVAsVi7KYGkkH+ukhyFUAdUbh/3ZjO0xWPYpkf/1ldvGes6pjK6P
# US2PHbe6ukiupqYYG3I5Ad0e20uQfZbz9vMSTiwslLhmsST0XAesEvi+SJYz2xAQ
# x2O4n/PxMRxZ3m5Q0WQxLTGFGjB2Bl+B+QPBzbpwb9JC77zgA8J2ncP2biEguSRJ
# e56Ezx6YpSoRv4d1jS3tpRL+ZFm8yv6We+hodE++0tLsfpUq42Guy3MrGQ2kTIRo
# 7TGLOLpayR8tYmnF0XEHaBiVl7u/Szr7kmOe/CfRG8IZl6UX+/66OqZeyJ12Q3m2
# fe7ZWnpWT5sVp2sJmiuGb3atFXBWKcwNumNuy4JecjQE+7NF8rfIv94NxbBV/WSM
# pKf6Yv9OgzkjY1nRdIS1FBHa88RR55+7Ikh4FIGPBTAibiCEJMc79+b8cdsQGOo4
# ymgbKjGeoRNjtegZ7XE/3TUywBBFMf8NfcjF8REs/HIl7u2RHwRaUTJdAgMBAAGj
# ggJzMIICbzA8BgkrBgEEAYI3FQcELzAtBiUrBgEEAYI3FQiG7sUghM++I4HxhQSF
# hqV1htyhDXuG5sF2wOlDAgFkAgEIMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1Ud
# DwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYB
# BQUHAwMwHQYDVR0OBBYEFOlnnQDHNUpYoPqECFP6JAqGDFM6MB8GA1UdIwQYMBaA
# FICT0Mhz5MfqMIi7Xax90DRKYJLSMIHUBgNVHR8EgcwwgckwgcaggcOggcCGgb1s
# ZGFwOi8vL0NOPUhPVENBS0VYLUNBLENOPUhvdENha2VYLENOPUNEUCxDTj1QdWJs
# aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
# LERDPU5vbkV4aXN0ZW50RG9tYWluLERDPWNvbT9jZXJ0aWZpY2F0ZVJldm9jYXRp
# b25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwgccG
# CCsGAQUFBwEBBIG6MIG3MIG0BggrBgEFBQcwAoaBp2xkYXA6Ly8vQ049SE9UQ0FL
# RVgtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZp
# Y2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Tm9uRXhpc3RlbnREb21haW4sREM9Y29t
# P2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0
# aG9yaXR5MA0GCSqGSIb3DQEBDQUAA4ICAQA7JI76Ixy113wNjiJmJmPKfnn7brVI
# IyA3ZudXCheqWTYPyYnwzhCSzKJLejGNAsMlXwoYgXQBBmMiSI4Zv4UhTNc4Umqx
# pZSpqV+3FRFQHOG/X6NMHuFa2z7T2pdj+QJuH5TgPayKAJc+Kbg4C7edL6YoePRu
# HoEhoRffiabEP/yDtZWMa6WFqBsfgiLMlo7DfuhRJ0eRqvJ6+czOVU2bxvESMQVo
# bvFTNDlEcUzBM7QxbnsDyGpoJZTx6M3cUkEazuliPAw3IW1vJn8SR1jFBukKcjWn
# aau+/BE9w77GFz1RbIfH3hJ/CUA0wCavxWcbAHz1YoPTAz6EKjIc5PcHpDO+n8Fh
# t3ULwVjWPMoZzU589IXi+2Ol0IUWAdoQJr/Llhub3SNKZ3LlMUPNt+tXAs/vcUl0
# 7+Dp5FpUARE2gMYA/XxfU9T6Q3pX3/NRP/ojO9m0JrKv/KMc9sCGmV9sDygCOosU
# 5yGS4Ze/DJw6QR7xT9lMiWsfgL96Qcw4lfu1+5iLr0dnDFsGowGTKPGI0EvzK7H+
# DuFRg+Fyhn40dOUl8fVDqYHuZJRoWJxCsyobVkrX4rA6xUTswl7xYPYWz88WZDoY
# gI8AwuRkzJyUEA07IYtsbFCYrcUzIHME4uf8jsJhCmb0va1G2WrWuyasv3K/G8Nn
# f60MsDbDH1mLtzGCAxgwggMUAgEBMGYwTzETMBEGCgmSJomT8ixkARkWA2NvbTEi
# MCAGCgmSJomT8ixkARkWEkhPVENBS0VYLUNBLURvbWFpbjEUMBIGA1UEAxMLSE9U
# Q0FLRVgtQ0ECEx4AAAAEjzQsNDP/rxMAAAAAAAQwDQYJYIZIAWUDBAIBBQCggYQw
# GAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
# NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQx
# IgQg7MQMaZTl51atqz8nhBzT0CXoT51gzjRrpjpaOSZ3+CswDQYJKoZIhvcNAQEB
# BQAEggIAbdncpaN6OUf7f9Itk+4Un9BXzakEdEqm6UZnge/WQZ1vQnRN3In5Iu11
# 4OpxGswodZ02976NrNA/M0YpoPauwRY/BEkc6ge14TExvHM/FVMp3PoE1zBI9P/M
# 7vCFIQwGrsOzhJwi9hPiBPkdwHMcjWmz3Maqb4qBRFLiKPxmvZfO3Td6flh1SCXD
# O6E4n/DyLRqEbDH9wG+d6RUaEvGZyLNrAXeTXz0XLW3VlFnN6YsT/7hdvnAUYFVy
# TXWSs6hKz0+neAQcFBnlPTB09KU/HORvTUsKGmD9Jo8NREl0h/YIAUrWOtPkUXSq
# bMpexuThTuBQ/qT/BxFoWyCeB1+qKd10IPOjeT6nji7bdvC3BYv6bVcJm9iIod69
# +mtQANBBNdtwCyfSk06ckaDh/oXWIy+E1nWuADN0xRxRFO28szEWjoW+UQfLeE4N
# V+VCda9SXhK42jdG9B8w1cNYNKGCTuJiidcGhUEaNmAQZ1SdgepApZHfDyooNw2h
# BGC+h4GnI1XG7d+2zYmgYicqtumXnNMevJjtWLpDirl9wXCpqzC66gFjBK8ezF10
# 1j9pmjV9B8MpBS2kGCFk/d9J48dzLp/ChwmPse1MQ5FB1cObkh1/Q2AzzTev+ILg
# XxKhW0HJOZbzZYaj7IhwYUuP5RidqGrLnT+mezi0MIlMjKChNQA=
# SIG # End signature block
