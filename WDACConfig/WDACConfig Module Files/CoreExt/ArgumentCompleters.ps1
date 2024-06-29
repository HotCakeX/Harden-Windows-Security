# Argument tab auto-completion for installed Appx package names
[WDACConfig.ArgumentCompleters]::ArgumentCompleterAppxPackageNames = [System.Management.Automation.ScriptBlock]::Create( {
        # Get the current command and the already bound parameters
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        # Get the app package names that match the word to complete
        Get-AppxPackage -Name *$wordToComplete* | ForEach-Object -Process {
            "`"$($_.Name)`""
        }
    })

# Opens Folder picker GUI so that user can select folders to be processed
[WDACConfig.ArgumentCompleters]::ArgumentCompleterFolderPathsPicker = [System.Management.Automation.ScriptBlock]::Create({
        # non-top-most, works better with window focus
        [System.Windows.Forms.FolderBrowserDialog]$Browser = New-Object -TypeName 'System.Windows.Forms.FolderBrowserDialog'
        $null = $Browser.ShowDialog()
        # Add quotes around the selected path
        return "`"$($Browser.SelectedPath)`""
    })

# Opens File picker GUI so that user can select an .exe file - for SignTool.exe
[WDACConfig.ArgumentCompleters]::ArgumentCompleterExeFilePathsPicker = [System.Management.Automation.ScriptBlock]::Create({
        # Create a new OpenFileDialog object
        [System.Windows.Forms.OpenFileDialog]$Dialog = New-Object -TypeName 'System.Windows.Forms.OpenFileDialog'
        # Set the filter to show only executable files
        $Dialog.Filter = 'Executable files (*.exe)|*.exe'
        $Dialog.Title = 'Select the SignTool executable file'
        $Dialog.InitialDirectory = $UserConfigDir
        # Show the dialog and get the result
        [System.String]$Result = $Dialog.ShowDialog()
        # If the user clicked OK, return the selected file path
        if ($Result -eq 'OK') {
            return "`"$($Dialog.FileName)`""
        }
    })

# Opens File picker GUI so that user can select a .cer file
[WDACConfig.ArgumentCompleters]::ArgumentCompleterCerFilePathsPicker = [System.Management.Automation.ScriptBlock]::Create({
        # Create a new OpenFileDialog object
        [System.Windows.Forms.OpenFileDialog]$Dialog = New-Object -TypeName 'System.Windows.Forms.OpenFileDialog'
        # Set the filter to show only certificate files
        $Dialog.Filter = 'Certificate files (*.cer)|*.cer'
        $Dialog.Title = 'Select a certificate file'
        $Dialog.InitialDirectory = $UserConfigDir
        # Show the dialog and get the result
        [System.String]$Result = $Dialog.ShowDialog()
        # If the user clicked OK, return the selected file path
        if ($Result -eq 'OK') {
            return "`"$($Dialog.FileName)`""
        }
    })

# Opens File picker GUI so that user can select multiple .cer files
[WDACConfig.ArgumentCompleters]::ArgumentCompleterCerFilesPathsPicker = [System.Management.Automation.ScriptBlock]::Create({
        # Create a new OpenFileDialog object
        [System.Windows.Forms.OpenFileDialog]$Dialog = New-Object -TypeName 'System.Windows.Forms.OpenFileDialog'
        # Set the filter to show only certificate files
        $Dialog.Filter = 'Certificate files (*.cer)|*.cer'
        $Dialog.Title = 'Select certificate files'
        $Dialog.InitialDirectory = $UserConfigDir
        $Dialog.Multiselect = $true
        # Show the dialog and get the result
        [System.String]$Result = $Dialog.ShowDialog()
        # If the user clicked OK, return the selected file paths
        if ($Result -eq 'OK') {
            return "`"$($Dialog.FileNames -join '","')`""
        }
    })

# Opens File picker GUI so that user can select a .xml file
[WDACConfig.ArgumentCompleters]::ArgumentCompleterXmlFilePathsPicker = [System.Management.Automation.ScriptBlock]::Create({
        # Create a new OpenFileDialog object
        [System.Windows.Forms.OpenFileDialog]$Dialog = New-Object -TypeName 'System.Windows.Forms.OpenFileDialog'
        # Set the filter to show only XML files
        $Dialog.Filter = 'XML files (*.xml)|*.xml'
        $Dialog.Title = 'Select XML files'
        $Dialog.InitialDirectory = $UserConfigDir
        # Show the dialog and get the result
        [System.String]$Result = $Dialog.ShowDialog()
        # If the user clicked OK, return the selected file path
        if ($Result -eq 'OK') {
            return "`"$($Dialog.FileName)`""
        }
    })

# Opens Folder picker GUI so that user can select folders to be processed
# WildCard file paths
[WDACConfig.ArgumentCompleters]::ArgumentCompleterFolderPathsPickerWildCards = [System.Management.Automation.ScriptBlock]::Create({
        # non-top-most, works better with window focus
        [System.Windows.Forms.FolderBrowserDialog]$Browser = New-Object -TypeName 'System.Windows.Forms.FolderBrowserDialog'
        $null = $Browser.ShowDialog()
        # Add quotes around the selected path and a wildcard character at the end
        return "`"$($Browser.SelectedPath)\*`""
    })

# Opens File picker GUI so that user can select any files
[WDACConfig.ArgumentCompleters]::ArgumentCompleterAnyFilePathsPicker = [System.Management.Automation.ScriptBlock]::Create({
        # Create a new OpenFileDialog object
        [System.Windows.Forms.OpenFileDialog]$Dialog = New-Object -TypeName 'System.Windows.Forms.OpenFileDialog'
        # Show the dialog and get the result
        [System.String]$Result = $Dialog.ShowDialog()
        # If the user clicked OK, return the selected file path
        if ($Result -eq 'OK') {
            return "`"$($Dialog.FileName)`""
        }
    })

# Opens File picker GUI so that user can select multiple .xml files
[WDACConfig.ArgumentCompleters]::ArgumentCompleterMultipleXmlFilePathsPicker = [System.Management.Automation.ScriptBlock]::Create({
        # Create a new OpenFileDialog object
        [System.Windows.Forms.OpenFileDialog]$Dialog = New-Object -TypeName 'System.Windows.Forms.OpenFileDialog'
        # Set the filter to show only XML files
        $Dialog.Filter = 'XML files (*.xml)|*.xml'
        # Set the MultiSelect property to true
        $Dialog.MultiSelect = $true
        $Dialog.ShowPreview = $true
        $Dialog.Title = 'Select WDAC Policy XML files'
        $Dialog.InitialDirectory = $UserConfigDir
        # Show the dialog and get the result
        [System.String]$Result = $Dialog.ShowDialog()
        # If the user clicked OK, return the selected file paths
        if ($Result -eq 'OK') {
            return "`"$($Dialog.FileNames -join '","')`""
        }
    })

# Opens File picker GUI so that user can select any files, multiple
[WDACConfig.ArgumentCompleters]::ArgumentCompleterMultipleAnyFilePathsPicker = [System.Management.Automation.ScriptBlock]::Create({
        # Create a new OpenFileDialog object
        [System.Windows.Forms.OpenFileDialog]$Dialog = New-Object -TypeName 'System.Windows.Forms.OpenFileDialog'
        $Dialog.Multiselect = $true
        # Show the dialog and get the result
        [System.String]$Result = $Dialog.ShowDialog()
        # If the user clicked OK, return the selected file path
        if ($Result -eq 'OK') {
            return "`"$($Dialog.FileNames -join '","')`""
        }
    })


# Opens Folder picker GUI so that user can select folders to be processed, multiple
[WDACConfig.ArgumentCompleters]::ArgumentCompleterMultipleFolderPathsPicker = [System.Management.Automation.ScriptBlock]::Create({
        # non-top-most, works better with window focus
        [System.Windows.Forms.FolderBrowserDialog]$Browser = New-Object -TypeName 'System.Windows.Forms.FolderBrowserDialog'
        $Browser.Multiselect = $true
        [System.String]$Result = $Browser.ShowDialog()
        # If the user clicked OK, return the selected file paths
        if ($Result -eq 'OK') {
            return "`"$($Browser.SelectedPaths -join '","')`""
        }
    })

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCClBT8d7gNxxIch
# kJuh42lpjqMGGJa4Ffub15i959XdwaCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgyDGqKhE0UKc2EllRaNaH1WhGRcpalHVgW7Q+nV2tWvQwDQYJKoZIhvcNAQEB
# BQAEggIAeH6EiMqVi4joMWzxAgIxSnvbVbSUQK0Y7eR6sQtTBbYypHcdNU5LEtcq
# NX0SuEJw4w79JNcsP0lq9z7kRJhFPnN19J8Dqpn/dLvN8mRhXLNphA47J7cvlUme
# S++eYw+PnsjfpGDL5P+hg9BgRJCs/UrMASy1X8d2ntjaK6DO1ciYKA3VDIWiDpD8
# I3WlrMDVPLj+z1nNqogJHaW95YU4Bhzw6SadQmnAcLcWlETBoQYwJ/x//MgVkdWI
# nRJGYvYAFBpnGeLS5zo4APWr2VYZfyyXRht/i6e+JhPLoXo9/B1mc7OeFulbxtEL
# Sdhpg6U8JZ4ge9WlmuEvQVckI+sXKlvhhqooarXJpbQh8Y8VmjBAZwG5IZJWHZYV
# vY5TjeZ+u6t9AdOPDezV8WLRJCvBAnM5S4DloM/1f3+5bgSLkkCpcuh45IQCj2qG
# u48EEic02vYq9ipkfR9+/7tTxuSRxCvSGzIQZyZmO807d8BMSCMsPVk9xomQ8Ftd
# Aao6OEeyvQhUmz3AOoAhTF4mV15OPgKPrAoUcnxKGbGby18mqmikcKXW06yDnacu
# Cw4EAp2/P5xZ8T84qHLFKMxvc4/6V+vosN1i+WVlkBzzsghdIu9PWnu/pKXSlkwG
# b88rbU0cTVyABPKGMjWM6H4BSzv5299AwN9Hlz1D+v/qXECDG3E=
# SIG # End signature block
