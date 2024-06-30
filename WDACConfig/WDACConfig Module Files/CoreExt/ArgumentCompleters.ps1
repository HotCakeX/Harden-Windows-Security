# Argument tab auto-completion for installed Appx package names
[WDACConfig.ArgumentCompleters]::ArgumentCompleterAppxPackageNames = [System.Management.Automation.ScriptBlock]::Create( {
        # Get the current command and the already bound parameters
        param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)
        # Get the app package names that match the word to complete
        foreach ($AppName in (Get-AppxPackage -Name *$WordToComplete*)) {
            "`"$($AppName.Name)`""
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
        $Dialog.InitialDirectory = ([WDACConfig.GlobalVars]::UserConfigDir)
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
        $Dialog.InitialDirectory = ([WDACConfig.GlobalVars]::UserConfigDir)
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
        $Dialog.InitialDirectory = ([WDACConfig.GlobalVars]::UserConfigDir)
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
        $Dialog.InitialDirectory = ([WDACConfig.GlobalVars]::UserConfigDir)
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
        $Dialog.InitialDirectory = ([WDACConfig.GlobalVars]::UserConfigDir)
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

