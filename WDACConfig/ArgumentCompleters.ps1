<#
# argument tab auto-completion for CertPath param to show only .cer files in current directory and 2 sub-directories recursively
[scriptblock]$ArgumentCompleterCertPath = {
    # Note the use of -Depth 1
    # Enclosing the $results = ... assignment in (...) also passes the value through.
    ($results = Get-ChildItem -Depth 2 -Filter *.cer | ForEach-Object { "`"$_`"" })
    if (-not $results) {
        # No results?
        $null # Dummy response that prevents fallback to the default file-name completion.
    }   
}
#>

# argument tab auto-completion for Policy Paths to show only .xml files and only suggest files that haven't been already selected by user 
# https://stackoverflow.com/questions/76141864/how-to-make-a-powershell-argument-completer-that-only-suggests-files-not-already/76142865
[scriptblock]$ArgumentCompleterPolicyPaths = {
    # Get the current command and the already bound parameters
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    # Find all string constants in the AST that end in ".xml"
    $existing = $commandAst.FindAll({ 
            $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and 
            $args[0].Value -like '*.xml' 
        }, 
        $false
    ).Value  

    # Get the xml files in the current directory
    Get-ChildItem -Filter *.xml | ForEach-Object {
        # Check if the file is already selected
        if ($_.FullName -notin $existing) {
            # Return the file name with quotes
            "`"$_`""
        }
    }
}

# argument tab auto-completion for Certificate common name
[scriptblock]$ArgumentCompleterCertificateCN = {     
    $certs = foreach ($cert in (Get-ChildItem 'Cert:\CurrentUser\my')) {
        (($cert.Subject -split ',' | Select-Object -First 1) -replace 'CN=', '').Trim()
    }    
    $certs | ForEach-Object { return "`"$_`"" }
}

# Argument tab auto-completion for installed Appx package names
[scriptblock]$ArgumentCompleterAppxPackageNames = {
    # Get the current command and the already bound parameters
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    # Get the app package names that match the word to complete
    Get-AppxPackage -Name *$wordToComplete* | ForEach-Object {
        "`"$($_.Name)`""
    }
}

# argument tab auto-completion for Base Policy Paths to show only .xml files and only suggest files that haven't been already selected by user 
[scriptblock]$ArgumentCompleterPolicyPathsBasePoliciesOnly = {
    # Get the current command and the already bound parameters
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    # Find all string constants in the AST that end in ".xml"
    $existing = $commandAst.FindAll({ 
            $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and 
            $args[0].Value -like '*.xml' 
        }, 
        $false
    ).Value  

    # Get the xml files in the current directory
    Get-ChildItem | Where-Object { $_.extension -like '*.xml' } | ForEach-Object {

        $xmlitem = [xml](Get-Content $_)
        $PolicyType = $xmlitem.SiPolicy.PolicyType

        if ($PolicyType -eq 'Base Policy') {

            # Check if the file is already selected
            if ($_.FullName -notin $existing) {
                # Return the file name with quotes
                "`"$_`""
            }
        }
    }
}

# argument tab auto-completion for Supplemental Policy Paths to show only .xml files and only suggest files that haven't been already selected by user
[scriptblock]$ArgumentCompleterPolicyPathsSupplementalPoliciesOnly = {
    # Get the current command and the already bound parameters
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    # Find all string constants in the AST that end in ".xml"
    $existing = $commandAst.FindAll({ 
            $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and 
            $args[0].Value -like '*.xml' 
        }, 
        $false
    ).Value  

    # Get the xml files in the current directory
    Get-ChildItem | Where-Object { $_.extension -like '*.xml' } | ForEach-Object {

        $xmlitem = [xml](Get-Content $_)
        $PolicyType = $xmlitem.SiPolicy.PolicyType

        if ($PolicyType -eq 'Supplemental Policy') {

            # Check if the file is already selected
            if ($_.FullName -notin $existing) {
                # Return the file name with quotes
                "`"$_`""
            }
        }
    }
}

# Opens Folder picker GUI so that user can select folders to be processed
[scriptblock]$ArgumentCompleterFolderPathsPicker = {
    # Load the System.Windows.Forms assembly
    Add-Type -AssemblyName System.Windows.Forms
    # non-top-most, works better with window focus
    $browser = New-Object System.Windows.Forms.FolderBrowserDialog
    $null = $browser.ShowDialog()
    # Add quotes around the selected path
    return "`"$($browser.SelectedPath)`""
}

# Opens File picker GUI so that user can select an .exe file - for SignTool.exe
[scriptblock]$ArgumentCompleterExeFilePathsPicker = {
    # Load the System.Windows.Forms assembly
    Add-Type -AssemblyName System.Windows.Forms
    # Create a new OpenFileDialog object
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    # Set the filter to show only executable files
    $dialog.Filter = 'Executable files (*.exe)|*.exe'
    # Show the dialog and get the result
    $result = $dialog.ShowDialog()
    # If the user clicked OK, return the selected file path
    if ($result -eq 'OK') {
        return "`"$($dialog.FileName)`""
    }
}

# Opens File picker GUI so that user can select a .cer file
[scriptblock]$ArgumentCompleterCerFilePathsPicker = {
    # Load the System.Windows.Forms assembly
    Add-Type -AssemblyName System.Windows.Forms
    # Create a new OpenFileDialog object
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    # Set the filter to show only certificate files
    $dialog.Filter = 'Certificate files (*.cer)|*.cer'
    # Show the dialog and get the result
    $result = $dialog.ShowDialog()
    # If the user clicked OK, return the selected file path
    if ($result -eq 'OK') {
        return "`"$($dialog.FileName)`""
    }
}

# Opens File picker GUI so that user can select a .xml file
[scriptblock]$ArgumentCompleterXmlFilePathsPicker = {
    # Load the System.Windows.Forms assembly
    Add-Type -AssemblyName System.Windows.Forms
    # Create a new OpenFileDialog object
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    # Set the filter to show only XML files
    $dialog.Filter = 'XML files (*.xml)|*.xml'
    # Show the dialog and get the result
    $result = $dialog.ShowDialog()
    # If the user clicked OK, return the selected file path
    if ($result -eq 'OK') {
        return "`"$($dialog.FileName)`""
    }
}

# Opens Folder picker GUI so that user can select folders to be processed
# WildCard file paths
[scriptblock]$ArgumentCompleterFolderPathsPickerWildCards = {
    # Load the System.Windows.Forms assembly
    Add-Type -AssemblyName System.Windows.Forms
    # non-top-most, works better with window focus
    $browser = New-Object System.Windows.Forms.FolderBrowserDialog
    $null = $browser.ShowDialog()
    # Add quotes around the selected path
    return "`"$($browser.SelectedPath)\*`""
}