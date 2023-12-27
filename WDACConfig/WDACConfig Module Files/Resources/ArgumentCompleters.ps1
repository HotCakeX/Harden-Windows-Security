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