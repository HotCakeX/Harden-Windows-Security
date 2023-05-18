# argument tab auto-completion for SignToolPath param to show only .exe files in the current directory
$ArgumentCompleterSignToolPath = {
    Get-ChildItem | where-object { $_.extension -like '*.exe' } | foreach-object { return "`"$_`"" }
}

# argument tab auto-completion for CertPath param to show only .cer files in current directory and 2 sub-directories recursively
$ArgumentCompleterCertPath = {
    # Note the use of -Depth 1
    # Enclosing the $results = ... assignment in (...) also passes the value through.
    ($results = Get-ChildItem -Depth 2 -Filter *.cer | foreach-object { "`"$_`"" })
    if (-not $results) {
        # No results?
        $null # Dummy response that prevents fallback to the default file-name completion.
    }   
}

# argument tab auto-completion for Policy Paths to show only .xml files and only suggest files that haven't been already selected by user 
# https://stackoverflow.com/questions/76141864/how-to-make-a-powershell-argument-completer-that-only-suggests-files-not-already/76142865
$ArgumentCompleterPolicyPaths = {
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
$ArgumentCompleterCertificateCN = {
     
    $CNs = (Get-ChildItem -Path 'Cert:\CurrentUser\My').Subject.Substring(3) | Where-Object { $_ -NotLike "*, DC=*" } |
    ForEach-Object {
            
        if ($_ -like "*CN=*") {
            
            $_ -match "CN=(?<cn>[^,]+)" | Out-Null
        
            return $Matches['cn']
        }
        else { return $_ }
    }   
    
    $CNs | foreach-object { return "`"$_`"" }
}

# Argument tab auto-completion for installed Appx package names
$ArgumentCompleterAppxPackageNames = {
    # Get the current command and the already bound parameters
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    # Get the app package names that match the word to complete
    Get-AppxPackage -Name *$wordToComplete* | ForEach-Object {
        "`"$($_.Name)`""
    }
}

# argument tab auto-completion for Base Policy Paths to show only .xml files and only suggest files that haven't been already selected by user 
$ArgumentCompleterPolicyPathsBasePoliciesOnly = {
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
    Get-ChildItem | where-object { $_.extension -like '*.xml' } | ForEach-Object {

        $xmlitem = [xml](Get-Content $_)
        $PolicyType = $xmlitem.SiPolicy.PolicyType

        if ($PolicyType -eq "Base Policy") {

            # Check if the file is already selected
            if ($_.FullName -notin $existing) {
                # Return the file name with quotes
                "`"$_`""
            }
        }
    }
}

# argument tab auto-completion for Supplemental Policy Paths to show only .xml files and only suggest files that haven't been already selected by user
$ArgumentCompleterPolicyPathsSupplementalPoliciesOnly = {
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
    Get-ChildItem | where-object { $_.extension -like '*.xml' } | ForEach-Object {

        $xmlitem = [xml](Get-Content $_)
        $PolicyType = $xmlitem.SiPolicy.PolicyType

        if ($PolicyType -eq "Supplemental Policy") {

            # Check if the file is already selected
            if ($_.FullName -notin $existing) {
                # Return the file name with quotes
                "`"$_`""
            }
        }
    }
}

# Opens Folder picker GUI so that user can select folders to be processed
$ArgumentCompleterFolderPathsPicker = {
    # Load the System.Windows.Forms assembly
    Add-Type -AssemblyName System.Windows.Forms
    # non-top-most, works better with window focus
    $browser = New-Object System.Windows.Forms.FolderBrowserDialog
    $null = $browser.ShowDialog()
    # Add quotes around the selected path
    return "`"$($browser.SelectedPath)`""
}

