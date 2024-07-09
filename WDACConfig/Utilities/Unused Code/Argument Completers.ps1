# argument tab auto-completion for CertPath param to show only .cer files in current directory and 2 sub-directories recursively
[System.Management.Automation.ScriptBlock]$ArgumentCompleterCertPath = {
    # Note the use of -Depth 1
    # Enclosing the $Results = ... assignment in (...) also passes the value through.
    ($Results = Get-ChildItem -Depth 2 -Filter '*.cer' | ForEach-Object -Process { "`"$_`"" })
    if (-not $Results) {
        # No results?
        $null # Dummy response that prevents fallback to the default file-name completion.
    }
}

# argument tab auto-completion for Policy Paths to show only .xml files and only suggest files that haven't been already selected by user
# https://stackoverflow.com/questions/76141864/how-to-make-a-powershell-argument-completer-that-only-suggests-files-not-already/76142865
[System.Management.Automation.ScriptBlock]$ArgumentCompleterPolicyPaths = {
    # Get the current command and the already bound parameters
    param($CommandName, $parameterName, $wordToComplete, $CommandAst, $fakeBoundParameters)

    # Find all string constants in the AST that end in ".xml"
    $Existing = $CommandAst.FindAll({
            $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
            $args[0].Value -like '*.xml'
        },
        $false
    ).Value

    # Get the xml files in the current directory
    Get-ChildItem -File -Filter '*.xml' | ForEach-Object -Process {
        # Check if the file is already selected
        if ($_.FullName -notin $Existing) {
            # Return the file name with quotes
            "`"$_`""
        }
    }
}

# argument tab auto-completion for Supplemental Policy Paths to show only .xml files and only suggest files that haven't been already selected by user
[System.Management.Automation.ScriptBlock]$ArgumentCompleterPolicyPathsSupplementalPoliciesOnly = {
    # Get the current command and the already bound parameters
    param($CommandName, $parameterName, $wordToComplete, $CommandAst, $fakeBoundParameters)

    # Find all string constants in the AST that end in ".xml"
    $Existing = $CommandAst.FindAll({
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
