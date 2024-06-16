Function Set-CiRuleOptions {
    [CmdletBinding(DefaultParameterSetName = 'All')]
    [OutputType([System.Void])]
    param (
        [ValidateSet('Base', 'BaseISG', 'BaseKernel', 'Supplemental')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Template')]
        [System.String]$Template,

        [ValidateScript({ Test-CiPolicy -XmlFile $_ })]
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$FilePath,

        [ValidateScript({
                if ($_ -notin [RuleOptionsx]::new().GetValidValues()) { throw "Invalid Policy Rule Option: $_" }
                # Return true if everything is okay
                $true
            })]
        [Parameter(Mandatory = $false)][System.String[]]$RulesToAdd,

        [ValidateScript({
                if ($_ -notin [RuleOptionsx]::new().GetValidValues()) { throw "Invalid Policy Rule Option: $_" }
                # Return true if everything is okay
                $true
            })]
        [Parameter(Mandatory = $false)][System.String[]]$RulesToRemove,

        [Parameter(Mandatory = $false)][System.Boolean]$RequireWHQL,
        [Parameter(Mandatory = $false)][System.Boolean]$EnableAuditMode,
        [Parameter(Mandatory = $false)][System.Boolean]$DisableFlightSigning,
        [Parameter(Mandatory = $false)][System.Boolean]$RequireEVSigners,
        [Parameter(Mandatory = $false)][System.Boolean]$ScriptEnforcement,
        [Parameter(Mandatory = $false)][System.Boolean]$TestMode,

        [Parameter(Mandatory = $false, ParameterSetName = 'RemoveAll')]
        [System.Management.Automation.SwitchParameter]$RemoveAll
    )
    Begin {
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        Import-Module -FullyQualifiedName "$ModuleRootPath\XMLOps\Close-EmptyXmlNodes_Semantic.psm1" -Force

        Write-Verbose -Message "Set-CiRuleOptions: Configuring the policy rule options for: $($FilePath.Name)"

        [System.Collections.Hashtable]$Intel = ConvertFrom-Json -AsHashtable -InputObject (Get-Content -Path "$ModuleRootPath\Resources\PolicyRuleOptions.Json" -Raw)

        # Load the XML file
        [System.Xml.XmlDocument]$Xml = Get-Content -Path $FilePath

        # Define the namespace manager
        [System.Xml.XmlNamespaceManager]$Ns = New-Object -TypeName System.Xml.XmlNamespaceManager -ArgumentList $Xml.NameTable
        $Ns.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')

        # Find the Rules Node
        [System.Xml.XmlElement]$RulesNode = $Xml.SelectSingleNode('//ns:Rules', $Ns)

        # an empty hashtable to store the existing rule options in the XML policy file
        [System.Collections.Hashtable]$ExistingRuleOptions = @{}

        # The final rule options to implement which contains only unique values
        $RuleOptionsToImplement = [System.Collections.Generic.HashSet[System.Int32]] @()

        # Defining the rule options for each policy type and scenario
        $BaseRules = [System.Collections.Generic.HashSet[System.Int32]] @(0, 2, 5, 6, 11, 12, 16, 17, 19, 20)
        $BaseISGRules = [System.Collections.Generic.HashSet[System.Int32]] @(0, 2, 5, 6, 11, 12, 14, 15, 16, 17, 19, 20)
        $BaseKernelModeRules = [System.Collections.Generic.HashSet[System.Int32]] @(2, 5, 6, 16, 17, 20)
        $SupplementalRules = [System.Collections.Generic.HashSet[System.Int32]] @(6, 18)
        $RequireWHQLRules = [System.Collections.Generic.HashSet[System.Int32]] @(2)
        $EnableAuditModeRules = [System.Collections.Generic.HashSet[System.Int32]] @(3)
        $DisableFlightSigningRules = [System.Collections.Generic.HashSet[System.Int32]] @(4)
        $RequireEVSignersRules = [System.Collections.Generic.HashSet[System.Int32]] @(8)
        $ScriptEnforcementRules = [System.Collections.Generic.HashSet[System.Int32]] @(11)
        $TestModeRules = [System.Collections.Generic.HashSet[System.Int32]] @(9, 10)

        # A flag to determine whether to clear all the existing rules based on the input parameters
        if ($PSBoundParameters['Template'] -or $PSBoundParameters['RemoveAll']) {
            [System.Boolean]$ClearAllRules = $true
        }
        else {
            [System.Boolean]$ClearAllRules = $False
        }

        # Iterating through each <Rule> node in the supplied XML file
        foreach ($RuleNode in $RulesNode.SelectNodes('ns:Rule', $Ns)) {
            # Get the option text from the <Option> node
            [System.String]$OptionText = $RuleNode.SelectSingleNode('ns:Option', $Ns).InnerText

            # Check if the option text exists in the Intel HashTable
            if ($Intel.ContainsValue($OptionText)) {

                # Add the option text and its corresponding key to the HashTable
                [System.Int32]$Key = $Intel.Keys | Where-Object -FilterScript { $Intel[$_] -eq $OptionText }
                $ExistingRuleOptions[$Key] = [System.String]$OptionText
            }
        }

        if (-NOT $ClearAllRules) {
            # Add the existing rule options to the final rule options to implement
            $RuleOptionsToImplement.UnionWith([System.Collections.Generic.HashSet[System.Int32]]@($ExistingRuleOptions.Keys))
        }
        else {
            $RuleOptionsToImplement.Clear()
        }

        # Process selected templates
        switch ($Template) {
            'Base' { $RuleOptionsToImplement.UnionWith($BaseRules) }
            'BaseISG' { $RuleOptionsToImplement.UnionWith($BaseISGRules) }
            'BaseKernel' { $RuleOptionsToImplement.UnionWith($BaseKernelModeRules) }
            'Supplemental' { $RuleOptionsToImplement.UnionWith($SupplementalRules) }
        }

        # Process individual boolean parameters
        switch ($true) {
            { $RequireWHQL -eq $true } { $RuleOptionsToImplement.UnionWith($RequireWHQLRules) }
            { $RequireWHQL -eq $false } { $RuleOptionsToImplement.ExceptWith($RequireWHQLRules) }
            { $EnableAuditMode -eq $true } { $RuleOptionsToImplement.UnionWith($EnableAuditModeRules) }
            { $EnableAuditMode -eq $false } { $RuleOptionsToImplement.ExceptWith($EnableAuditModeRules) }
            { $DisableFlightSigning -eq $true } { $RuleOptionsToImplement.UnionWith($DisableFlightSigningRules) }
            { $DisableFlightSigning -eq $false } { $RuleOptionsToImplement.ExceptWith($DisableFlightSigningRules) }
            { $RequireEVSigners -eq $true } { $RuleOptionsToImplement.UnionWith($RequireEVSignersRules) }
            { $RequireEVSigners -eq $false } { $RuleOptionsToImplement.ExceptWith($RequireEVSignersRules) }
            { $ScriptEnforcement -eq $false } { $RuleOptionsToImplement.UnionWith($ScriptEnforcementRules) }
            { $ScriptEnforcement -eq $true } { $RuleOptionsToImplement.ExceptWith($ScriptEnforcementRules) }
            { $TestMode -eq $true } { $RuleOptionsToImplement.UnionWith($TestModeRules) }
            { $TestMode -eq $false } { $RuleOptionsToImplement.ExceptWith($TestModeRules) }
        }

        # Process individual rules to add
        foreach ($Item in $RulesToAdd) {
            [System.Int32]$Key = $Intel.Keys | Where-Object -FilterScript { $Intel[$_] -eq $Item }
            [System.Void]$RuleOptionsToImplement.Add($Key)
        }
        # Process individual rules to  remove
        foreach ($Item in $RulesToRemove) {
            [System.Int32]$Key = $Intel.Keys | Where-Object -FilterScript { $Intel[$_] -eq $Item }
            [System.Void]$RuleOptionsToImplement.Remove($Key)
        }

        # Make sure Supplemental policies only contain rule options that are applicable to them
        if (($Template -eq 'Supplemental') -or ($Xml.SiPolicy.PolicyType -eq 'Supplemental Policy')) {
            foreach ($Rule in $RuleOptionsToImplement) {
                if ($Rule -notin '18', '14', '13', '7', '5', '6') {
                    [System.Void]$RuleOptionsToImplement.Remove($Rule)
                }
            }
        }
    }
    Process {

        # Compare the existing rule options in the policy XML file with the rule options to implement
        Compare-Object -ReferenceObject ([System.Int32[]]$RuleOptionsToImplement) -DifferenceObject ([System.Int32[]]$ExistingRuleOptions.Keys) |
        ForEach-Object -Process {
            if ($_.SideIndicator -eq '<=') {
                Write-Verbose -Message "Set-CiRuleOptions: Adding Rule Option: $($Intel[[System.String]$_.InputObject])"
            }
            else {
                Write-Verbose -Message "Set-CiRuleOptions: Removing Rule Option: $($Intel[[System.String]$_.InputObject])"
            }
        }

        # Always remove any existing rule options initially. The calculations determining which
        # Rules must be included in the policy are all made in the Begin block.
        if ($null -ne $RulesNode) {
            $RulesNode.RemoveAll()
        }

        # Create new Rule elements
        foreach ($Rule in ($RuleOptionsToImplement | Sort-Object)) {

            # Create a new rule element
            [System.Xml.XmlElement]$NewRuleNode = $Xml.CreateElement('Rule', $RulesNode.NamespaceURI)

            # Create the Option element inside of the rule element
            [System.Xml.XmlElement]$OptionNode = $Xml.CreateElement('Option', $RulesNode.NamespaceURI)
            # Set the value of the Option element
            $OptionNode.InnerText = $Intel[[System.String]$Rule]
            # Append the Option element to the Rule element
            [System.Void]$NewRuleNode.AppendChild($OptionNode)

            # Add the new Rule element to the Rules node
            [System.Void]$RulesNode.AppendChild($NewRuleNode)
        }
    }
    End {
        $Xml.Save($FilePath)

        # Close the empty XML nodes
        Close-EmptyXmlNodes_Semantic -XmlFilePath $FilePath

        # Set the HVCI to Strict
        Set-HVCIOptions -Strict -FilePath $FilePath

        # Validate the XML file at the end
        Test-CiPolicy -XmlFile $FilePath | Out-Null
    }
    <#
    .SYNOPSIS
        Configures the Policy rule options in a given XML file and sets the HVCI to Strict in the output XML file.
        This function is completely self-sufficient and does not rely on built-in modules.
    .DESCRIPTION
        It offers many ways to configure the policy rule options in a given XML file.
        All of its various parameters provide the flexibility that ensures only one pass is needed to configure the policy rule options.
    .LINK
        https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CiRuleOptions
    .PARAMETER Template
        Specifies the template to use for the CI policy rules: Base, BaseISG, BaseKernel, or Supplemental
    .PARAMETER RulesToAdd
        Specifies the rule options to add to the policy XML file
        If a rule option is already selected by the RulesToRemove parameter, it won't be suggested by the argument completer of this parameter.
    .PARAMETER RulesToRemove
        Specifies the rule options to remove from the policy XML file
        If a rule option is already selected by the RulesToAdd parameter, it won't be suggested by the argument completer of this parameter.
    .PARAMETER RemoveAll
        Removes all the existing rule options from the policy XML file
    .PARAMETER FilePath
        Specifies the path to the XML file that contains the CI policy rules
    .PARAMETER RequireWHQL
        Specifies whether to require WHQL signatures for all drivers
    .PARAMETER EnableAuditMode
        Specifies whether to enable audit mode
    .PARAMETER DisableFlightSigning
        Specifies whether to disable flight signing
    .PARAMETER RequireEVSigners
        Specifies whether to require EV signers
    .PARAMETER DisableScriptEnforcement
        Specifies whether to disable script enforcement
    .PARAMETER TestMode
        Specifies whether to enable test mode
    .NOTES
        First the template is processed, then the individual boolean parameters, and finally the individual rules to add and remove.
    .INPUTS
        System.Management.Automation.SwitchParameter
        System.IO.FileInfo
        System.String[]
        System.String
    .OUTPUTS
        System.Void
    #>
}
# Note: This argument completer suggest rule options that are not already selected on the command line by *any* other parameter
# It currently doesn't make a distinction between the RulesToAdd/RulesToRemove parameters and other parameters.
[System.Management.Automation.ScriptBlock]$RuleOptionsScriptBlock = {
    # Get the current command and the already bound parameters
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)

    # Find all string constants in the AST
    $Existing = $CommandAst.FindAll(
        # The predicate scriptblock to define the criteria for filtering the AST nodes
        {
            $Args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
        },
        # The recurse flag, whether to search nested scriptblocks or not.
        $false
    ).Value

    [RuleOptionsx]::new().GetValidValues() | ForEach-Object -Process {
        # Check if the item is already selected
        if ($_ -notin $Existing) {
            # Return the item
            "'$_'"
        }
    }
}

Register-ArgumentCompleter -CommandName 'Set-CiRuleOptions' -ParameterName 'FilePath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterXmlFilePathsPicker)
Register-ArgumentCompleter -CommandName 'Set-CiRuleOptions' -ParameterName 'RulesToAdd' -ScriptBlock $RuleOptionsScriptBlock
Register-ArgumentCompleter -CommandName 'Set-CiRuleOptions' -ParameterName 'RulesToRemove' -ScriptBlock $RuleOptionsScriptBlock

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDU7GoTN2CjgYbJ
# ZP1KzS6tBADW19yY2rBwjY3kBGB+36CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgSj88jVDHRKpm7gAR1FoPst3HR/ZTe7A0cUXyHXr9C4QwDQYJKoZIhvcNAQEB
# BQAEggIAF6BtvXItokq3wH63vRKIK6y38cLNZzJDTiIf4ziDEOBLzZAwMwmlXjjz
# VbyawRAHpKXKxMiDbyac6gKLHEMaLpR3v3QvcKXVUAXJt39CqbB2DtWzPUs8QpkR
# ittxi5S4Y5bbtopMYfNHTKCjy4GvPFihKiH1vkqnq+NEirQ2X7HTHWCC5owTQKuR
# OykREYh4V9z6hLeatyrHVDQF5bHtADB6SzIEGjVYONH3WthG1Fiela4bW0u0X78Z
# l2tzYtkxfn0hzA1Fbt0larX5PikJ2xDRZJIcoY3KWPlYTO6XOd20UtVucoBXzEi0
# ZnsXOVyVCRjwRfS+AbW+dyiU0IAJsLoVzCry4aj6K/fos58tgZK+/EOJ+XBRy8qw
# qq8y+WiHGFrQ5cQPUCkRJwvei3KD9/br61376pEa8TygmhbZp+J2isHxGIN1/ABf
# lip/fA1cmL4nwedO8Tncvks+w2z19CPA3ijKEKPX2+jvTyypiDgqx8i2NvloO5N3
# fOopB31DjgPTEd7Sl5KQyuSd0a9wlqRgs2EESyJg9rwkXwARwz89FcsRgYy21a7t
# 79HHBNahVFzTho6xRkyb/S7LZzdk3Jj+nO66jsNTtaga5rUhad79/vPx2IztTQdC
# 26Yj4PiF54g3lGgRQ+Se2m7TGZPJsmbe9YJgAJTCGZme+PFWrGU=
# SIG # End signature block
