Function Remove-DuplicateFileAttrib_IDBased {
    <#
        .SYNOPSIS
            Takes a path to an XML file and removes duplicate FileAttrib elements from the <FileRules> node
            and duplicate FileRuleRef elements from the <ProductSigners> node under each <SigningScenarios> node
            and duplicate FileAttribRef elements from the <Signer> node under each <Signers> node.

            The criteria for removing duplicates is the ID attribute of the FileAttrib elements and the RuleID attribute of the FileRuleRef elements
        .PARAMETER XmlFilePath
            The path to the XML file to be modified.
        .INPUTS
            System.IO.FileInfo
        .OUTPUTS
            System.Void
        #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath
    )
    Begin {
        # Load the XML file
        [System.Xml.XmlDocument]$Xml = Get-Content -Path $XmlFilePath

        # Define namespace manager
        [System.Xml.XmlNamespaceManager]$NsMgr = New-Object -TypeName System.Xml.XmlNamespaceManager -ArgumentList $Xml.NameTable
        $NsMgr.AddNamespace('sip', 'urn:schemas-microsoft-com:sipolicy')
    }

    Process {
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Get all FileAttrib elements
        [System.Xml.XmlNodeList]$FileAttribs = $Xml.SelectNodes('//sip:FileRules/sip:FileAttrib', $NsMgr)

        # Track seen FileAttrib IDs
        [System.Collections.Hashtable]$SeenFileAttribIDs = @{}

        # Loop through each FileAttrib element
        foreach ($FileAttrib in $FileAttribs) {

            [System.String]$FileAttribID = $FileAttrib.ID

            # Check if the FileAttrib ID has been seen before
            if ($SeenFileAttribIDs.ContainsKey($FileAttribID)) {

                Write-Verbose -Message "Remove-DuplicateFileAttrib: Removed duplicate FileAttrib with ID: $FileAttribID"
                [System.Void]$FileAttrib.ParentNode.RemoveChild($FileAttrib)
            }
            else {
                # If not seen before, add to seen FileAttrib IDs
                $SeenFileAttribIDs[$FileAttribID] = $true
            }
        }

        # Get all ProductSigners under SigningScenarios
        [System.Xml.XmlNodeList]$SigningScenarios = $Xml.SelectNodes('//sip:SigningScenarios/sip:SigningScenario', $NsMgr)

        # Loop through each SigningScenario
        foreach ($Scenario in $SigningScenarios) {

            # Track seen FileRuleRef IDs
            [System.Collections.Hashtable]$SeenFileRuleRefIDs = @{}

            # Get all FileRuleRef elements under ProductSigners
            $FileRuleRefs = $Scenario.ProductSigners.FileRulesRef.FileRuleRef

            # Loop through each FileRuleRef element
            foreach ($FileRuleRef in $FileRuleRefs) {

                [System.String]$FileRuleRefID = $FileRuleRef.RuleID

                # Check if the FileRuleRef ID has been seen before
                if ($SeenFileRuleRefIDs.ContainsKey($FileRuleRefID)) {

                    Write-Verbose -Message "Remove-DuplicateFileAttrib: Removed duplicate FileRuleRef with ID: $FileRuleRefID"
                    [System.Void]$FileRuleRef.ParentNode.RemoveChild($FileRuleRef)
                }
                else {
                    # If not seen before, add to seen FileRuleRef IDs
                    $SeenFileRuleRefIDs[$FileRuleRefID] = $true
                }
            }
        }

        # Get all Signers
        [System.Xml.XmlNodeList]$Signers = $Xml.SelectNodes('//sip:Signers/sip:Signer', $NsMgr)

        # Loop through each Signer
        foreach ($Signer in $Signers) {

            # Get all FileAttribRef elements under the Signer
            [System.Xml.XmlElement[]]$FileAttribRefs = $Signer.ChildNodes | Where-Object -FilterScript { $_.Name -eq 'FileAttribRef' }

            # Track seen FileAttribRef IDs
            [System.Collections.Hashtable]$SeenFileAttribRefIDs = @{}

            # Loop through each FileAttribRef element
            foreach ($FileAttribRef in $FileAttribRefs) {

                [System.String]$FileAttribRefID = $FileAttribRef.RuleID

                # Check if the FileAttribRef ID has been seen before
                if ($SeenFileAttribRefIDs.ContainsKey($FileAttribRefID)) {

                    Write-Verbose -Message "Remove-DuplicateFileAttrib: Removed duplicate FileAttribRef with ID: $FileAttribRefID"
                    [System.Void]$Signer.RemoveChild($FileAttribRef)
                }
                else {
                    # If not seen before, add to seen FileAttribRef IDs
                    $SeenFileAttribRefIDs[$FileAttribRefID] = $true
                }
            }
        }
    }
    End {
        # Save the modified XML
        $Xml.Save($XmlFilePath)
    }
}
Export-ModuleMember -Function 'Remove-DuplicateFileAttrib_IDBased'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCoBzqo9bOuq4LY
# 7dvo0RSNbiamzQ2ozQnVzHNBPmu3QKCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgtFhd3kizWVhQ+YWuDvoKRdBXXZesybYz6oFAtyIMXRMwDQYJKoZIhvcNAQEB
# BQAEggIAXsyM/HXPu+26zounQmH1v6pg4P0hRB2zfNHG5qRsWjAyyareVwAaDg+r
# MqACKITxotj2qLW2qzRiCXl6+hGmgKwq9zZOnoNij5IyG6fKzktGqLWQyNcGHu97
# /vIoaB+npr4mM1CdYaF9qtJNddicBRh1YEVEgt0cnCP0tROVHJ7D1KuUJlXZCUr6
# bnPATade9+rHOCMXIGjApTdNL0bKhpRpCRlc8UWQstNjP/BEtaHZk1MSgJKq6NpF
# FMwDcGKIXjRWW3NDPh4IEOpG16Hf9n7ZwanYxSkAxTWjMGYBG7QQ/wl8M6P2SLCA
# GZKAInWuH6WHZb1UuEhRw+PSBG+l/8wucvO9buCfguA3pN1MkAxc9j37PfsSDSxp
# LwXkPRxuk3y69o82gfox7JaNW1hBH21ILq8ukFvW1UvYByJ/U9+hvTgPvGO/IBqw
# DmW2+zRh9XtS4Dkf3xqdwpTKryreIS9x26/sdrc8s2txNrvpoBRD4dUlZ6URxR8P
# FWqItHglppsag3IapBaad4gZ/Fk6rUnz2itXiZbVooROmyDoLOxRqXRel1UgX9YK
# 5RdEls+BhvnDA6lwSsK+JBYP1GuDivlIqjN/XjfGuwUvNq1N5l24vf6AbF/UY68t
# rcVpzqsmJaC8uQZyA2spdaBHNy+bO/TXc7vd+mwVa4om8mJrQnA=
# SIG # End signature block
