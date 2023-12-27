Function Move-UserModeToKernelMode {
    <#
    .SYNOPSIS
        Moves all User mode AllowedSigners in the User mode signing scenario to the Kernel mode signing scenario and then
        deletes the entire User mode signing scenario block
    .PARAMETER FilePath
        The path to the XML file to be modified
    .INPUTS
        System.String
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [System.String]$FilePath
    )
    # Importing the $PSDefaultParameterValues to the current session, prior to everything else
    . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

    # Load the XML file as an XmlDocument object
    $Xml = [System.Xml.XmlDocument](Get-Content -Path $FilePath)

    # Get the SigningScenario nodes as an array
    $signingScenarios = $Xml.SiPolicy.SigningScenarios.SigningScenario

    # Find the SigningScenario node with Value 131 and store it in a variable
    $signingScenario131 = $signingScenarios | Where-Object -FilterScript { $_.Value -eq '131' }

    # Find the SigningScenario node with Value 12 and store it in a variable
    $signingScenario12 = $signingScenarios | Where-Object -FilterScript { $_.Value -eq '12' }

    # Get the AllowedSigners node from the SigningScenario node with Value 12
    $AllowedSigners12 = $signingScenario12.ProductSigners.AllowedSigners

    # Check if the AllowedSigners node has any child nodes
    if ($AllowedSigners12.HasChildNodes) {
        # Loop through each AllowedSigner node from the SigningScenario node with Value 12
        foreach ($AllowedSigner in $AllowedSigners12.AllowedSigner) {
            # Create a new AllowedSigner node and copy the SignerId attribute from the original node
            # Use the namespace of the parent element when creating the new element
            $NewAllowedSigner = $Xml.CreateElement('AllowedSigner', $signingScenario131.NamespaceURI)
            $NewAllowedSigner.SetAttribute('SignerId', $AllowedSigner.SignerId)

            # Append the new AllowedSigner node to the AllowedSigners node of the SigningScenario node with Value 131
            # out-null to prevent console display
            $signingScenario131.ProductSigners.AllowedSigners.AppendChild($NewAllowedSigner) | Out-Null
        }

        # Remove the SigningScenario node with Value 12 from the XML document
        # out-null to prevent console display
        $Xml.SiPolicy.SigningScenarios.RemoveChild($signingScenario12) | Out-Null
    }

    # Remove Signing Scenario 12 block only if it exists and has no allowed signers (i.e. is empty)
    if ($signingScenario12 -and $AllowedSigners12.count -eq 0) {
        # Remove the SigningScenario node with Value 12 from the XML document
        $Xml.SiPolicy.SigningScenarios.RemoveChild($signingScenario12)
    }

    # Save the modified XML document to a new file
    $Xml.Save($FilePath)
}

# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'Move-UserModeToKernelMode'

# SIG # Begin signature block
# MIILhgYJKoZIhvcNAQcCoIILdzCCC3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC83txXBhn2JeBL
# DPm+MYe9bYVtiLnIbgwTbw2FzDtCf6CCB88wggfLMIIFs6ADAgECAhNUAAAABzgp
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
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgtEtBx7NVAZYE
# DY5Bo9uL1Tf5f78NMnYkfZJhJYdjMogwDQYJKoZIhvcNAQEBBQAEggIAmuEnGowg
# QDu6PzcPiOqleOloLHnGSQPipuKYlpXvgqhlbhirKLhHr9JUVdh4mVUQngYaK6qS
# Rv6M1GpN4QGnPnjKQkgvUjWxcXbV8x/Y48+O61WW1uQWcZSPVUuw6ZKGTpHPacPe
# jmzESqY45nSW4cY2hvk5SzZBV6TnuKZVkxt/sy+ydTsaesDm1b73Y1yusKFWRkVX
# /96GIlW54blyX+XPhZbIKNjmtYNcCBWDQo9PSLUfpUV8n1aAiBvZROkkFtDRtbJB
# uRHNXSQcyUJXMMMXqrZto8tZgSIye0UPrJjy3IxSGlQ5L/tdSE+EE4P1ha6U6OgO
# 9xvqxSI0oOZKb3ROo9mXl/exAMMsehxLwiw1cgt55NRBzSDrZUWl9vS4GgvcYZom
# pb3BWHe5rb7y3K6E69BN4v3eHHFiOKwwPYlEhU3Z1222EV2BkTiF0txh+1I72Ct7
# qp3twailfQeln7oCAuNPUDC98VJcSXYepGzhcCdBy6T/vAKRcocLleFWG/GEvz6h
# CrVcLn7Hy3ZEM7Dqtg85gzdyh1P7VbAIOLOLXs7HcfStc9xMaIEGaaVoPUVx8N0h
# AyIdAFY2+l1gmSky/yoXBuRBa87dAk3n/ziFVYHZVk/AVtPH3Go+jh/1r1ApPxjr
# NDCoQd7SLFesXqosJh5+ZOFQ21q3zWshN/U=
# SIG # End signature block
