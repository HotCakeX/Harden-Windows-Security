Function Confirm-CertCN {
    <#
    .SYNOPSIS
        Function to check Certificate Common name - used mostly to validate values in UserConfigurations.json
    .PARAMETER CN
        Common name of the certificate to check
    .INPUTS
        System.String
    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [System.String]$CN
    )
    # Importing the $PSDefaultParameterValues to the current session, prior to everything else
    . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

    # Create an empty array to store the output objects
    [System.Object[]]$Output = @()

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

        # Create a custom object with the certificate thumbprint, subject, friendly name and subject CN
        $Output += [PSCustomObject]@{
            Thumbprint   = [System.String]$Cert.Thumbprint
            Subject      = [System.String]$Cert.Subject
            FriendlyName = [System.String]$Cert.FriendlyName
            SubjectCN    = [System.String]$SubjectCN
        }
    }

    return [System.Boolean]([System.String[]]$Output.SubjectCN -contains $CN ? $true : $false)
}

# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'Confirm-CertCN'

# SIG # Begin signature block
# MIILhgYJKoZIhvcNAQcCoIILdzCCC3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC2VdHP4wCDZGkL
# CmEU/g4CZRbnceVzhVeRbvSWYaqwE6CCB88wggfLMIIFs6ADAgECAhNUAAAABzgp
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
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg/QX2OiJ8an2N
# OIBQh9Cw4REo8swetC4l7QjvNaG/L/cwDQYJKoZIhvcNAQEBBQAEggIArHtHiarm
# kbXaMA8iXrB7+c9IvrP+u5Q9bA3RtJ5EgST11s/YXisuHwemiZ/mHhmnwxLhnC4R
# PGZD9jhsJiz/qHiWAMM4kW4qFW7188RBVMnjsWlMh9uUiwoW3bryI7q3Rwg3zTea
# RKfmqNzFY1Xp0fvA6qNrrqeBOyJTbT87o1GCjuek9gQY++yIYiB5pepC+eH+gIBG
# AEAtJkBmjcKZr/wVXDG8cV59xXC/ivl9EOp+D8XS0IV71WfYpup3bX7itNIXqnqk
# RUI8aqnrXMoZaNmwLC64Ova6PJVsFFqgPQOdauD2psNK2zMlgGZ2i+ap3qtkGIsG
# MwXOZpo2x9y1g7k0zX/p3QFaMGCswo3GhrWxEsIR9eiGXELINy/9Lr6vZEnC+vtw
# T0rBGkWuoeJ8fSDcMafWQQT3SzaWttwB5H2nq1NCeIGdKIdeKp2y95IvZDhesIyv
# nPSvmT3D7eFQMRXzA0FCZljvY0znKNed02oNwoG/kz7hyjfVC+e71skSnjwj6jou
# aDvLsuaM0C7YvMsN6IKdl3EvilsYv7zxlh5KABuNnvL/UUn+XcnP7GvwCySPWOyt
# k1bpgzzXYq2HrL+tMXk/MTXU/cocKKpffZzNstrcbkoFb+XTOdMCrXHjP8papDKF
# lvoYrvxPRjo6dbrrpOYaXnpAmTEroiMewFI=
# SIG # End signature block
