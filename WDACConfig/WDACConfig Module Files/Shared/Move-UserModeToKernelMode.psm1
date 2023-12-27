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
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC83txXBhn2JeBL
# DPm+MYe9bYVtiLnIbgwTbw2FzDtCf6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgtEtBx7NVAZYEDY5Bo9uL1Tf5f78NMnYkfZJhJYdjMogwDQYJKoZIhvcNAQEB
# BQAEggIAIIKKJ786J3PKzJnxJ2YPL9WeXKgVPUYyG30zKvlAV6XusoRkZmn2wDbp
# zwlmcPTcjrgFmFMaTDKmvDlLDO/rJtcdgtmOPSp0Era6pKyESY8Mcry5t+WwgKOA
# K/CEB2qRoT9gFDEASj+rN0vaajEcWELQuL3xMmJh7il0i/KfJcrBTm4hcuxd8599
# PacKbS3tL8LHT1oWlMWyPqIA1SAqV0X0k7jy2Unqy21qmnaQhIuo7SLk9DixOCF2
# dV2/D2AUubWFP6IceXx4lM8TUIUfZx3TZlOUg1eyxJXQF/5yz5BpfFPf3mHU5JLR
# g3VoMms9eXfNM14nn5Qe5AVNrlUK+e6hYFqA8pdnzW89Ci3+UcleFvLAQXFHDdIk
# s5sm7294pj06fjhwSEmGtRVC4Imhlry5AArlHYMy7lMm2ooiHUTd2OK7W/0L9qzO
# 7RwMqQVt7JdLm+0SOqMZghlcmolVheipkRh+hGTG88wtqQ0lAEoc1+kyEuRxO7/b
# exqQK/CQ4ORouZMy6t1vWCGcbRXfqPBoATBZfzbeqqDkS+qkjbJt5wjTK3iKlR6r
# w/2Upm5yyYJfk0BKp9rvZmJ4fwlJV+oO850E3dGjfYa3l4q0YFEL9eC0+CisR3BX
# dZxYJOv8BTpuR3paEELwN8zSLLf2Zf6xw/2YslSJNcPblKq+r2E=
# SIG # End signature block
