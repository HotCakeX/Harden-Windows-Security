Function New-AppxPackageCiPolicy {
    <#
    .SYNOPSIS
        Creates a WDAC policy file for Appx packages
    .DESCRIPTION
        This function creates a WDAC policy file for Appx packages based on the logs that contain the PackageFamilyName property
        It needs to receive Code Integrity Operational logs as input
        It then checks whether any of the logs contain the PackageFamilyName property and if so, it creates a policy file for each unique PackageFamilyName
    .NOTES
        The function that calls this function should be able to handle the output object
        By checking whether the PolicyPath property is null or not, meaning the policy could not be created because no PackageFamilyName property was found in any of the logs
        or the PackageFamilyName property was found but the app is not installed on the system and as a result the version could not be detected

        The calling function should also be able to handle the RemainingLogs property which contains the logs that were not used in the policy file
        And create hash rules for them since they are kernel protected files.
    .PARAMETER Logs
        The event logs to create the policy file from
    .PARAMETER DirectoryPath
        The path to the directory to store the policy file
    .INPUTS
        PSCustomObject[]
        System.IO.DirectoryInfo
    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$Logs,

        [Parameter(Mandatory = $true)]
        [System.IO.DirectoryInfo]$DirectoryPath
    )
    Begin {
        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        Write-Verbose -Message 'New-AppxPackageCiPolicy: Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\New-EmptyPolicy.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-RuleRefs.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-FileRules.psm1" -Force

        # The object to return
        $OutputObject = [PSCustomObject]@{
            PolicyPath    = $null
            RemainingLogs = $null
        }

        # The path to the Appx package WDAC Policy file
        [System.IO.FileInfo]$AppxKernelProtectedPolicyPath = (Join-Path -Path $DirectoryPath -ChildPath "AppxPackageKernelCiPolicy $(Get-Date -Format "MM-dd-yyyy 'at' HH-mm-ss").xml")
    }
    Process {
        # Only select the logs that have the PackageFamilyName property
        [PSCustomObject[]]$LogsWithAppxPackages = $Logs | Where-Object -FilterScript { $null -ne $_.'PackageFamilyName' }

        if ($null -eq $LogsWithAppxPackages) {
            Write-Verbose -Message 'New-AppxPackageCiPolicy: No PackageFamilyName property were found in any of the logs'
            return $OutputObject
        }

        # Get the unique PackageFamilyName values since only one rule is needed for each Appx Package (aka game, app etc.)
        [PSCustomObject[]]$LogsWithAppxPackagesUnique = $LogsWithAppxPackages | Group-Object -Property PackageFamilyName | ForEach-Object -Process { $_.Group[0] }

        # Replace the version for the Appx package in the log with the correct version that is available for the installed app on the system
        # If the app is not installed on the system then assign the version to Null and do not create rules for it
        foreach ($Appx in $LogsWithAppxPackagesUnique) {

            $PossibleVersion = [System.Version](Get-AppxPackage | Where-Object { $_.PackageFamilyName -eq $Appx.PackageFamilyName }).Version

            # If the version is not null, empty or whitespace then assign it to the FileVersion property of the Appx package
            if (-NOT [System.String]::IsNullOrWhiteSpace($PossibleVersion)) {
                $Appx.FileVersion = [System.Version]$PossibleVersion
                Write-Verbose -Message "New-AppxPackageCiPolicy: The version of the Appx package $($Appx.PackageFamilyName) is $($Appx.FileVersion) and will be used in the policy file"
            }
            # Otherwise, assign the version to Null
            else {
                $Appx.FileVersion = $null
                Write-Verbose -Message "New-AppxPackageCiPolicy: The Appx package $($Appx.PackageFamilyName) is not installed on the system"
            }
        }

        # Define 2 arrays that hold File rules and RuleRefs for use in the empty policy to generate the Appx package policy file
        [System.String[]]$FileAttribArray = @()
        [System.String[]]$RuleRefsArray = @()

        # Create the File rules and RuleRefs for each Appx package
        $LogsWithAppxPackagesUnique | Where-Object -FilterScript { $null -ne $_.FileVersion } | ForEach-Object -Begin { $i = 1 } -Process {
            $FileAttribArray += Write-Output -InputObject "`n<Allow ID=`"ID_ALLOW_A_$i`" FriendlyName=`"$($_.'PackageFamilyName') Filerule`" MinimumFileVersion=`"0.0.0.0`" PackageFamilyName=`"$($_.PackageFamilyName)`" PackageVersion=`"$([System.String]$_.FileVersion)`" />"
            $RuleRefsArray += Write-Output -InputObject "`n<FileRuleRef RuleID=`"ID_ALLOW_A_$i`" />"
            $i++
        }

        # Create the Appx package policy file
        New-EmptyPolicy -RulesContent $FileAttribArray -RuleRefsContent $RuleRefsArray | Out-File -FilePath $AppxKernelProtectedPolicyPath -Force

        # Assign the path of the Appx package policy file to the PolicyPath property of the output object
        $OutputObject.PolicyPath = $AppxKernelProtectedPolicyPath

        # Check if there are any logs left that are not used in the policy file
        # These logs either did not have the PackageFamilyName property
        # or the app is not installed on the system and as a result the version was set to null
        $OutputObject.RemainingLogs = $Logs | Where-Object -FilterScript { ($LogsWithAppxPackages -notcontains $_) -and ($null -eq $_.FileVersion) }
    }
    End {
        Return $OutputObject
    }
}
Export-ModuleMember -Function 'New-AppxPackageCiPolicy'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAng320/Ertmn5C
# uwaHPzhu693zGAsEGsGWOH2fo+TY26CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgXsIPT7IsLqmepKNGQw+X+uTF0mQDPz8JZV8ZYWQW5C4wDQYJKoZIhvcNAQEB
# BQAEggIAWSKnvZDMBCs8niB56rbJT3ywQLG922rnul0cC5Vci+YnmodJwI1PQZKU
# PDJvPi9lYgx6AUE17VsN6+A7KJd6KAy7TAmS4zizwIi3tvhMGATfGN2PI+4QfxZL
# Pfn4U3czdfjH0KT++3V3RyZywvjJt0VdGkta/ktnQ1WbNXc2inmqsjuZJphfMWw1
# HXH0QJdC42q7WAf1U6Z5B4ORgTBwG9Z9iF6+/VZXKE08a2hw8RPk2cZYbxVj4qgI
# G+rDcQ7zMXR+h1DPsnw2xUX8fxRwvL02VTh6IYaY1zRvttSTIEYWGZWZ3+KkPZDb
# Uw1wi7ytnEYZYtFVMYuyq3vQkKEUt0rr6J9pGPGCpZ1ZiR12cH2HYvtZ6oeviBRO
# MQDZfTFgGR6zYrUHj5gUzocaAnFPYphiUAycVq1UjJSYbxb4eAMlIRh3Yml9E2uA
# kqRpDtvjPu+dhma8wHxdqgaQ+ZP7r78YKzzH69oOicRn7KaJdnIzfl7REnvMkzCT
# VqW3mZWBFmU1feSRUlPVOApNN0/mBFiH7lM2tvU4xRMSmmnxywvyCgBdV6yVKJ9B
# lShbdJT/JdVES10ZDte+P4wbcxYvrasZkrzbOHXvFYar4/UrEMMyCkkoSWV/oFds
# w0InFRmJRvIbjNWGAYo8vIeKCkuq+fqdp/QSFaQ7/qVXN1mNNwM=
# SIG # End signature block
