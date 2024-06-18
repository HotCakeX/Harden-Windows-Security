Function Optimize-MDECSVData {
    <#
        .SYNOPSIS
            Optimizes the MDE CSV data by adding the nested properties in the "AdditionalFields" property to the parent record as first-level properties
        .DESCRIPTION
            The function runs each CSV file in parallel for fast processing based on the number of CPU cores available
        .PARAMETER CSVPaths
            The path to the CSV file containing the Microsoft Defender for Endpoint Advanced Hunting data
        .PARAMETER Debug
            A switch parameter to enable debugging actions such as exporting the new array to a CSV file
        .PARAMETER StagingArea
            The path to the directory where the debug CSV file will be saved which are the outputs of this function
        .INPUTS
            System.IO.FileInfo[]
        .OUTPUTS
            System.Collections.Hashtable[]
        #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable[]])]
    Param (
        [Parameter(Mandatory = $true)][System.IO.FileInfo[]]$CSVPaths,
        [Parameter(Mandatory = $true)][System.IO.DirectoryInfo]$StagingArea
    )
    Begin {
        [System.Boolean]$Debug = $PSBoundParameters.Debug.IsPresent ? $true : $false
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        Try {
            # Get the number of enabled CPU cores
            $CPUEnabledCores = [System.Int64](Get-CimInstance -ClassName Win32_Processor -Verbose:$false).NumberOfEnabledCore
        }
        Catch {
            Write-Verbose -Message 'Optimize-MDECSVData: Unable to detect the number of enabled CPU cores, defaulting to 5...'
        }
    }

    Process {

        # Create a new HashTable array to hold the updated data from the original CSVs
        [System.Collections.Hashtable[]]$NewCsvData = $CSVPaths | ForEach-Object -ThrottleLimit ($CPUEnabledCores ?? 5) -Parallel {

            # Read the initial MDE AH CSV export and save them into a variable
            [System.Object[]]$CsvData += Import-Csv -Path $_

            # Add the nested properties in the "AdditionalFields" property to the parent record as first-level properties
            foreach ($Row in $CsvData) {

                # Create a new HashTable for the combined data
                [System.Collections.Hashtable]$CurrentRowHashTable = @{}

                # For each row in the CSV data, create a new object to hold the updated properties, except for the "AdditionalFields" property
                foreach ($Property in $Row.PSObject.Properties) {
                    if ($Property.Name -ne 'AdditionalFields') {
                        $CurrentRowHashTable[$Property.Name] = $Property.Value
                    }
                }

                # Convert the AdditionalFields JSON string to a HashTable
                [System.Collections.Hashtable]$JsonConverted = $Row.AdditionalFields | ConvertFrom-Json -AsHashtable

                # Add each Key/Value pairs from the additional fields HashTable to the CurrentRow HashTable
                foreach ($Item in $JsonConverted.GetEnumerator()) {
                    $CurrentRowHashTable[$Item.Name] = $Item.Value
                }

                # Send the new HashTable to the pipeline to be saved in the HashTable Array
                [System.Collections.Hashtable]$CurrentRowHashTable
            }
        }
    }

    End {

        if ($Debug) {

            Write-Verbose -Message 'Optimize-MDECSVData: Debug parameter was used, exporting the new array to a CSV file...'

            # Initialize a HashSet to keep track of all property names (aka keys in the HashTable Array)
            $PropertyNames = [System.Collections.Generic.HashSet[System.String]] @()

            # Loop through each HashTable's keys in the new updated CSV data to find and add any new key names to the list that are not already present
            # These are the property names from the AdditionalFields
            foreach ($Obj in $NewCsvData.Keys) {
                if (-NOT $PropertyNames.Contains($Obj)) {
                    $PropertyNames += $Obj
                }
            }

            # Export the new array to a CSV file containing all of the original properties and the new properties from the AdditionalFields
            # guarantees that no property gets lost during CSV export
            $NewCsvData | Select-Object -Property $PropertyNames | Export-Csv -Path (Join-Path -Path $StagingArea -ChildPath 'Pass1.csv') -Force
        }

        Return $NewCsvData
    }
}
Export-ModuleMember -Function 'Optimize-MDECSVData'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCkFwypNcqB4koG
# rfO6TuBdJYhS+tywkergBshqFhd42aCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQglZ8vwPYgwZdWgqL2QD9jkNrs63TDoit6lxZ0WCZPia8wDQYJKoZIhvcNAQEB
# BQAEggIAPkT4LmU7OGJQWFeHQQgzVblZBxE/WWyWspFgg7gDrIESBfyW+OyfbIiJ
# r8GPXhIUCvXMY0sHhpP2Z1sqIu8ER3L0cPcF4dVVKVUe2Sysd1RgExA6VH+Cmf/I
# shfBeyI5858xfkajRyTXVgtldwfF/Kc78WAuZpj1GnORWbU8zrD1EFrcFwDgy8uz
# cKxp2/IFVwpcg5umB5JQ9DZCVu9g6CS8BnXlpCvBx6r/DGxIWPgsjNk7DvmSFcJa
# 6MPSf/tDyLdGjscXLCkxjv3UconvDLztPmYW1F5x10TVXwoNaz2dUyPoGaXPCUfM
# 5+BCJV2oEPSOx/r85ldABUv8rpnORUmazLDDVB/WWQT89B+9IoQiWe8u4FCinhs/
# lhbWIlvYBctqJCVC04unCwd4hGWxZ1NoEA9t4WMFagud4XbRa2E2daFTSSgdYqiL
# XsJC8BVwNNrCYkjPVW/aOE5CB5iGQGnAoDRmU/5WgccRYhSHUjlN2krgXHoq+DIG
# exuQQyNkf6ru3bY+5v2T4aZOsDiXUNyIv1la9Bi6yWpC++TwW3DdOA2adDHNntTj
# AZo9HMhYwlsgPCW9BcTER36hxYcxQXGlD+cGBSEXi4L+i26gJV6aLVbo8IpxB8hw
# 2fz2zcHtPcDSRmmbWoCB++4qxWE/vxNqP2/eIVRjVPMGsgUr8R4=
# SIG # End signature block
