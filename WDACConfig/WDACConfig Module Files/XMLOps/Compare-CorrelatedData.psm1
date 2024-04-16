Function Compare-CorrelatedData {
    <#
    .SYNOPSIS
        Finds the correlated events in the new CSV data and groups them together based on the EtwActivityId
        Ensures that each Audit or Blocked event has its correlated Signing information events grouped together as nested HashTables

        The correlated data of each log is unique based on 4 main properties, Publisher TBS and name, Issuer TBS and name

        The output of this function does not contain duplicates. Neither duplicate files nor duplicate signer information for each file.

        If 2 logs for the same file exist and one of them contains the signing information while the other one doesn't, the one with signing information is kept.
    .PARAMETER OptimizedCSVData
        The CSV data to be processed, they should be the output of the Optimize-MDECSVData function
    .PARAMETER StagingArea
        The path to the directory where the debug CSV file will be saved which are the outputs of this function
    .PARAMETER Debug
        A switch parameter to enable debugging actions such as exporting the correlated event data to a JSON file
    .PARAMETER StartTime
        A DateTime object that specifies the start time of the logs to be processed. If this parameter is not specified, all logs will be processed.
    .PARAMETER PolicyNamesToFilter
        An array of strings that specifies the policy names to filter the logs by. If this parameter is not specified, all logs will be processed.
    .PARAMETER LogType
        A string that specifies the type of logs to process. The only valid values are 'Audit' and 'Blocked'
    .INPUTS
        System.Collections.Hashtable[]
        System.DateTime
        System.String[]
        System.String
    .OUTPUTS
        System.Collections.Hashtable
        #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    Param (
        [Parameter(Mandatory = $true)][System.Collections.Hashtable[]]$OptimizedCSVData,
        [Parameter(Mandatory = $true)][System.IO.DirectoryInfo]$StagingArea,
        [Parameter(Mandatory = $false)][System.DateTime]$StartTime,
        [AllowNull()]
        [Parameter(Mandatory = $false)][System.String[]]$PolicyNamesToFilter,
        [ValidateSet('Audit', 'Blocked')]
        [Parameter(Mandatory = $true)][System.String]$LogType
    )

    Begin {
        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Detecting if Debug switch is used
        $PSBoundParameters.Debug.IsPresent ? ([System.Boolean]$Debug = $true) : ([System.Boolean]$Debug = $false) | Out-Null

        # Group the events based on the EtwActivityId, which is the unique identifier for each group of correlated events
        [Microsoft.PowerShell.Commands.GroupInfo[]]$GroupedEvents = $OptimizedCSVData | Group-Object -Property EtwActivityId

        Write-Verbose -Message "Compare-CorrelatedData: Total number of groups: $($GroupedEvents.Count)"

        # Create a collection to store the packages of logs to return at the end
        [System.Collections.Hashtable]$EventPackageCollections = @{}
    }

    Process {

        # Loop over each group of logs
        Foreach ($RawLogGroup in $GroupedEvents) {

            # Store the group data in a HashTable array
            [System.Collections.Hashtable[]]$GroupData = $RawLogGroup.Group

            if ($StartTime) {
                try {
                    # Try to prase the TimeStamp string as DateTime type
                    [System.DateTime]$CurrentEventTimeStamp = [System.DateTime]::Parse((($GroupData.Timestamp) | Select-Object -First 1))

                    # If the current log's TimeStamp is older than the time frame specified by the user then skip this iteration/log completely
                    if ($CurrentEventTimeStamp -lt $StartTime ) {
                        Continue
                    }
                }
                Catch {
                    Write-Verbose -Message "Event Timestamp for the file '$($GroupData.FileName)' was invalid"
                }
            }

            # Detect the Audit events only if the LogType parameter is set to 'Audit'
            if ($LogType -eq 'Audit') {

                # Process Audit events for Code Integrity and AppLocker
                if (($GroupData.ActionType -contains 'AppControlCodeIntegrityPolicyAudited') -or ($GroupData.ActionType -contains 'AppControlCIScriptAudited')) {

                    # Create a temporary HashTable to store the main event, its correlated events and its type
                    [System.Collections.Hashtable]$TempAuditHashTable = @{
                        CorrelatedEventsData = @{}
                        Type                 = 'Audit'
                        SignatureStatus      = ''
                    }

                    # Finding the main Audit event in the group
                    # Only selecting the first event because when multiple Audit policies of the same type are deployed on the system, they same event is generated for each of them
                    [System.Collections.Hashtable]$AuditTemp = $GroupData |
                    Where-Object -FilterScript { $_['ActionType'] -in ('AppControlCodeIntegrityPolicyAudited', 'AppControlCIScriptAudited') } | Select-Object -First 1

                    # If the user provided policy names to filter the logs by
                    if ($null -ne $PolicyNamesToFilter) {
                        # Skip this iteration if the policy name of the current log is not in the list of policy names to filter by
                        if ($AuditTemp.PolicyName -notin $PolicyNamesToFilter) {
                            Continue
                        }
                    }

                    # Generating a unique key for the hashtable based on file's properties
                    [System.String]$UniqueAuditMainEventDataKey = $AuditTemp.FileName + '|' + $AuditTemp.SHA256 + '|' + $AuditTemp.SHA1 + '|' + $AuditTemp.FileVersion

                    # Adding the main event to the temporary HashTable, each key/value pair
                    foreach ($Data in $AuditTemp.GetEnumerator()) {
                        $TempAuditHashTable[$Data.Key] = $Data.Value
                    }

                    # Looping over the signer infos and adding the unique publisher/issuer pairs to the correlated events data
                    foreach ($SignerInfo in ($GroupData | Where-Object -FilterScript { $_.ActionType -eq 'AppControlCodeIntegritySigningInformation' })) {

                        # If the PublisherTBSHash or IssuerTBSHash is null, skip this iteration, usually in these situations the Issuer name and Publisher names are set to 'unknown'
                        if (($null -eq $SignerInfo.PublisherTBSHash) -or ($null -eq $SignerInfo.IssuerTBSHash)) {
                            Continue
                        }

                        [System.String]$UniqueAuditSignerKey = $SignerInfo.PublisherTBSHash + '|' +
                        $SignerInfo.PublisherName + '|' +
                        $SignerInfo.IssuerName + '|' +
                        $SignerInfo.IssuerTBSHash

                        if (-NOT $TempAuditHashTable['CorrelatedEventsData'].Contains($UniqueAuditSignerKey)) {
                            $TempAuditHashTable['CorrelatedEventsData'][$UniqueAuditSignerKey] = $SignerInfo
                        }
                    }

                    # Determining whether this log package is signed or unsigned
                    $TempAuditHashTable['SignatureStatus'] = $TempAuditHashTable.CorrelatedEventsData.Count -eq 0 ? 'Unsigned' : 'Signed'

                    # Check see if the main hashtable already contains the same file (key)
                    if ($EventPackageCollections.ContainsKey($UniqueAuditMainEventDataKey)) {

                        # If it does, check if the current log is signed and the main log is unsigned
                        if (($EventPackageCollections[$UniqueAuditMainEventDataKey]['SignatureStatus'] -eq 'Unsigned') -and ($TempAuditHashTable['SignatureStatus'] -eq 'Signed')) {

                            Write-Debug -Message "The unsigned log of the file $($TempAuditHashTable['FileName']) is being replaced with its signed log."

                            # Remove the Unsigned log from the main HashTable
                            $EventPackageCollections.Remove($UniqueAuditMainEventDataKey)

                            # Add the current Audit event with a unique identifiable key to the main HashTable
                            # This way we are replacing the Unsigned log with the Signed log that has more data, for the same file, providing the ability to create signature based rules for that file instead of hash based rule
                            $EventPackageCollections[$UniqueAuditMainEventDataKey] += $TempAuditHashTable
                        }
                    }
                    else {
                        # Add the current Audit event with a unique identifiable key to the main HashTable
                        $EventPackageCollections[$UniqueAuditMainEventDataKey] += $TempAuditHashTable
                    }
                }
            }

            # Detect the blocked events only if the LogType parameter is set to 'Blocked'
            if ($LogType -eq 'Blocked') {

                # Process Blocked events for Code Integrity and AppLocker
                if (($GroupData.ActionType -contains 'AppControlCodeIntegrityPolicyBlocked') -or ($GroupData.ActionType -contains 'AppControlCIScriptBlocked')) {

                    # Create a temporary HashTable to store the main event, its correlated events and its type
                    [System.Collections.Hashtable]$TempBlockedHashTable = @{
                        CorrelatedEventsData = @{}
                        Type                 = 'Blocked'
                        SignatureStatus      = ''
                    }

                    # Finding the main block event in the group
                    # Only selecting the first event because when multiple enforced policies of the same type are deployed on the system, they same event might be generated for each of them
                    [System.Collections.Hashtable]$BlockedTemp = $GroupData |
                    Where-Object -FilterScript { $_['ActionType'] -in ('AppControlCodeIntegrityPolicyBlocked', 'AppControlCIScriptBlocked') } | Select-Object -First 1

                    # If the user provided policy names to filter the logs by
                    if ($null -ne $PolicyNamesToFilter) {
                        # Skip this iteration if the policy name of the current log is not in the list of policy names to filter by
                        if ($BlockedTemp.PolicyName -notin $PolicyNamesToFilter) {
                            Continue
                        }
                    }

                    # Generating a unique key for the hashtable based on file's properties
                    [System.String]$UniqueBlockedMainEventDataKey = $BlockedTemp.FileName + '|' + $BlockedTemp.SHA256 + '|' + $BlockedTemp.SHA1 + '|' + $BlockedTemp.FileVersion

                    # Adding the main event to the temporary HashTable, each key/value pair
                    foreach ($Data in $BlockedTemp.GetEnumerator()) {
                        $TempBlockedHashTable[$Data.Key] = $Data.Value
                    }

                    # Looping over the signer infos and adding the unique publisher/issuer pairs to the correlated events data
                    foreach ($SignerInfo in ($GroupData | Where-Object -FilterScript { $_.ActionType -eq 'AppControlCodeIntegritySigningInformation' })) {

                        # If the PublisherTBSHash or IssuerTBSHash is null, skip this iteration, usually in these situations the Issuer name and Publisher names are set to 'unknown'
                        if (($null -eq $SignerInfo.PublisherTBSHash) -or ($null -eq $SignerInfo.IssuerTBSHash)) {
                            Continue
                        }

                        [System.String]$UniqueBlockedSignerKey = $SignerInfo.PublisherTBSHash + '|' +
                        $SignerInfo.PublisherName + '|' +
                        $SignerInfo.IssuerName + '|' +
                        $SignerInfo.IssuerTBSHash

                        if (-NOT $TempBlockedHashTable['CorrelatedEventsData'].Contains($UniqueBlockedSignerKey)) {
                            $TempBlockedHashTable['CorrelatedEventsData'][$UniqueBlockedSignerKey] = $SignerInfo
                        }
                    }

                    # Determining whether this log package is signed or unsigned
                    $TempBlockedHashTable['SignatureStatus'] = $TempBlockedHashTable.CorrelatedEventsData.Count -eq 0 ? 'Unsigned' : 'Signed'

                    # Check see if the main hashtable already contains the same file (key)
                    if ($EventPackageCollections.ContainsKey($UniqueBlockedMainEventDataKey)) {

                        # If it does, check if the current log is signed and the main log is unsigned
                        if (($EventPackageCollections[$UniqueBlockedMainEventDataKey]['SignatureStatus'] -eq 'Unsigned') -and ($TempBlockedHashTable['SignatureStatus'] -eq 'Signed')) {

                            Write-Debug -Message "The unsigned log of the file $($TempBlockedHashTable['FileName']) is being replaced with its signed log."

                            # Remove the Unsigned log from the main HashTable
                            $EventPackageCollections.Remove($UniqueBlockedMainEventDataKey)

                            # Add the current Audit event with a unique identifiable key to the main HashTable
                            # This way we are replacing the Unsigned log with the Signed log that has more data, for the same file, providing the ability to create signature based rules for that file instead of hash based rule
                            $EventPackageCollections[$UniqueBlockedMainEventDataKey] += $TempBlockedHashTable
                        }
                    }
                    else {
                        # Add the current Audit event with a unique identifiable key to the main HashTable
                        $EventPackageCollections[$UniqueBlockedMainEventDataKey] += $TempBlockedHashTable
                    }
                }
            }
        }
    }

    End {

        if ($Debug) {
            Write-Verbose -Message 'Compare-CorrelatedData: Debug parameter was used, exporting data to Json...'

            # Outputs the entire data to a JSON file for debugging purposes with max details
            $EventPackageCollections | ConvertTo-Json -Depth 100 | Set-Content -Path (Join-Path -Path $StagingArea -ChildPath 'Pass2.Json') -Force
        }

        Return $EventPackageCollections
    }
}
Export-ModuleMember -Function 'Compare-CorrelatedData'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC4U8how5q7ZEkr
# agzaF3Sfxg7+UTeCemF9BEQIH+diD6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgL+mDBytP9xDjH4CUX3CFufyVJmEZqt2BOv63SEo59JkwDQYJKoZIhvcNAQEB
# BQAEggIAiTJwhm+hnrevcV21mYV5qqiKmKSOH0pCWjMA9CVQ/lsSgpVaiWimQPLb
# YbRg8JG6IZqVE6C7CY5GuAFVyMVF8C6PbZcAiLIxkdnxt3SRbIbplb3lcE+OsGvM
# EzMQfcfBdIMzOCX4ieif/uqq+zIp97SXlBQd9lmZeafbqNIpvr4E3uVtLURlxkLz
# guF0jaqjzn7PDItkiJGYwn5fmB4VP7hDPtILi8K2aEhx7x2d+ECMlZgU2s/hBfq1
# dR3O5qQLVZ89qy8ObVWh77V4j6CFb8gXq4f8+YZntEgw9dXONwaepZgS7El5rB1M
# ZRhONWppQrscSSmZNfSPSAvF7bIZ/QsFLwziyLgKD5zbQJdE0M75i6VggFwYMckf
# z/ACki0tCLuMNf0y9622Y2MWKNfMHhEL4gCfAwnjuI67sOl1isg2OcvbMsrErAhK
# 0JS7yJPwvGoMhusTc5rEq32vAJjyL8odmD5Npk+ww2l6ZZFz2bi2TyMJFgbaq3kp
# Ixp8tcLWZH6VFZMlZsgH4sdC1ajwxcGOdynfpZdSJRL4flBZSph1+JhJuHBWtwkS
# nmDvekGrbtiQCCZrhUDs+ztPwTMACGuRVBDbiQw7iwT5/h2T4iaGxMjnhIFyIcr7
# PJ5DSSdsxs5p0e8y7EA+XuKAw+2VWKqfTKOS4v/zwB8iGbj9WwY=
# SIG # End signature block
