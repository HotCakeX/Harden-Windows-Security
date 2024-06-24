Function Get-KernelModeDrivers {
    <#
    .SYNOPSIS
        Gets the path of all of the kernel-mode drivers from the system
    .DESCRIPTION
        The output of this function is completely based on the ConfigCI module's workflow.
        It checks the same locations that the ConfigCI checks for .sys files and kernel-mode DLLs

        It even returns the same kernel-mode dll files from System32 folder that the (Get-SystemDriver -ScanPath 'C:\Windows\System32') command does

        The output of the function can only contain DLL and SYS files
    .NOTES
        If not parameter is used, the function scans the local system for drivers
    .PARAMETER Directory
        The directory paths to scan for kernel-mode drivers
    .PARAMETER File
        The file paths to scan for kernel-mode drivers
    .INPUTS
        System.IO.DirectoryInfo[]
        System.IO.FileInfo[]
    .OUTPUTS
        System.String[]
     #>
    [CmdletBinding()]
    [OutputType([System.String[]])]
    Param (
        [ValidateScript({ Test-Path -Path $_ -PathType 'Container' })]
        [Parameter(Mandatory = $False)][System.IO.DirectoryInfo[]]$Directory,
        [ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' })]
        [Parameter(Mandatory = $False)][System.IO.FileInfo[]]$File
    )
    Begin {
        # Import the ConfigCI assembly resources if they are not already imported
        if (-NOT ('Microsoft.SecureBoot.UserConfig.ImportParser' -as [System.Type]) ) {
            Write-Verbose -Message 'Importing the ConfigCI assembly resources'
            Add-Type -Path ([System.String](PowerShell.exe -Command { (Get-Command -Name Merge-CIPolicy).DLL }))
        }

        Function Test-UserPE {
            <#
             .SYNOPSIS
                This function tests if a DLL is a user-mode PE
             #>
            Param (
                [AllowNull()]
                [System.String[]]$Imports
            )

            if ($null -eq $Imports) {
                return $False
            }
            # If any of these DLLs are found in the imports list, the method return true, indicating that the file is likely a user-mode PE
            elseif (($Imports -icontains 'kernel32.dll') -or ($Imports -icontains 'kernelbase.dll') -or ($Imports -icontains 'mscoree.dll') -or ($Imports -icontains 'ntdll.dll') -or ($Imports -icontains 'user32.dll')) {
                return $true
            }
            else {
                return $False
            }
        }

        function Get-FolderDllKernelDrivers {
            <#
             .SYNOPSIS
                Gets the kernel drivers from a directory or file
             #>
            [OutputType([System.String[]], [System.Boolean])]
            param (
                [Parameter(Mandatory = $False)]
                [System.IO.DirectoryInfo]$Directory,
                [System.IO.FileInfo]$File
            )

            if ($Directory) {
                [System.Collections.Generic.List[System.String]]$DllKernelDrivers = @()
                foreach ($File in ([WDACConfig.FileUtility]::GetFilesFast($Directory, $null, '.dll'))) {
                    $HasSIP = $False
                    $IsPE = $False
                    $Imports = [Microsoft.SecureBoot.UserConfig.ImportParser]::GetImports($File.FullName, [ref]$HasSIP, [ref]$IsPE)
                    if ($HasSIP -and -not (Test-UserPE -Imports $Imports)) {
                        $DllKernelDrivers.Add($File.FullName)
                    }
                }
                return $DllKernelDrivers
            }
            elseif ($File) {
                $HasSIP = $False
                $IsPE = $False
                $Imports = [Microsoft.SecureBoot.UserConfig.ImportParser]::GetImports($File.FullName, [ref]$HasSIP, [ref]$IsPE)
                if ($HasSIP -and -not (Test-UserPE -Imports $Imports)) {
                    Return $true
                }
            }
        }

        # Final output variable that includes all kernel-mode driver files
        $DriverFiles = [System.Collections.Generic.HashSet[System.String]]@()

        # List of all potential DLL files
        $PotentialKernelModeDlls = [System.Collections.Generic.HashSet[System.String]]@()

        # This is only used to display extra info
        $KernelModeDlls = [System.Collections.Generic.HashSet[System.String]]@()
    }

    Process {
        # If directory paths were passed by user, add them all to the paths to be scanned
        if ($null -ne $PSBoundParameters['Directory']) {

            # Get the .sys files from the directories
            $DriverFiles.UnionWith([System.String[]]([WDACConfig.FileUtility]::GetFilesFast($PSBoundParameters['Directory'], $null, '.sys')))

            # Get all of the .dll files from the user-selected directories
            $PotentialKernelModeDlls.UnionWith([System.String[]]([WDACConfig.FileUtility]::GetFilesFast($PSBoundParameters['Directory'], $null, '.dll')))
        }
        # If file paths were passed by the user
        elseif ($null -ne $PSBoundParameters['File']) {

            foreach ($FilePath in $PSBoundParameters['File']) {

                Switch (($FilePath).Extension) {
                    '.sys' {
                        [System.Void]$DriverFiles.Add($FilePath)
                        break
                    }
                    '.dll' {
                        if (Get-FolderDllKernelDrivers -File $FilePath) {
                            [System.Void]$DriverFiles.Add($FilePath)
                            break
                        }
                    }
                }
            }

            # Return from the process block after all the user-provided files have been processed
            return
        }
        # If no parameters were passed, scan the system for kernel-mode drivers
        else {
            # Reference: ReadDriverFolders() method in ConfigCI Helper class
            # "$env:SystemRoot\System32\DriverStore\FileRepository"
            # "$env:SystemRoot\System32\drivers"

            # Since there can be more than one folder due to localizations such as en-US then from each of the folders, the bootres.dll.mui file is added
            Foreach ($Path in Get-ChildItem -Directory -Path "$env:SystemDrive\Windows\Boot\Resources") {
                [System.Void]$DriverFiles.Add("$Path\bootres.dll.mui")
            }

            # Get all of the .dll files from the system32 directory
            $PotentialKernelModeDlls.UnionWith([System.String[]]([WDACConfig.FileUtility]::GetFilesFast("$env:SystemRoot\System32", $null, '.dll')))

            # Get the .sys files from the System32 directory
            $DriverFiles.UnionWith([System.String[]]([WDACConfig.FileUtility]::GetFilesFast("$env:SystemRoot\System32", $null, '.sys')))
        }

        Write-Verbose -Message "Number of sys files: $($DriverFiles.Count)"
        Write-Verbose -Message "Number of potential kernel-mode DLLs: $($PotentialKernelModeDlls.Count)"

        # Scan all of the .dll files to see if they are kernel-mode drivers
        foreach ($KernelDll in $PotentialKernelModeDlls) {
            if (Get-FolderDllKernelDrivers -File $KernelDll) {
                [System.Void]$KernelModeDlls.Add($KernelDll)
                [System.Void]$DriverFiles.Add($KernelDll)
            }
        }

        Write-Verbose -Message "Number of kernel-mode DLLs folder: $($KernelModeDlls.Count)"
    }
    End {
        Write-Verbose -Message "Returning $($DriverFiles.Count) kernel-mode driver file paths"
        Return $DriverFiles
    }
}

Export-ModuleMember -Function 'Get-KernelModeDrivers'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBapeBjzHzxVqow
# 1H3Daq0NgAhz7cpaMs9l9LTMtetKAaCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgomEe1VqYnvvitIRoduLzwFSFmDpbHa2b+5E2ckJm6LMwDQYJKoZIhvcNAQEB
# BQAEggIAEUwoxnAWZ7Rsx79FyXu6zI8/ssbrvkf1dRDS4QAIb1+DL1j/nUk8OUIQ
# IhtYlUQNCWJx0+4qw/VnPEWMdHuSjpYGSPHjIPitO7TOrZFtyg5/Cc/l2cTslAX0
# 2G0UcmQxLJazLbQUv6cIDEdMQUhyYj5pROUEBslToy0gVnuVtYVMiL0pZoO3P1Va
# E7mwsKuyEgFQSHc7PyHAA8pVwHTWbx7lWrfPKx3TAJlUciqeMPX1c3fBA4fI3463
# j85W/1/Ijkchiia+Et3Dx2EeO+lrQw4h1fcL8j0U5fs2bx+GUf9slD3IM5fU+Lbh
# dcBgI1SSDutFGW8AFSi6PaSmqdtNuHTHePUdIfWuF37zf8RXlDHnmCBND9kUcF81
# +/+9mQ+AmINUFLqWtm6Uljhauph4BpF+mTifpT7Flpi1uNr4MUAacvZ1RrFrSL7Q
# lONDc7/DHSY/DyPVp9/hZv0aSMGcUatzsJ56F+RLRwlOVqrXQHyiiExO5ekaY5ay
# 52jqclDOxoFzrTKhKVzjoqFdZ34rLp8/fkYck9SXQmNWIoTCJlmuBAd4HqT6ixEu
# B6wkF+A0m2Db391JttnFhLGAhE23ORmcHJnXBpRZDT33yT0lx/L0VWySG1drEdui
# Ax04Ood32s/QbBYbBaYjQuCTvSVBWAmk3kgJZbJJemhg+GDnM6g=
# SIG # End signature block
