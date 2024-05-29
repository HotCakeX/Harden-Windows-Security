Function Get-KernelModeDrivers {
    <#
    .SYNOPSIS
        Gets the path of all of the kerne-mode drivers from the system
    .DESCRIPTION
        The output of this function is completely based on the ConfigCI module's workflow.
        It checks the same locations that the ConfigCI checks for .sys files and

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

        Write-Verbose -Message 'Importing the ConfigCI assembly resources'
        Add-Type -Path ([System.String](PowerShell.exe -Command { (Get-Command -Name Merge-CIPolicy).DLL }))

        Function Test-UserPE {
            <#
             .SYNOPSIS
                 This function tests if a file is a user-mode PE
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
                [System.String[]]$DllKernelDrivers = @()
                foreach ($File in Get-ChildItem -ErrorAction Ignore -File -Recurse -Include '*.dll' -Path $Directory) {
                    $HasSIP = $False
                    $IsPE = $False
                    $Imports = [Microsoft.SecureBoot.UserConfig.ImportParser]::GetImports($File.FullName, [ref]$HasSIP, [ref]$IsPE)
                    if ($HasSIP -and -not (Test-UserPE -Imports $Imports)) {
                        $DllKernelDrivers += $File.FullName
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
        # HashSets used for during the internal processes
        $FilePathsToScan = [System.Collections.Generic.HashSet[System.String]]@()
        $PotentialKernelModeDlls = [System.Collections.Generic.HashSet[System.String]]@()
        $KernelModeDlls = [System.Collections.Generic.HashSet[System.String]]@()
    }

    Process {

        # If directory paths were passed by user, add them all to the paths to be scanned
        if ($null -ne $PSBoundParameters['Directory']) {
            foreach ($DirPath in $PSBoundParameters['Directory']) {
                [System.Void]$FilePathsToScan.Add($DirPath)
            }
        }
        # If file paths were passed by the user
        elseif ($null -ne $PSBoundParameters['File']) {

            foreach ($FilePath in $PSBoundParameters['File']) {

                Switch (($FilePath).Extension) {
                    '.sys' { $DriverFiles.Add($FilePath); break }
                    '.dll' {
                        if (Get-FolderDllKernelDrivers -File $FilePath) {
                            [System.Void]$KernelModeDlls.Add($FilePath)
                            [System.Void]$DriverFiles.Add($FilePath)
                        }
                        break
                    }
                }
            }

            # Return from the process block after all the user-provided files have been processed
            return
        }
        # If no parameters were passed, scan the system for kernel-mode drivers
        else {
            # Reference: ReadDriverFolders() method in ConfigCI Helper class
            # [System.Void]$FilePathsToScan.Add("$env:SystemRoot\System32\DriverStore\FileRepository")
            # [System.Void]$FilePathsToScan.Add("$env:SystemRoot\System32\drivers")
            [System.Void]$FilePathsToScan.Add("$env:SystemRoot\System32")

            # Since there can be more than one folder due to localizations such as en-US then from each of the folders, the bootres.dll.mui file is added
            Foreach ($Path in Get-ChildItem -Directory -Path "$env:SystemDrive\Windows\Boot\Resources") {
                [System.Void]$DriverFiles.Add("$Path\bootres.dll.mui")
            }
        }

        # Get the .sys files from the directories
        Foreach ($DirectoryPath in $FilePathsToScan) {

            # Ignoring errors because of access denied errors
            foreach ($DriverFile in Get-ChildItem -ErrorAction Ignore -File -Include '*.sys' -Recurse -Path $DirectoryPath) {
                [System.Void]$DriverFiles.Add($DriverFile.FullName)
            }
        }

        Write-Verbose -Message "Number of sys files: $($DriverFiles.Count)"

        # Get all of the .dll files from the system32 directory
        Foreach ($DllPath in Get-ChildItem -ErrorAction Ignore -File -Recurse -Include '*.dll' -Path "$env:SystemRoot\System32\") {
            [System.Void]$PotentialKernelModeDlls.Add($DllPath.FullName)
        }

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
