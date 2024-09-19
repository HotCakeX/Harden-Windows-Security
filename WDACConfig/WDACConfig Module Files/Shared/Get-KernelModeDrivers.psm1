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
        [ValidateScript({ [System.IO.Directory]::Exists($_) })]
        [Parameter(Mandatory = $False)][System.IO.DirectoryInfo[]]$Directory,
        [ValidateScript({ [System.IO.File]::Exists($_) })]
        [Parameter(Mandatory = $False)][System.IO.FileInfo[]]$File
    )
    Begin {
        # Import the ConfigCI assembly resources if they are not already imported
        if (-NOT ('Microsoft.SecureBoot.UserConfig.ImportParser' -as [System.Type]) ) {
            [WDACConfig.Logger]::Write('Importing the ConfigCI assembly resources')
            Add-Type -Path ([System.String](PowerShell.exe -NoProfile -Command { (Get-Command -Name Merge-CIPolicy).DLL }))
        }

        Function Test-UserPE {
            <#
             .SYNOPSIS
                This function tests if a DLL is a user-mode PE by inspecting its imports
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
            foreach ($Item in [WDACConfig.FileUtility]::GetFilesFast($PSBoundParameters['Directory'], $null, '.sys')) {
                [System.Void]$DriverFiles.Add($Item)
            }

            # Get all of the .dll files from the user-selected directories
            foreach ($Item in [WDACConfig.FileUtility]::GetFilesFast($PSBoundParameters['Directory'], $null, '.dll')) {
                [System.Void]$PotentialKernelModeDlls.Add($Item)
            }
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

            # Since there can be more than one folder due to localizations such as en-US then from each of the folders, the bootres.dll.mui file is added
            Foreach ($Path in Get-ChildItem -Directory -Path "$env:SystemDrive\Windows\Boot\Resources") {
                [System.Void]$DriverFiles.Add("$Path\bootres.dll.mui")
            }

            # Get all of the .dll files from the system32 directory
            foreach ($Item in [WDACConfig.FileUtility]::GetFilesFast("$env:SystemRoot\System32", $null, '.dll')) {
                [System.Void]$PotentialKernelModeDlls.Add($Item)
            }

            # Get the .sys files from the System32 directory
            foreach ($Item in [WDACConfig.FileUtility]::GetFilesFast("$env:SystemRoot\System32", $null, '.sys')) {
                [System.Void]$DriverFiles.Add($Item)
            }
        }

        [WDACConfig.Logger]::Write("Number of sys files: $($DriverFiles.Count)")
        [WDACConfig.Logger]::Write("Number of potential kernel-mode DLLs: $($PotentialKernelModeDlls.Count)")

        # Scan all of the .dll files to see if they are kernel-mode drivers
        foreach ($KernelDll in $PotentialKernelModeDlls) {
            if (Get-FolderDllKernelDrivers -File $KernelDll) {
                [System.Void]$KernelModeDlls.Add($KernelDll)
                [System.Void]$DriverFiles.Add($KernelDll)
            }
        }

        [WDACConfig.Logger]::Write("Number of kernel-mode DLLs folder: $($KernelModeDlls.Count)")
    }
    End {
        [WDACConfig.Logger]::Write("Returning $($DriverFiles.Count) kernel-mode driver file paths")
        Return $DriverFiles
    }
}

Export-ModuleMember -Function 'Get-KernelModeDrivers'
