Function Test-KernelProtectedFiles {
    <#
    .SYNOPSIS
        Detects kernel-protected files files such as the main executable of the games installed through Xbox app
    .DESCRIPTION
        For these files, only Kernel can get their details such as hashes, it passes them to event viewer and we take them from event viewer logs
        Any other attempts such as "Get-FileHash" or "Get-AuthenticodeSignature" fails and ConfigCI Module cmdlets totally ignore these files and do not create allow rules for them
    .INPUTS
        System.IO.DirectoryInfo[]
        System.IO.FileInfo[]
    .OUTPUTS
        System.Collections.Generic.HashSet[System.String]
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.HashSet[System.String]])]
    Param(
        [ValidateScript({ Test-Path -Path $_ -PathType Container -IsValid })]
        [Parameter(Mandatory = $false)][System.IO.DirectoryInfo[]]$DirectoryPaths,

        [ValidateScript({ Test-Path -Path $_ -PathType Leaf -IsValid })]
        [Parameter(Mandatory = $false)][System.IO.FileInfo[]]$FilePaths,

        [Parameter(Mandatory = $false)][PSCustomObject[]]$Logs
    )

    Write-Verbose -Message 'Test-KernelProtectedFiles: Checking for Kernel-Protected files'

    if ($DirectoryPaths -or $FilePaths) {
        # Final output to return
        $ExesWithNoHash = [System.Collections.Generic.HashSet[System.String]]@()

        # Files to process
        $ApplicableFiles = [System.Collections.Generic.HashSet[System.String]]@()

        switch ($true) {
            $DirectoryPaths {
                # Get all of the executables in the directory paths
                $ApplicableFiles = Get-ChildItem -File -Recurse -Path $DirectoryPaths -Filter '*.exe', '*.dll'
            }
            $FilePaths {
                $ApplicableFiles = $FilePaths | Where-Object -FilterScript { [System.IO.Path]::GetExtension($_) -in @('.exe', '.dll') }
            }
        }

        foreach ($Exe in $ApplicableFiles) {
            try {
                # Testing each executable to find the protected ones
                Get-FileHash -Path $Exe -ErrorAction Stop | Out-Null
            }
            # If the executable is protected, it will throw an exception and the module will continue to the next one
            # Making sure only the right file is captured by narrowing down the error type.
            # E.g., when get-filehash can't get a file's hash because its open by another program, the exception is different: System.IO.IOException
            catch [System.UnauthorizedAccessException] {
                [System.Void]$ExesWithNoHash.Add($Exe)
            }
            catch {
                Write-Verbose -Message "Test-KernelProtectedFiles: An unexpected error occurred while checking the file: $Exe"
            }
        }

        Return ($ExesWithNoHash.Count -eq 0 ? $null : $ExesWithNoHash)
    }

    elseif ($Logs) {

        # Final output to return
        $KernelProtectedFileLogs = [System.Collections.Generic.HashSet[PSCustomObject]]@()

        # Looping through every file with .exe and .dll extensions to check if they are kernel protected regardless of whether the file exists or not
        foreach ($Log in $Logs | Where-Object -FilterScript { [System.IO.Path]::GetExtension($_.'Full Path') -in @('.exe', '.dll') }) {
            try {
                Get-FileHash -Path $Log.'Full Path' -ErrorAction Stop | Out-Null
            }
            catch [System.UnauthorizedAccessException] {
                [System.Void]$KernelProtectedFileLogs.Add($Log)
            }
            catch {
                Write-Verbose -Message "Test-KernelProtectedFiles: An unexpected error occurred while checking the file: $($Log.'Full Path')"
            }
        }

        Return ($KernelProtectedFileLogs.Count -eq 0 ? $null : $KernelProtectedFileLogs)
    }
}
Export-ModuleMember -Function 'Test-KernelProtectedFiles'
