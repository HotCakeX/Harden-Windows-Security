Function Test-KernelProtectedFiles {
    <#
    .SYNOPSIS
        Detects kernel-protected files files such as the main executable of the games installed through Xbox app
    .DESCRIPTION
        For these files, only Kernel can get their details such as hashes, it passes them to event viewer and we take them from event viewer logs
        Any other attempts such as "Get-FileHash" or "Get-AuthenticodeSignature" fails and ConfigCI Module cmdlets totally ignore these files and do not create allow rules for them
    .INPUTS
        System.IO.DirectoryInfo[]
    .OUTPUTS
        System.Collections.Generic.HashSet[System.String]
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.HashSet[System.String]])]
    Param(
        [ValidateScript({ Test-Path -Path $_ -PathType Container -IsValid })]
        [Parameter(Mandatory = $true)][System.IO.DirectoryInfo[]]$DirectoryPaths
    )
    Begin {
        # Final output
        $ExesWithNoHash = [System.Collections.Generic.HashSet[System.String]]@()
        # Get all of the executables in the directory paths
        $AnyAvailableExes = [System.Collections.Generic.HashSet[System.String]]@(Get-ChildItem -File -Recurse -Path $DirectoryPaths -Filter '*.exe')
    }
    Process {
        foreach ($Exe in $AnyAvailableExes) {
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
        }
    }
    End {
        Return ($ExesWithNoHash.Count -eq 0 ? $null : $ExesWithNoHash)
    }
}
Export-ModuleMember -Function 'Test-KernelProtectedFiles'
