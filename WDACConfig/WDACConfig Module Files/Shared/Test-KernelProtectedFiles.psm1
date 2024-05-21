Function Test-KernelProtectedFiles {
    <#
    .SYNOPSIS
        Detects kernel-protected files files such as the main executable of the games installed through Xbox app inside of the event logs
    .DESCRIPTION
        For these files, only Kernel can get their details such as hashes, it passes them to event viewer and we take them from event viewer logs
        Any other attempts such as "Get-FileHash" or "Get-AuthenticodeSignature" fails and ConfigCI Module cmdlets totally ignore these files and do not create allow rules for them
    .INPUTS
        PSCustomObject[]
    .OUTPUTS
        PSCustomObject[]
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    Param(
        [Parameter(Mandatory = $true)][PSCustomObject[]]$Logs
    )
    Begin {
        Write-Verbose -Message 'Test-KernelProtectedFiles: Checking for Kernel-Protected files'
        # Final output to return
        $KernelProtectedFileLogs = [System.Collections.Generic.HashSet[PSCustomObject]]@()
    }
    Process {
        # Looping through every existing file with .exe and .dll extensions to check if they are kernel protected
        foreach ($Log in ($Logs | Where-Object -FilterScript { ([System.IO.Path]::GetExtension($_.'Full Path') -in @('.exe', '.dll')) -and ([System.IO.Path]::Exists($_.'Full Path')) })) {
            try {
                Get-FileHash -Path $Log.'Full Path' -ErrorAction Stop | Out-Null
            }
            # If the executable is protected, it will throw an exception and the module will continue to the next one
            # Making sure only the right file is captured by narrowing down the error type.
            # E.g., when get-filehash can't get a file's hash because its open by another program, the exception is different: System.IO.IOException
            catch [System.UnauthorizedAccessException] {
                [System.Void]$KernelProtectedFileLogs.Add($Log)
            }
            catch {
                Write-Verbose -Message "Test-KernelProtectedFiles: An unexpected error occurred while checking the file: $($Log.'Full Path')"
            }
        }
    }
    End {
        Return ($KernelProtectedFileLogs.Count -eq 0 ? $null : [PSCustomObject[]]$KernelProtectedFileLogs)
    }
}
Export-ModuleMember -Function 'Test-KernelProtectedFiles'
