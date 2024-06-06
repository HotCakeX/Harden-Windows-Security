Function Test-ECCSignedFiles {
    <#
.SYNOPSIS
    This function gets list of directories or files
    Then it checks if the files are WDAC compliant
    If they are, it checks if they are signed with ECC
    If they are, it returns an array of them of -Process parameter is not used

    With -Progress parameter, the function creates Hash level rules for each ECC file
    puts them in a separate XML policy file and returns the path to it
.PARAMETER Directory
    The directories to process
.PARAMETER File
    The files to process
.PARAMETER Process
    Indicates that instead of returning list of ECC Signed files, the function
    will create Hash Level rules for them
.PARAMETER ECCSignedFilesTempPolicy
    The path to the temporary policy file where the Hash Level rules will be stored.
.INPUTS
    System.IO.DirectoryInfo[]
    System.IO.FileInfo[]
.OUTPUTS
    System.String[]
    System.IO.FileInfo
.NOTES
    The OID of the ECC algorithm for public keys is '1.2.840.10045.2.1'
#>
    Param (
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
        [Parameter(Mandatory = $false)][System.IO.DirectoryInfo[]]$Directory,
        [Parameter(Mandatory = $false)][System.IO.FileInfo[]]$File,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$Process,
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$ECCSignedFilesTempPolicy
    )
    Begin {
        Write-Verbose -Message 'Test-ECCSignedFiles: Importing the required sub-modules'
        Import-Module -Force -FullyQualifiedName @(
            "$ModuleRootPath\Shared\Get-KernelModeDrivers.psm1",
            "$ModuleRootPath\Core\Get-CiFileHashes.psm1",
            "$ModuleRootPath\XMLOps\New-HashLevelRules.psm1",
            "$ModuleRootPath\XMLOps\Clear-CiPolicy_Semantic.psm1",
            "$ModuleRootPath\CoreExt\Classes.psm1"
        ) -Verbose:$false

        $WDACSupportedFiles = [System.Collections.Generic.HashSet[System.String]]@()
        $ECCSignedFiles = [System.Collections.Generic.HashSet[System.String]]@()

        # Get compliant WDAC files from the Files parameter and add them to the HashSet
        if (($null -ne $File) -and ($File.Count -gt 0)) {
            &$FindWDACCompliantFiles $File | ForEach-Object -Process { [System.Void]$WDACSupportedFiles.Add($_) }
        }

        # Get compliant WDAC files in the directories from the Directory parameter and add them to the HashSet
        if (($null -ne $Directory) -and ($Directory.Count -gt 0)) {
            &$FindWDACCompliantFiles $Directory | ForEach-Object -Process { [System.Void]$WDACSupportedFiles.Add($_) }
        }
    }
    Process {
        Write-Verbose -Message "Test-ECCSignedFiles: Processing $($WDACSupportedFiles.Count) WDAC compliant files to check for ECC signatures."
        # The check for existence is mainly for the files detected in audit logs that no longer exist on the disk
        # Audit logs or MDE data simply don't have the data related to the file's signature algorithm, so only local files can be checked
        foreach ($Path in $WDACSupportedFiles | Where-Object -FilterScript { ([System.IO.FileInfo]$_).Exists -eq $true }) {
            if ((Get-AuthenticodeSignature -LiteralPath $Path | Where-Object -FilterScript { $_.Status -eq 'Valid' }).SignerCertificate.PublicKey.Oid.Value -eq '1.2.840.10045.2.1') {
                Write-Verbose -Message "Test-ECCSignedFiles: The file '$Path' is signed with ECC algorithm. Will create Hash Level rules for it."
                [System.Void]$ECCSignedFiles.Add($Path)
            }
        }
    }
    End {
        if (-NOT $Process) {
            Return ($ECCSignedFiles.Count -gt 0 ? $ECCSignedFiles : $null)
        }
        else {

            if (($null -ne $ECCSignedFiles) -and ($ECCSignedFiles.Count -gt 0)) {

                [HashCreator[]]$CompleteHashes = @()

                foreach ($ECCSignedFile in $ECCSignedFiles) {

                    # Create a new HashCreator object
                    [HashCreator]$CurrentHash = New-Object -TypeName HashCreator

                    $HashOutput = Get-CiFileHashes -FilePath $ECCSignedFile -SkipVersionCheck

                    # Add the hash details to the new object
                    $CurrentHash.AuthenticodeSHA256 = $HashOutput.SHA256Authenticode
                    $CurrentHash.AuthenticodeSHA1 = $HashOutput.SHA1Authenticode
                    $CurrentHash.FileName = ([System.IO.FileInfo]$ECCSignedFile).Name
                    # Check if the file is kernel-mode or user-mode -- Don't need the verbose output of the cmdlet when using it in embedded mode
                    $CurrentHash.SiSigningScenario = ($null -eq (Get-KernelModeDrivers -File $ECCSignedFile 4>$null)) ? 1 : 0

                    # Add the new object to the CompleteHashes array
                    $CompleteHashes += $CurrentHash
                }

                Copy-Item -LiteralPath 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml' -Destination $ECCSignedFilesTempPolicy -Force
                Clear-CiPolicy_Semantic -Path $ECCSignedFilesTempPolicy

                New-HashLevelRules -Hashes $CompleteHashes -XmlFilePath $ECCSignedFilesTempPolicy

                Return $ECCSignedFilesTempPolicy
            }
            else {
                Write-Verbose -Message 'Test-ECCSignedFiles: No ECC signed files found. Exiting the function.'
                Return $null
            }
        }
    }
}
Export-ModuleMember -Function 'Test-ECCSignedFiles'
