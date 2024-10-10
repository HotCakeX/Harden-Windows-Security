Function Test-ECCSignedFiles {
    <#
.SYNOPSIS
    This function gets list of directories or files
    Then it checks if the files are WDAC compliant
    If they are, it checks if they are signed with ECC
    If they are, it returns an array of them if -Process parameter is not used

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
        [ValidateScript({ [System.IO.Directory]::Exists($_) })]
        [Parameter(Mandatory = $false)][System.IO.DirectoryInfo[]]$Directory,

        [Parameter(Mandatory = $false)][System.IO.FileInfo[]]$File,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$Process,
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$ECCSignedFilesTempPolicy
    )
    Begin {
        [WDACConfig.Logger]::Write('Test-ECCSignedFiles: Importing the required sub-modules')
        Import-Module -Force -FullyQualifiedName @(
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Get-KernelModeDrivers.psm1",
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\XMLOps\New-HashLevelRules.psm1",
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\XMLOps\Clear-CiPolicy_Semantic.psm1"
        ) -Verbose:$false

        # Get the compliant WDAC files from the File and Directory parameters and add them to the HashSet
        $WDACSupportedFiles = [System.Collections.Generic.HashSet[System.String]]@([WDACConfig.FileUtility]::GetFilesFast($Directory, $File, $null))

    }
    Process {
        [WDACConfig.Logger]::Write("Test-ECCSignedFiles: Processing $($WDACSupportedFiles.Count) WDAC compliant files to check for ECC signatures.")
        # The check for existence is mainly for the files detected in audit logs that no longer exist on the disk
        # Audit logs or MDE data simply don't have the data related to the file's signature algorithm, so only local files can be checked

        $ECCSignedFiles = [System.Collections.Generic.HashSet[System.String]]@(
            foreach ($Path in $WDACSupportedFiles) {

                if (([System.IO.FileInfo]$Path).Exists -eq $true) {

                    $AuthResult = Get-AuthenticodeSignature -LiteralPath $Path

                    if ($AuthResult.Status -ieq 'Valid') {

                        if (($AuthResult.SignerCertificate.PublicKey.Oid.Value).Contains('1.2.840.10045.2.1')) {
                            #  [WDACConfig.Logger]::Write("Test-ECCSignedFiles: The file '$Path' is signed with ECC algorithm. Will create Hash Level rules for it.")
                            $Path
                        }
                    }
                }
            }
        )
    }
    End {
        if (-NOT $Process) {
            Return ($ECCSignedFiles.Count -gt 0 ? $ECCSignedFiles : $null)
        }
        else {

            if (($null -ne $ECCSignedFiles) -and ($ECCSignedFiles.Count -gt 0)) {

                $CompleteHashes = New-Object -TypeName 'System.Collections.Generic.List[WDACConfig.HashCreator]'

                foreach ($ECCSignedFile in $ECCSignedFiles) {

                    [WDACConfig.Logger]::Write("Test-ECCSignedFiles: Creating Hash Level rules for the ECC signed file '$ECCSignedFile'.")

                    [WDACConfig.CodeIntegrityHashes]$HashOutput = [WDACConfig.CiFileHash]::GetCiFileHashes($ECCSignedFile)

                    $CompleteHashes.Add([WDACConfig.HashCreator]::New(
                            $HashOutput.SHA256Authenticode,
                            $HashOutput.SHA1Authenticode,
                        ([System.IO.FileInfo]$ECCSignedFile).Name,
                            # Check if the file is kernel-mode or user-mode
                        ($null -eq (Get-KernelModeDrivers -File $ECCSignedFile)) ? 1 : 0
                        )
                    )
                }

                Copy-Item -LiteralPath 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml' -Destination $ECCSignedFilesTempPolicy -Force
                Clear-CiPolicy_Semantic -Path $ECCSignedFilesTempPolicy

                New-HashLevelRules -Hashes $CompleteHashes -XmlFilePath $ECCSignedFilesTempPolicy

                Return $ECCSignedFilesTempPolicy
            }
            else {
                [WDACConfig.Logger]::Write('Test-ECCSignedFiles: No ECC signed files found. Exiting the function.')
                Return $null
            }
        }
    }
}
Export-ModuleMember -Function 'Test-ECCSignedFiles'
