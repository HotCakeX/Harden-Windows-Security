Function Get-CiFileHashes {
    [CmdletBinding()]
    [OutputType([ordered])]
    param (
        [Parameter(Mandatory = $true, Position = 0, valueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo]$FilePath
    )
    Begin {
        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null

        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Defining the WinTrust class from the WDACConfig Namespace if it doesn't already exist
        if (-NOT ('WDACConfig.WinTrust' -as [System.Type]) ) {
            Add-Type -Path "$ModuleRootPath\C#\AuthenticodeHashCalc.cs"
        }

        # Defining the PageHashCalculator class from the WDACConfig Namespace if it doesn't already exist
        if (-NOT ('WDACConfig.PageHashCalculator' -as [System.Type]) ) {
            Add-Type -Path "$ModuleRootPath\C#\PageHashCalc.cs"
        }

        # Defining an ordered hashtable to store the output
        $OutputHashes = [ordered]@{
            SHA1Page           = ''
            SHA256Page         = ''
            SHa1Authenticode   = ''
            SHA256Authenticode = ''
        }

        function Get-AuthenticodeHash {
            <#
            .SYNOPSIS
               This is a nested function that calculates the authenticode hash of a file using a specified hash algorithm
            .PARAMETER FilePath
                The path to the file for which the hash is to be calculated
            .PARAMETER HashAlgorithm
                The hash algorithm to be used. It can be either 'SHA1' or 'SHA256'
            .INPUTS
                System.IO.FileInfo
                System.String
            .OUTPUTS
                System.String
            #>
            param (
                [parameter(Mandatory = $true)]
                [System.IO.FileInfo]$FilePath,

                [parameter(Mandatory = $true)]
                [System.String]$HashAlgorithm
            )
            Begin {
                # Creating a StringBuilder object to store the hash value as a hexadecimal string
                [System.Text.StringBuilder]$HashString = New-Object -TypeName System.Text.StringBuilder(64)

                # Initializing a pointer to zero, which will be used to store the handle of the CryptCATAdmin context
                [System.IntPtr]$ContextHandle = [System.IntPtr]::Zero

                # Initializing a pointer to zero, which will be used to store the handle of the file stream
                [System.IntPtr]$FileStreamHandle = [System.IntPtr]::Zero

                Function Get-FlatFileHash {
                    <#
                    .SYNOPSIS
                        This is a nested function that calculates the flat hash of a file using a specified hash algorithm
                        This only runs as a fallback method when normal Authenticode hashes cannot be calculated because the file is Non-conformant
                    .NOTES
                        This function acts as a 2nd fallback.
                        The first fallback is defined and handled by the AuthenticodeHashCalc.cs
                    .PARAMETER FilePath
                        The path to the file for which the hash is to be calculated
                    .PARAMETER Algorithm
                        The hash algorithm to be used
                    .INPUTS
                        System.IO.FileInfo
                        System.String
                    .OUTPUTS
                        System.String
                    #>
                    param(
                        [parameter(Mandatory = $true)]
                        [System.IO.FileInfo]$FilePath,

                        [parameter(Mandatory = $true)]
                        [System.String]$Algorithm
                    )
                    Return [System.String](Get-FileHash -Algorithm $Algorithm -Path $FilePath).Hash
                }
            }

            Process {

                try {
                    # Old code - handle could not be properly closed
                    # $VoidPtr = [System.IO.File]::OpenRead($FilePath).SafeFileHandle.DangerousGetHandle()

                    # Opening a read-only file stream for the given file path
                    [System.IO.FileStream]$FileStream = [System.IO.File]::OpenRead($FilePath)

                    # Getting the handle of the file stream
                    [System.IntPtr]$FileStreamHandle = $FileStream.SafeFileHandle.DangerousGetHandle()

                    # Checking if the handle is valid
                    if ($FileStreamHandle -eq [System.IntPtr]::Zero) {
                        # Returning null if the handle is invalid
                        return $null
                    }

                    # Acquiring a CryptCATAdmin context for the specified hash algorithm
                    # This is a wrapper for the native CryptCATAdminAcquireContext2 function
                    # See https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatadminacquirecontext2
                    if (-NOT ([WDACConfig.WinTrust]::CryptCATAdminAcquireContext2([ref]$ContextHandle, [System.IntPtr]::Zero, $HashAlgorithm, [System.IntPtr]::Zero, 0))) {
                        # Throwing an exception if the context could not be acquired
                        #   throw "Could not acquire context for $HashAlgorithm"

                        Write-Verbose -Message "Could not acquire context for $HashAlgorithm"

                        Return [System.String](Get-FlatFileHash -FilePath $FilePath -Algorithm $HashAlgorithm)
                    }

                    # Initializing a variable to store the size of the hash in bytes
                    [System.Int64]$HashSize = 0

                    # Calculating the hash of the file using the CryptCATAdmin context
                    # This is a wrapper for the native CryptCATAdminCalcHashFromFileHandle3 function
                    if (-NOT ([WDACConfig.WinTrust]::CryptCATAdminCalcHashFromFileHandle3($ContextHandle, $FileStreamHandle, [ref]$HashSize, [System.IntPtr]::Zero, [WDACConfig.WinTrust]::CryptcatadminCalchashFlagNonconformantFilesFallbackFlat))) {
                        # Throwing an exception if the hash could not be calculated
                        #  throw "Could not hash $FilePath using $HashAlgorithm"

                        Write-Verbose -Message "Could not hash $FilePath using $HashAlgorithm"

                        Return [System.String](Get-FlatFileHash -FilePath $FilePath -Algorithm $HashAlgorithm)
                    }

                    # Initializing a pointer to zero, which will be used to store the hash value
                    [System.IntPtr]$HashValue = [System.IntPtr]::Zero

                    try {
                        # Allocating memory for the hash value using the size obtained from the previous call
                        [System.IntPtr]$HashValue = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($HashSize)

                        # Calculating the hash of the file again using the CryptCATAdmin context and storing it in the allocated memory
                        if (-NOT ([WDACConfig.WinTrust]::CryptCATAdminCalcHashFromFileHandle3($ContextHandle, $FileStreamHandle, [ref]$HashSize, $HashValue, [WDACConfig.WinTrust]::CryptcatadminCalchashFlagNonconformantFilesFallbackFlat))) {
                            # Throwing an exception if the hash could not be calculated
                            # throw "Could not hash $FilePath using $HashAlgorithm"

                            Write-Verbose -Message "Could not hash $FilePath using $HashAlgorithm"

                            Return [System.String](Get-FlatFileHash -FilePath $FilePath -Algorithm $HashAlgorithm)
                        }

                        # Looping through the hash value byte by byte
                        for ($Offset = 0; $Offset -lt $HashSize; $Offset++) {

                            # Reading a byte from the allocated memory using the offset
                            [System.Byte]$Byte = [System.Runtime.InteropServices.Marshal]::ReadByte($HashValue, $Offset)

                            # Appending the byte to the StringBuilder object as a hexadecimal string
                            $HashString.Append($Byte.ToString('X2')) | Out-Null
                        }
                    }
                    finally {
                        # Freeing the allocated memory if it is not zero
                        if ($HashValue -ne [System.IntPtr]::Zero) {
                            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($HashValue)
                        }

                        # Closing the file stream
                        $FileStream.Close()
                    }
                }
                finally {
                    # Releasing the CryptCATAdmin context if it is not zero
                    if ($ContextHandle -ne [System.IntPtr]::Zero) {
                        [WDACConfig.WinTrust]::CryptCATAdminReleaseContext($ContextHandle, 0) | Out-Null # Hide the boolean output
                    }
                }
            }
            End {
                # Returning the hash value as a hexadecimal string
                return [System.String]$HashString.ToString()
            }
        }
    }
    process {
        # Calling the GetPageHash method of the PageHashCalculator class to calculate the SHA1 and SHA256 page hashes of the file
        # This method uses the native GetFileInformationByHandleEx function to get the page hash
        # https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex
        [System.String]$OutputHashes.SHA1Page = [WDACConfig.PageHashCalculator]::GetPageHash('SHA1', $FilePath)
        [System.String]$OutputHashes.SHA256Page = [WDACConfig.PageHashCalculator]::GetPageHash('SHA256', $FilePath)

        # Calling the GetAuthenticodeHash function to calculate the SHA1 and SHA256 authenticode hashes of the file
        [System.String]$OutputHashes.SHA1Authenticode = Get-AuthenticodeHash -FilePath $FilePath -HashAlgorithm 'SHA1'
        [System.String]$OutputHashes.SHA256Authenticode = Get-AuthenticodeHash -FilePath $FilePath -HashAlgorithm 'SHA256'
    }
    End {
        # Returning the output ordered hashtable
        Return $OutputHashes
    }
    <#
.SYNOPSIS
    Calculates the Authenticode hash and first page hash of the PEs with SHA1 and SHA256 algorithms.
    The hashes are compliant wih the Windows Defender Application Control (WDAC) policy.
    For more information please visit: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create#more-information-about-hashes
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Get-CiFileHashes
.PARAMETER Path
    The path to the file for which the hashes are to be calculated.
.INPUTS
    System.IO.FileInfo
.OUTPUTS
    [ordered]
    The output is an ordered hashtable with the following keys:
    - SHA1Page: The SHA1 hash of the first page of the PE file.
    - SHA256Page: The SHA256 hash of the first page of the PE file.
    - SHA1Authenticode: The SHA1 hash of the Authenticode signature of the PE file.
    - SHA256Authenticode: The SHA256 hash of the Authenticode signature of the PE file.
.NOTES
    If the is non-conformant, the function will calculate the flat hash of the file using the specified hash algorithm
    And return them as the Authenticode hashes. This is compliant with how the WDAC engine in Windows works.
#>
}
