Function Assert-WDACConfigIntegrity {
    [CmdletBinding(
        DefaultParameterSetName = 'SaveLocally'
    )]
    [OutputType([System.String], [System.Object[]])]
    param (
        [Alias('S')]
        [Parameter(Mandatory = $false, ParameterSetName = 'SaveLocally')]
        [System.Management.Automation.SwitchParameter]$SaveLocally,

        [Alias('P')]
        [Parameter(Mandatory = $false, ParameterSetName = 'SaveLocally')]
        [ValidateScript({ [System.IO.Directory]::Exists($_) })]
        [System.IO.DirectoryInfo]$Path = "$([WDACConfig.GlobalVars]::ModuleRootPath)\..\Utilities\",

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )
    begin {
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false
        [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)
        . "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\PSDefaultParameterValues.ps1"

        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -Force -FullyQualifiedName "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Update-Self.psm1"

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-Self -InvocationStatement $MyInvocation.Statement }

        # Define the output file name and the URL of the cloud CSV file
        [System.String]$OutputFileName = 'Hashes.csv'
        [System.Uri]$Url = 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/WDACConfig/Utilities/Hashes.csv'

        # Download the cloud CSV file and convert it to an array of objects
        [System.Object[]]$CloudCSV = (Invoke-WebRequest -Uri $Url -ProgressAction SilentlyContinue).Content | ConvertFrom-Csv

        # An empty array to store the final results
        $FinalOutput = New-Object -TypeName System.Collections.Generic.List[PSCustomObject]
    }
    process {

        Write-Verbose -Message 'Looping through the WDACConfig module files'
        foreach ($File in ([WDACConfig.FileUtility]::GetFilesFast(([WDACConfig.GlobalVars]::ModuleRootPath), $null, '*'))) {

            # Making sure the PowerShell Gallery file in the WDACConfig module's folder is skipped
            if ($File.Name -eq 'PSGetModuleInfo.xml') {
                Write-Verbose -Message "Skipping the extra file: $($File.Name)"
                continue
            }

            # Read the file as a byte array - This way we can get hashes of a file in use by another process where Get-FileHash would fail
            [System.Byte[]]$Bytes = [System.IO.File]::ReadAllBytes($File)

            #Region SHA2-512 calculation
            # Create a SHA512 object
            [System.Security.Cryptography.SHA512]$Sha512 = [System.Security.Cryptography.SHA512]::Create()

            # Compute the hash of the byte array
            [System.Byte[]]$HashBytes = $Sha512.ComputeHash($Bytes)

            # Dispose the SHA512 object
            $Sha512.Dispose()

            # Convert the hash bytes to a hexadecimal string to make it look like the output of the Get-FileHash which produces hexadecimals (0-9 and A-F)
            # If [System.Convert]::ToBase64String was used, it'd return the hash in base64 format, which uses 64 symbols (A-Z, a-z, 0-9, + and /) to represent each byte
            [System.String]$HashString = [System.BitConverter]::ToString($HashBytes)

            # Remove the dashes from the hexadecimal string
            $HashString = $HashString.Replace('-', '')
            #Endregion SHA2-512 calculation

            #Region SHA3-512 calculation
            try {
                [System.Security.Cryptography.SHA3_512]$SHA3_512 = [System.Security.Cryptography.SHA3_512]::Create()

                # Compute the hash of the byte array
                [System.Byte[]]$SHA3_512HashBytes = $SHA3_512.ComputeHash($Bytes)

                # Dispose the SHA3_512 object
                $SHA3_512.Dispose()

                # Convert the hash bytes to a hexadecimal string to make it look like the output of the Get-FileHash which produces hexadecimals (0-9 and A-F)
                # If [System.Convert]::ToBase64String was used, it'd return the hash in base64 format, which uses 64 symbols (A-Z, a-z, 0-9, + and /) to represent each byte
                [System.String]$SHA3_512HashString = [System.BitConverter]::ToString($SHA3_512HashBytes)

                # Remove the dashes from the hexadecimal string
                $SHA3_512HashString = $SHA3_512HashString.Replace('-', '')
            }
            catch [System.PlatformNotSupportedException] {
                Write-Verbose -Message 'The SHA3-512 algorithm is not supported on this system. Requires build 24H2 or higher.'
            }
            #Endregion SHA3-512 calculation

            # Create a custom object to store the relative path, file name and the hash of the file
            $FinalOutput.Add([PSCustomObject]@{
                    RelativePath     = [System.String]([System.IO.Path]::GetRelativePath(([WDACConfig.GlobalVars]::ModuleRootPath), $File.FullName))
                    FileName         = [System.String]$File.Name
                    FileHash         = [System.String]$HashString
                    FileHashSHA3_512 = [System.String]$SHA3_512HashString
                })
        }

        if ($SaveLocally) {
            Write-Verbose -Message "Saving the results to a CSV file in $((Join-Path -Path $Path -ChildPath $OutputFileName))"
            $FinalOutput | Export-Csv -Path (Join-Path -Path $Path -ChildPath $OutputFileName) -Force
        }
    }
    end {
        Write-Verbose -Message 'Comparing the local files hashes with the ones in the cloud'
        [System.Object[]]$ComparisonResults = Compare-Object -ReferenceObject $CloudCSV -DifferenceObject $FinalOutput -Property RelativePath, FileName, FileHash | Where-Object -Property SideIndicator -EQ '=>'

        if ($ComparisonResults) {
            Write-Warning -Message 'Tampered files detected!'
            Write-ColorfulTextWDACConfig -Color PinkBoldBlink -InputText 'The following files are different from the ones in the cloud:'
            $ComparisonResults
        }
        else {
            Write-ColorfulTextWDACConfig -Color NeonGreen -InputText 'All of your local WDACConfig files are genuine.'
        }
    }
    <#
.SYNOPSIS
    Gets the SHA2-512 hashes of files in the WDACConfig and compares them with the ones in the cloud and shows the differences.
    It also calculates the SHA3-512 hashes of the files and will completely switch to this new algorithm after Windows build 24H2 is reached GA.
.DESCRIPTION
    The Assert-WDACConfigIntegrity function scans all the relevant files in the WDACConfig's folder and its subfolders, calculates their SHA2-512 hashes in hexadecimal format,
    Then it downloads the cloud CSV file from the GitHub repository and compares the hashes of the local files with the ones in the cloud.
    By doing so, you can ascertain that the files in your local WDACConfig folder are identical to the ones in the cloud and devoid of any interference.
    If there is any indication of tampering, the outcomes will be displayed on the console.
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Assert-WDACConfigIntegrity
.PARAMETER SaveLocally
    Indicates that the function should save the results to a CSV file locally.
    You don't need to use this parameter.
.PARAMETER Path
    Specifies the path to save the CSV file to. The default path is the Utilities folder in the WDACConfig's folder.
    This is used before uploading to GitHub to renew the hashes.
    You don't need to use this parameter.
.PARAMETER SkipVersionCheck
    Indicates that the function should skip the version check and not run the updater.
.PARAMETER Verbose
    Indicates that the function should display verbose messages.
.INPUTS
    System.Management.Automation.SwitchParameter
    System.IO.DirectoryInfo
.OUTPUTS
    System.String
    System.Object[]
.EXAMPLE
    Assert-WDACConfigIntegrity
#>
}
