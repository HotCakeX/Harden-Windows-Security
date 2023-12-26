Function Assert-WDACConfigIntegrity {
    [CmdletBinding(
        DefaultParameterSetName = 'SaveLocally'
    )]
    param (
        [Alias('S')]
        [Parameter(Mandatory = $false, ParameterSetName = 'SaveLocally')]
        [System.Management.Automation.SwitchParameter]$SaveLocally,

        [Alias('P')]
        [Parameter(Mandatory = $false, ParameterSetName = 'SaveLocally')]
        [ValidateScript({ Test-Path -Path $_ -PathType 'Container' })]
        [System.IO.FileInfo]$Path = "$ModuleRootPath\..\Utilities\",

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )
    begin {
        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null

        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Importing the required sub-modules
        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Write-ColorfulText.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Update-self.psm1" -Force

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-self -InvocationStatement $MyInvocation.Statement }

        # Define the output file name and the URL of the cloud CSV file
        [System.String]$OutputFileName = 'Hashes.csv'
        [System.Uri]$Url = 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/WDACConfig-v0.2.8/WDACConfig/WDACConfig%20Module%20Files/Hashes.csv'

        # Download the cloud CSV file and convert it to an array of objects
        [System.Object[]]$CloudCSV = (Invoke-WebRequest -Uri $Url -ProgressAction SilentlyContinue).Content | ConvertFrom-Csv

        # An empty array to store the final results
        [System.Object[]]$FinalOutput = @()
    }
    process {

        Write-Verbose -Message 'Looping through all the files'
        foreach ($File in Get-ChildItem -Path $ModuleRootPath -Recurse -File -Force) {

            if ($File.Name -eq $OutputFileName) {
                Write-Verbose -Message "Skipping the output file: $($File.Name)"
                continue
            }

            # Create a custom object to store the relative path, file name and the hash of the file
            $FinalOutput += [PSCustomObject]@{
                RelativePath = ([System.IO.Path]::GetRelativePath($ModuleRootPath, $File.FullName))
                FileName     = $File.Name
                FileHash     = (Get-FileHash -Path $File.FullName -Algorithm 'SHA512').Hash
            }
        }

        if ($SaveLocally) {
            Write-Verbose -Message "Saving the results to a CSV file in $($Path.FullName)"
            $FinalOutput | Export-Csv -Path (Join-Path -Path $Path -ChildPath $OutputFileName) -Force
        }
    }
    end {
        Write-Verbose -Message 'Comparing the local files hashes with the ones in the cloud'
        [System.Object[]]$ComparisonResults = Compare-Object -ReferenceObject $CloudCSV -DifferenceObject $FinalOutput -Property RelativePath, FileName, FileHash | Where-Object -Property SideIndicator -EQ '=>'

        if ($ComparisonResults) {
            Write-ColorfulText -Color PinkBoldBlink -InputText 'The following files are different from the ones in the cloud:'
            $ComparisonResults
        }
        else {
            Write-ColorfulText -Color NeonGreen -InputText 'All of your local WDACConfig files are genuine.'
        }
    }
    <#
.SYNOPSIS
    Gets the SHA512 hashes of files in the WDACConfig and compares them with the ones in the cloud and shows the differences.

.DESCRIPTION
    The Assert-WDACConfigIntegrity function scans all the files in the WDACConfig's folder and its subfolders, calculates their SHA512 hashes using the Get-FileHash cmdlet.
    Then it downloads the cloud CSV file from the GitHub repository and compares the hashes of the local files with the ones in the cloud.
    This way you can make sure that the files in your local WDACConfig folder are the same as the ones in the cloud and no one has tampered with them.

.PARAMETER SaveLocally
    Indicates that the function should save the results to a CSV file locally.
    You don't need to use this parameter.

.PARAMETER Path
    Specifies the path to save the CSV file to. The default path is the Utilities folder in the WDACConfig's folder.
    This is used before uploading to GitHub to renew the hashes.
    You don't need to use this parameter.

.PARAMETER SkipVersionCheck
    Indicates that the function should skip the version check and not run the updater.

.INPUTS
    System.Management.Automation.SwitchParameter
    System.IO.FileInfo

.OUTPUTS
    System.String
    System.Object[]

.EXAMPLE
    Assert-WDACConfigIntegrity

#>
}
