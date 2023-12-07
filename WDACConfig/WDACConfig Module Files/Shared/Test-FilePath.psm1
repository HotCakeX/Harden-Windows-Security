Function Test-FilePath {
    <#
    .SYNOPSIS
        function that takes 2 arrays, one contains file paths and the other contains folder paths. It checks them and shows file paths
        that are not in any of the folder paths. Performs this check recursively too so works if the filepath is in a sub-directory of a folder path

    #>
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$FilePath,
        [Parameter(Mandatory = $true)]
        [System.String[]]$DirectoryPath
    )

    # Loop through each file path
    foreach ($file in $FilePath) {
        # Check if the file path is valid
        if (Test-Path -Path $file -PathType 'Leaf') {
            # Get the full path of the file
            $FileFullPath = Resolve-Path -Path $file

            # Initialize a variable to store the result
            [System.Boolean]$Result = $false

            # Loop through each directory path
            foreach ($Directory in $DirectoryPath) {
                # Check if the directory path is valid
                if (Test-Path -Path $Directory -PathType 'Container') {
                    # Get the full path of the directory
                    $DirectoryFullPath = Resolve-Path -Path $Directory

                    # Check if the file path starts with the directory path
                    if ($FileFullPath -like "$DirectoryFullPath\*") {
                        # The file is inside the directory or its sub-directories
                        $Result = $true
                        break # Exit the inner loop
                    }
                }
                else {
                    # The directory path is not valid
                    Write-Warning "The directory path '$Directory' is not valid."
                }
            }

            # Output the file path if it is not inside any of the directory paths
            if (-not $Result) {
                Write-Output -InputObject $FileFullPath
            }
        }
        else {
            # The file path is not valid
            Write-Warning "The file path '$file' is not valid."
        }
    }
}

# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'Test-FilePath' -Verbose:$false
