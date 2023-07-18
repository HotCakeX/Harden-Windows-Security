#Requires -RunAsAdministrator       
function Invoke-WDACSimulation {
    [CmdletBinding(
        PositionalBinding = $false,
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    Param(
        [ValidateScript({ Test-Path $_ -PathType 'Container' }, ErrorMessage = "The path you selected is not a folder path.")] 
        [Parameter(Mandatory = $true)][System.String]$FolderPath,

        [ValidateScript({ Test-Path $_ -PathType 'Leaf' }, ErrorMessage = "The path you selected is not a file path.")]
        [Parameter(Mandatory = $true)][System.String]$XmlFilePath,

        [Parameter(Mandatory = $false)][Switch]$SkipVersionCheck # Used by all the entire Cmdlet
    )

    begin {    

        # Importing resources such as functions by dot-sourcing so that they will run in the same scope and their variables will be usable
        . "$psscriptroot\Resources2.ps1"
        . "$psscriptroot\Resources.ps1"

        # Detecting if Debug switch is used, will do debugging actions based on that
        $Debug = $PSBoundParameters.Debug.IsPresent

        # Stop operation as soon as there is an error anywhere, unless explicitly specified otherwise
        $ErrorActionPreference = 'Stop'
        if (-NOT $SkipVersionCheck) { . Update-self }       
    }
    
    process {
       
        if ($FolderPath) {
            # Store the results of the Signed files
            $SignedResult = @()
            # Get all of the files that WDAC supports from the user provided directory
            $CollectedFiles = (Get-ChildItem -Recurse -Path $FolderPath -File -Include "*.sys", "*.exe", "*.com", "*.dll", "*.ocx", "*.msp", "*.mst", "*.msi", "*.js", "*.vbs", "*.ps1", "*.appx").FullName

            # Get the path of the Temp folder
            $Temp = [System.IO.Path]::GetTempPath()

            # Generate a random number
            $Random = Get-Random -Minimum $(Get-Random -Minimum 10 -Maximum 5265) -Maximum $(Get-Random -Minimum 5267 -Maximum 626568)

            # Create a folder name with the random number
            $Folder = "RandomFolder$Random"

            # Join the Temp folder path and the folder name
            $RandomTempDirPath = Join-Path -Path $Temp -ChildPath $Folder

            # Create the folder in the Temp folder
            [void] (New-Item -Path $RandomTempDirPath -ItemType Directory -Force)

            $global:ProcessThePolicy = $false

            # Loop through each file
            $CollectedFiles | ForEach-Object {

                $CurrentFilePath = $_ 

                # If the file is signed and valid
                if ((Get-AuthenticodeSignature -FilePath $CurrentFilePath).Status -eq 'valid') { 
                    # If debug is used show extra info on the console
                    if ($Debug) {                        
                        Write-Host "Currently processing signed file: `n$CurrentFilePath" -ForegroundColor Yellow
                    }
                    $SignedResult += Compare-SignerAndCertificate -XmlFilePath $XmlFilePath -SignedFilePath $CurrentFilePath | Where-Object { $_.CertRootMatch -eq $true }                             
                }  
                # If the file is signed but invalid              
                elseif ((Get-AuthenticodeSignature -FilePath $CurrentFilePath).Status -eq 'HashMismatch') {
                    Write-Warning "The file $CurrentFilePath is tampered and unsafe to use."
                }        
                # if the file is Unsigned
                elseif ((Get-AuthenticodeSignature -FilePath $CurrentFilePath).Status -eq 'NotSigned') {

                    # Get the name of the item that is being copied
                    # A check to cover situations where multiple files with the same name but in different directories exist in the folder path selected by user
                    # Storing them in different directories inside the Random Temp directory
                    $ItemName = Split-Path -Path $CurrentFilePath -Leaf

                    # Check if the item already exists in the destination
                    if (Test-Path -Path "$RandomTempDirPath\$ItemName") {
                        # If yes, generate a random number between 1 and 1000
                        $RandomNumber = Get-Random -Minimum 1 -Maximum 1000

                        # Append the random number to the destination path
                        $NewRandomTempDirPath = $RandomTempDirPath + "\$RandomNumber"

                        # Create a new folder with the random name
                        New-Item -Path $NewRandomTempDirPath -ItemType Directory -Force | Out-Null

                        # Copy the item to the destination
                        Copy-Item -Path $CurrentFilePath -Destination $NewRandomTempDirPath
                    }
                    else {
                        # if an item with the same don't doesn't already exist in the random temp folder then copy it to the root folder instead of creating a new nested directory inside there
                        Copy-Item -Path $CurrentFilePath -Destination $RandomTempDirPath                    
                    }
                    # Fllag to tell the next command whether to process unsigned files or not
                    $global:ProcessThePolicy = $true
                }
            } 
            # if there was any unsigned files, process them
            if ($global:ProcessThePolicy) {
                # Scan the unsigned files by Hash level in order to get their 4 Authenticode and Page hashes
                New-CIPolicy -UserWriteablePaths -FilePath "$RandomTempDirPath\outputpolicy.xml" -Level hash -Fallback none -AllowFileNameFallbacks -UserPEs -NoShadowCopy -ScanPath $RandomTempDirPath
                
                # Call the Compare-XmlFiles function with two xml file paths as parameters and store the result in a variable
                # The result only contains files that exist in both xml files, the temp file from unsigned files and the one selected by the user
                $HashComparisonResult = Compare-XmlFiles -refXmlPath $XmlFilePath -tarXmlPath "$RandomTempDirPath\outputpolicy.xml" | Where-Object { $_.Comparison -eq 'Both' }
                
                if ($Debug) {

                    # Display the result in a table format with four columns: Comparison, HashValue, HashType, and FilePath
                    $HashComparisonResult | Select-Object -Property FilePathForHash, Comparison | Format-Table -AutoSize

                    $HashComparisonResult.Count
                }            
            }

            if ($Debug) {
                Write-Host "this is the random Temp: $RandomTempDirPath" -ForegroundColor Green
            }
        
            # File path of the files allowed by Hash
            $Hashresults = $HashComparisonResult.FilePathForHash

            # Filepath of files allowed by Signer/certificate
            $SignedResult = $SignedResult.FilePath | Get-Unique            

            if ($Debug) {
                $SignedResult               
            }
                 
            # Create an empty array to store the output objects
            $FinalAllowedFilesOutputObject = @()

            # Loop through the first array and create output objects with the file path and source
            foreach ($path in $Hashresults) {
                # Create a hash table with the file path and source
                $object = @{
                    FilePath = $path
                    Source   = "Hash"
                }
                # Convert the hash table to a PSObject and add it to the output array
                $FinalAllowedFilesOutputObject += New-Object -TypeName PSObject -Property $object
            }

            # Loop through the second array and create output objects with the file path and source
            foreach ($path in $SignedResult) {
                # Create a hash table with the file path and source
                $object = @{
                    FilePath = $path
                    Source   = "Signer"
                }
                # Convert the hash table to a PSObject and add it to the output array
                $FinalAllowedFilesOutputObject += New-Object -TypeName PSObject -Property $object
            }            

            # Unique number of files allowed by hash
            $UniqueFilesAllowedByHash = $FinalAllowedFilesOutputObject | Select-Object -Property FilePath, source -Unique | Where-Object { $_.source -eq "hash" }

            # Showing Signature based allowed file details
            &$WriteLavender "`n$($SignedResult.count) files inside the folder you selected are allowed by your xml policy by Signature"
            
            # Showing Hash based allowed file details
            &$WriteLavender "`n$($UniqueFilesAllowedByHash.count) files inside the folder you selected are allowed by your xml policy by Hashes"

            # Display the final main output array as a table - allowed files
            $FinalAllowedFilesOutputObject | Select-Object -Property FilePath, source -Unique | Sort-Object | Format-Table
            
            if ($($FinalAllowedFilesOutputObject.Filepath) -and $CollectedFiles) {
          
                $FinalComparisonForFilesNotAllowed = Compare-Object -ReferenceObject $($FinalAllowedFilesOutputObject.Filepath) -DifferenceObject $CollectedFiles -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
            }

            # Showing details of files not allwoed by the selected xml policy
            &$WritePink "`nThere are $($FinalComparisonForFilesNotAllowed.count) files inside the folder you selected that are Not allowed by your xml policy`n"

            # Display the final main output array as a table - Not allowed files
            $FinalComparisonForFilesNotAllowed | Format-Table -AutoSize

            # Invoke-Item -Path $RandomTempDirPath
            # Pause
            
            # Clean up the random temp folder in the end
            Remove-Item -Path $RandomTempDirPath -Recurse -Force

        }
    }
    
    <#
.SYNOPSIS
Simulates the deployment of the WDAC policy

.LINK
https://github.com/HotCakeX/Harden-Windows-Security/wiki/Invoke-WDACSimulation

.DESCRIPTION
Simulates the deployment of the WDAC policy by analyzing a folder and checking which of the files in the folder are allowed by a user selected policy xml file

.COMPONENT
Windows Defender Application Control, ConfigCI PowerShell module

.FUNCTIONALITY
Simulates the deployment of the WDAC policy

.PARAMETER FolderPath
Provide path to a folder where you want WDAC simulation to take place

.PARAMETER XmlFilePath
Provide path to a policy xml file that you want the cmdlet to simulate its deployment and running files against it

.PARAMETER SkipVersionCheck
Can be used with any parameter to bypass the online version check - only to be used in rare cases

#>
}

# Importing argument completer ScriptBlocks
. "$psscriptroot\ArgumentCompleters.ps1"
# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete
Register-ArgumentCompleter -CommandName "Invoke-WDACSimulation" -ParameterName "FolderPath" -ScriptBlock $ArgumentCompleterFolderPathsPicker
Register-ArgumentCompleter -CommandName "Invoke-WDACSimulation" -ParameterName "XmlFilePath" -ScriptBlock $ArgumentCompleterXmlFilePathsPicker
