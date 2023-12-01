#Requires -RunAsAdministrator       
function Invoke-WDACSimulation {
    [CmdletBinding(
        PositionalBinding = $false,
        SupportsShouldProcess = $true
    )]
    Param(
        [ValidateScript({ Test-Path $_ -PathType 'Container' }, ErrorMessage = 'The path you selected is not a folder path.')] 
        [Parameter(Mandatory = $true)][System.String]$FolderPath,

        [ValidateScript({ Test-Path $_ -PathType 'Leaf' }, ErrorMessage = 'The path you selected is not a file path.')]
        [Parameter(Mandatory = $true)][System.String]$XmlFilePath,

        [Parameter(Mandatory = $false)][Switch]$SkipVersionCheck # Used by the entire Cmdlet
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
        # For Testing purposes
        # $FolderPath = ''
        # $XmlFilePath = ''
      
        if ($FolderPath) {
            # Store the processed results of the valid Signed files
            [System.Object[]]$SignedResult = @()

            # File paths of the files allowed by Signer/certificate
            [System.Object[]]$AllowedSignedFilePaths = @()

            # File paths of the files allowed by Hash
            [System.Object[]]$AllowedUnsignedFilePaths = @()

            # Stores the final object of all of the results
            [System.Object[]]$MegaOutputObject = @()

            # File paths of the Signed files with HashMismatch Status
            [System.Object[]]$SignedHashMismatchFilePaths = @()

            # File paths of the Signed files with a status that doesn't fall into any other category 
            [System.Object[]]$SignedButUnknownFilePaths = @()

            # Hash Sha256 values of all the file rules based on hash in the supplied xml policy file
            [System.Object[]]$SHA256HashesFromXML = (Get-FileRuleOutput -xmlPath $XmlFilePath).hashvalue
                        
            # Get all of the files that WDAC supports from the user provided directory
            [System.Object[]]$CollectedFiles = (Get-ChildItem -Recurse -Path $FolderPath -File -Include '*.sys', '*.exe', '*.com', '*.dll', '*.ocx', '*.msp', '*.mst', '*.msi', '*.js', '*.vbs', '*.ps1', '*.appx').FullName
                     
            # Loop through each file
            $CollectedFiles | ForEach-Object -Process {

                $CurrentFilePath = $_

                # Check see if the file's hash exists in the XML file regardless of whether it's signed or not
                # This is because WDAC policies sometimes have hash rules for signed files too
                try {
                    $CurrentFilePathHash = (Get-AppLockerFileInformation -Path $CurrentFilePath -ErrorAction Stop).hash -replace 'SHA256 0x', ''
                }
                catch {  
                    Write-Debug -Message "Get-AppLockerFileInformation failed for the file at $CurrentFilePath, using New-CIPolicyRule cmdlet..."                 
                    
                    $CurrentHashOutput = New-CIPolicyRule -Level hash -Fallback none -AllowFileNameFallbacks -UserWriteablePaths -DriverFilePath $CurrentFilePath
                  
                    $CurrentFilePathHash = ($CurrentHashOutput | Where-Object -FilterScript { $_.name -like '*Hash Sha256*' }).attributes.hash
                }
           
                # if the file's hash exists in the XML file
                if ($CurrentFilePathHash -in $SHA256HashesFromXML) {
                    $AllowedUnsignedFilePaths += $CurrentFilePath
                }
                else {                                 
                    
                    switch ((Get-AuthenticodeSignature -FilePath $CurrentFilePath).Status) {
                        # If the file is signed and valid
                        'valid' {  
                            # If debug is used show extra info on the console
                            if ($Debug) {                        
                                Write-Host "Currently processing signed file: `n$CurrentFilePath" -ForegroundColor Yellow
                            }
                            # Use the function in Resources2.ps1 file to process it
                            $SignedResult += Compare-SignerAndCertificate -XmlFilePath $XmlFilePath -SignedFilePath $CurrentFilePath | Where-Object -FilterScript { ($_.CertRootMatch -eq $true) -and ($_.CertNameMatch -eq $true) -and ($_.CertPublisherMatch -eq $true) }
                            break
                        }
                        'HashMismatch' {                  
                            $SignedHashMismatchFilePaths += $CurrentFilePath
                            break 
                        } 
                        default { $SignedButUnknownFilePaths += $CurrentFilePath; break }
                    }                  
                }              
            }
            
            # File paths of the files allowed by Signer/certificate, Unique
            [System.Object[]]$AllowedSignedFilePaths = $SignedResult.FilePath | Get-Unique            

       
            if ($AllowedUnsignedFilePaths) {
                # Loop through the first array and create output objects with the file path and source
                foreach ($Path in $AllowedUnsignedFilePaths) {
                    # Create a hash table with the file path and source
                    [System.Collections.Hashtable]$Object = @{
                        FilePath   = $Path
                        Source     = 'Hash'
                        Permission = 'Allowed'
                    }
                    # Convert the hash table to a PSObject and add it to the output array
                    $MegaOutputObject += New-Object -TypeName PSObject -Property $Object
                }  
            }          

            # For valid Signed files
            if ($AllowedSignedFilePaths) {
                # Loop through the second array and create output objects with the file path and source
                foreach ($Path in $AllowedSignedFilePaths) {
                    # Create a hash table with the file path and source properties
                    [System.Collections.Hashtable]$Object = @{
                        FilePath   = $Path
                        Source     = 'Signer'
                        Permission = 'Allowed'
                    }
                    # Convert the hash table to a PSObject and add it to the output array
                    $MegaOutputObject += New-Object -TypeName PSObject -Property $Object
                }            
            }

            # For Signed files with mismatch signature status
            if ($SignedHashMismatchFilePaths) {
                # Loop through the second array and create output objects with the file path and source
                foreach ($Path in $SignedHashMismatchFilePaths) {
                    # Create a hash table with the file path and source properties
                    [System.Collections.Hashtable]$Object = @{
                        FilePath   = $Path
                        Source     = 'Signer'
                        Permission = 'Not Allowed - Hash Mismatch'
                    }
                    # Convert the hash table to a PSObject and add it to the output array
                    $MegaOutputObject += New-Object -TypeName PSObject -Property $Object
                }            
            }

            # For Signed files with Unknown signature status
            if ($SignedButUnknownFilePaths) {
                # Loop through the second array and create output objects with the file path and source
                foreach ($Path in $SignedButUnknownFilePaths) {
                    # Create a hash table with the file path and source properties
                    [System.Collections.Hashtable]$Object = @{
                        FilePath   = $Path
                        Source     = 'Signer'
                        Permission = 'Not Allowed - Expired or unknown'
                    }
                    # Convert the hash table to a PSObject and add it to the output array
                    $MegaOutputObject += New-Object -TypeName PSObject -Property $Object
                }            
            }

            # Unique number of files allowed by hash - used for counting only
            $UniqueFilesAllowedByHash = $MegaOutputObject | Select-Object -Property FilePath, source, Permission -Unique | Where-Object -FilterScript { $_.source -eq 'hash' }

            # To detect files that are not allowed

            # Check if any supported files were found in the user provided directory and any of them were allowed
            if ($($MegaOutputObject.Filepath) -and $CollectedFiles) {
                # Compare the paths of all the supported files that were found in user provided directory with the array of files that were allowed by Signer or hash in the policy
                # Then save the output to a different array
                [System.Object[]]$FinalComparisonForFilesNotAllowed = Compare-Object -ReferenceObject $($MegaOutputObject.Filepath) -DifferenceObject $CollectedFiles -PassThru | Where-Object -FilterScript { $_.SideIndicator -eq '=>' }
            }

            # If there is any files in the user selected directory that is not allowed by the policy
            if ($FinalComparisonForFilesNotAllowed) {

                foreach ($Path in $FinalComparisonForFilesNotAllowed) {
                    # Create a hash table with the file path and source properties
                    [System.Collections.Hashtable]$Object = @{
                        FilePath   = $Path
                        Source     = 'N/A'
                        Permission = 'Not Allowed'
                    }
                    # Convert the hash table to a PSObject and add it to the output array
                    $MegaOutputObject += New-Object -TypeName PSObject -Property $Object
                }  
            }
          
            # Change the color of the Table header
            $PSStyle.Formatting.TableHeader = "$($PSStyle.Foreground.FromRGB(255,165,0))"

            # Display the final main output array as a table - allowed files   
            $MegaOutputObject | Select-Object -Property FilePath,
            
            @{
                Label      = 'Source'
                Expression =
                { switch ($_.source) {
                        { $_ -eq 'Signer' } { $color = "$($PSStyle.Foreground.FromRGB(152,255,152))" } # Use PSStyle to set the color
                        { $_ -eq 'Hash' } { $color = "$($PSStyle.Foreground.FromRGB(255,255,49))" } # Use PSStyle to set the color
                        { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(255,20,147))" } # Use PSStyle to set the color
                    }
                    "$color$($_.source)$($PSStyle.Reset)" # Use PSStyle to reset the color
                }
            }, Permission -Unique | Sort-Object -Property Permission | Format-Table -Property FilePath, Source, Permission
            
            # Showing Signature based allowed file details
            &$WriteLavender "`n$($AllowedSignedFilePaths.count) File(s) Inside the Selected Folder Are Allowed by Signatures by Your Policy."
            
            # Showing Hash based allowed file details
            &$WriteLavender "$($UniqueFilesAllowedByHash.count) File(s) Inside the Selected Folder Are Allowed by Hashes by Your Policy.`n"
                        
            # Export the output as CSV
            $MegaOutputObject | Select-Object -Property FilePath, source, Permission -Unique | Sort-Object -Property Permission | Export-Csv -Path .\WDACSimulationOutput.csv -Force

            if ($Debug) {
                Write-Host 'Files that were UNSIGNED' -ForegroundColor Blue
                $AllowedUnsignedFilePaths
            }        
           
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
Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
Register-ArgumentCompleter -CommandName 'Invoke-WDACSimulation' -ParameterName 'FolderPath' -ScriptBlock $ArgumentCompleterFolderPathsPicker
Register-ArgumentCompleter -CommandName 'Invoke-WDACSimulation' -ParameterName 'XmlFilePath' -ScriptBlock $ArgumentCompleterXmlFilePathsPicker
