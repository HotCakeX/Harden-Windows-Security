#Requires -RunAsAdministrator       
function Invoke-WDACSimulation {
    [CmdletBinding(
        PositionalBinding = $false,
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    Param(
        [ValidateScript({
        (Get-AuthenticodeSignature -FilePath $_).Status -eq 'valid'
            }, ErrorMessage = "The Selected file doesn't have a valid certificate"
        )]
        [Parameter(Mandatory = $false)][System.String]$FilePath,
        [Parameter(Mandatory = $false)][System.String]$FolderPath,
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
            # Store the results of the Unsigned files
            $UnSignedResult = @()
            # Get all of the files that WDAC supports from the user provided directory
            $CollectedFiles = (Get-ChildItem -Recurse -Path $FolderPath -File -Include "*.sys", "*.exe", "*.com", "*.dll", "*.ocx", "*.msp", "*.mst", "*.msi", "*.js", "*.vbs", "*.ps1", "*.appx").FullName

            # Loop through each file
            $CollectedFiles | ForEach-Object {
                # If the file is signed and valid
                if ((Get-AuthenticodeSignature -FilePath $_).Status -eq 'valid') {
                    $CurrentFile = $_ 
                    $SignedResult += Compare-SignerAndCertificate -XmlFilePath $XmlFilePath -SignedFilePath $CurrentFile | Where-Object { $_.CertRootMatch -eq $true }
                }  
                # If the file is signed and invalid              
                elseif ((Get-AuthenticodeSignature -FilePath $_).Status -eq 'HashMismatch') {
                    Write-Warning "The file $CurrentFile is tampered and unsafe to use."
                }
                # if the file is Unsigned
                else {
                    $SHA256Hash = Get-FileHash -Algorithm SHA256 -Path $CurrentFile
                    $SHA1Hash = Get-FileHash -Algorithm SHA1 -Path $CurrentFile
                }
            
            }           
        
          
            # Showing Signed file details
            &$WriteLavender "The following Signed files are allowed in the policy"
            $SignedResult = $SignedResult.FilePath | Get-Unique
            $SignedResult
            $SignedResult.count
        
        }

        if ($FilePath) {

            $Result = Compare-SignerAndCertificate -XmlFilePath $XmlFilePath -SignedFilePath $FilePath | Where-Object { $_.CertNameMatch -eq $true }
            $Result.FilePath | Get-Unique
        }

    } 
   


}

# Importing argument completer ScriptBlocks
. "$psscriptroot\ArgumentCompleters.ps1"
# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete


Register-ArgumentCompleter -CommandName "Invoke-WDACSimulation" -ParameterName "FolderPath" -ScriptBlock $ArgumentCompleterFolderPathsPicker
Register-ArgumentCompleter -CommandName "Invoke-WDACSimulation" -ParameterName "FilePath" -ScriptBlock $ArgumentCompleterALLFilePathsPicker
Register-ArgumentCompleter -CommandName "Invoke-WDACSimulation" -ParameterName "XmlFilePath" -ScriptBlock $ArgumentCompleterXmlFilePathsPicker