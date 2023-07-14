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
        [Parameter(Mandatory = $false)][string]$FilePath,
        [Parameter(Mandatory = $false)][string]$FolderPath,
        [Parameter(Mandatory = $true)][string]$XmlFilePath,

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

            $Result = @()
            (Get-ChildItem -Recurse -Path $FolderPath -File -Include "*.sys", "*.exe", "*.com", "*.dll", "*.ocx", "*.msp", "*.mst", "*.msi", "*.js", "*.vbs", "*.ps1", "*.appx").FullName | Where-Object { (Get-AuthenticodeSignature -FilePath $_).Status -eq 'valid' } | ForEach-Object {
                $currentObjcc = $_   
                $Result += Compare-SignerAndCertificate -XmlFilePath $XmlFilePath -SignedFilePath $currentObjcc | Where-Object { $_.CertNameMatch -eq $true }
            }
        
          
        
            $Result = $Result.FilePath | Get-Unique
            $Result
            $Result.count
        
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