#Requires -RunAsAdministrator
function Deploy-SignedWDACConfig {
    [CmdletBinding(
        HelpURI = "https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig",
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    Param(
        [ValidatePattern('\.cer$')][ValidateScript({ Test-Path $_ -PathType Leaf }, ErrorMessage = "The path you selected is not a file path.")]
        [parameter(Mandatory = $true)][string]$CertPath,

        [ValidatePattern('\.xml$')][ValidateScript({ Test-Path $_ -PathType Leaf }, ErrorMessage = "The path you selected is not a file path.")]
        [parameter(Mandatory = $true)][string[]]$PolicyPaths,

        [ValidateScript({
                try {
                    # TryCatch to show a custom error message instead of saying input is null when personal store is empty 
                    ((Get-ChildItem -ErrorAction Stop -Path 'Cert:\CurrentUser\My').Subject.Substring(3)) -contains $_            
                }
                catch {
                    Write-Error "A certificate with the provided common name doesn't exist in the personal store of the user certificates."
                } # this error msg is shown when cert CN is not available in the personal store of the user certs
            }, ErrorMessage = "A certificate with the provided common name doesn't exist in the personal store of the user certificates." )]
        [parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$CertCN,

        [ValidatePattern('\.exe$')][parameter(Mandatory = $false)][string]$SignToolPath,
        
        [Parameter(Mandatory = $false)][switch]$SkipVersionCheck
    )

    begin {
        # Importing resources such as functions by dot-sourcing so that they will run in the same scope and their variables will be usable
        . "$psscriptroot\Resources.ps1"

        # Stop operation as soon as there is an error, anywhere, unless explicitly specified otherwise
        $ErrorActionPreference = 'Stop'         
        if (-NOT $SkipVersionCheck) { . Update-self }       
    }

    process {

        foreach ($PolicyPath in $PolicyPaths) {
            $xml = [xml](Get-Content $PolicyPath)
            $PolicyType = $xml.SiPolicy.PolicyType
            $PolicyID = $xml.SiPolicy.PolicyID
            $PolicyName = ($xml.SiPolicy.Settings.Setting | Where-Object { $_.provider -eq "PolicyInfo" -and $_.valuename -eq "Name" -and $_.key -eq "Information" }).value.string
            Remove-Item -Path ".\$PolicyID.cip" -ErrorAction SilentlyContinue
            if ($PolicyType -eq "Supplemental Policy") {          
                Add-SignerRule -FilePath $PolicyPath -CertificatePath $CertPath -Update -User -Kernel
            }
            else {            
                Add-SignerRule -FilePath $PolicyPath -CertificatePath $CertPath -Update -User -Kernel -Supplemental
            }
            Set-HVCIOptions -Strict -FilePath $PolicyPath
            Set-RuleOption -FilePath $PolicyPath -Option 6 -Delete
            ConvertFrom-CIPolicy $PolicyPath "$PolicyID.cip" | Out-Null

            . Get-SignTool

            & $SignToolPath sign -v -n $CertCN -p7 . -p7co 1.3.6.1.4.1.311.79.1 -fd certHash ".\$PolicyID.cip"              
            Remove-Item ".\$PolicyID.cip" -Force            
            Rename-Item "$PolicyID.cip.p7" -NewName "$PolicyID.cip" -Force
            CiTool --update-policy ".\$PolicyID.cip" -json
            Write-host "`n`npolicy with the following details has been Signed and Deployed in Enforcement Mode:" -ForegroundColor Green        
            Write-Output "PolicyName = $PolicyName"
            Write-Output "PolicyGUID = $PolicyID`n"
        }
    }

    <#
.SYNOPSIS
Signs and Deploys WDAC policies, accepts signed or unsigned policies and deploys them

.LINK
https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig

.DESCRIPTION
Using official Microsoft methods, Signs and Deploys WDAC policies, accepts signed or unsigned policies and deploys them (Windows Defender Application Control)

.COMPONENT
Windows Defender Application Control

.FUNCTIONALITY
Using official Microsoft methods, Signs and Deploys WDAC policies, accepts signed or unsigned policies and deploys them (Windows Defender Application Control)

.PARAMETER Sign_Deploy_Policies 
Sign and deploy WDAC policies

.PARAMETER SkipVersionCheck
Can be used with any parameter to bypass the online version check - only to be used in rare cases

#>
}

# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete

# argument tab auto-completion for Certificate common name
$ArgumentCompleterCertificateCN = {
     
    $CNs = (Get-ChildItem -Path 'Cert:\CurrentUser\My').Subject.Substring(3) | Where-Object { $_ -NotLike "*, DC=*" } |
    ForEach-Object {
            
        if ($_ -like "*CN=*") {
            
            $_ -match "CN=(?<cn>[^,]+)" | Out-Null
        
            return $Matches['cn']
        }
        else { return $_ }
    }   
    
    $CNs | foreach-object { return "`"$_`"" }
}
Register-ArgumentCompleter -CommandName "Deploy-SignedWDACConfig" -ParameterName "CertCN" -ScriptBlock $ArgumentCompleterCertificateCN


# argument tab auto-completion for Policy Paths to show only .xml files and only suggest files that haven't been already selected by user 
# https://stackoverflow.com/questions/76141864/how-to-make-a-powershell-argument-completer-that-only-suggests-files-not-already/76142865
Register-ArgumentCompleter `
    -CommandName Deploy-SignedWDACConfig `
    -ParameterName PolicyPaths `
    -ScriptBlock {
    # Get the current command and the already bound parameters
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    # Find all string constants in the AST that end in ".xml"
    $existing = $commandAst.FindAll({ 
            $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and 
            $args[0].Value -like '*.xml' 
        }, 
        $false
    ).Value  

    # Get the xml files in the current directory
    Get-ChildItem -Filter *.xml | ForEach-Object {
        # Check if the file is already selected
        if ($_.FullName -notin $existing) {
            # Return the file name with quotes
            "`"$_`""
        }
    }
}
 

# argument tab auto-completion for Certificate Path to show only .cer files
$ArgumentCompleterCertPath = {
    Get-ChildItem | where-object { $_.extension -like '*.cer' } | foreach-object { return "`"$_`"" }   
}
Register-ArgumentCompleter -CommandName "Deploy-SignedWDACConfig" -ParameterName "CertPath" -ScriptBlock $ArgumentCompleterCertPath


# argument tab auto-completion for Certificate Path to show only .cer files
$ArgumentCompleterSignToolPath = {
    Get-ChildItem | where-object { $_.extension -like '*.exe' } | foreach-object { return "`"$_`"" }
}
Register-ArgumentCompleter -CommandName "Deploy-SignedWDACConfig" -ParameterName "SignToolPath" -ScriptBlock $ArgumentCompleterSignToolPath
