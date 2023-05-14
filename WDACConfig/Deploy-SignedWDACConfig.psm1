#Requires -RunAsAdministrator
function Deploy-SignedWDACConfig {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    Param(
        [ValidatePattern('\.cer$')]
        [ValidateScript({ Test-Path $_ -PathType 'Leaf' }, ErrorMessage = "The path you selected is not a file path.")]
        [parameter(Mandatory = $true)][System.String]$CertPath,

        [ValidatePattern('\.xml$')]
        [ValidateScript({ Test-Path $_ -PathType 'Leaf' }, ErrorMessage = "The path you selected is not a file path.")]
        [parameter(Mandatory = $true)][System.String[]]$PolicyPaths,

        [ValidateScript({
                try {
                    # TryCatch to show a custom error message instead of saying input is null when personal store is empty 
                    ((Get-ChildItem -ErrorAction Stop -Path 'Cert:\CurrentUser\My').Subject.Substring(3)) -contains $_            
                }
                catch {
                    Write-Error -Message "A certificate with the provided common name doesn't exist in the personal store of the user certificates."
                } # this error msg is shown when cert CN is not available in the personal store of the user certs
            }, ErrorMessage = "A certificate with the provided common name doesn't exist in the personal store of the user certificates." )]
        [parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][System.String]$CertCN,

        [ValidatePattern('\.exe$')]
        [ValidateScript({ # Setting the minimum version of SignTool that is allowed to be executed as well as other checks
                [System.Version]$WindowsSdkVersion = '10.0.22621.755'
                (((get-item -Path $_).VersionInfo).ProductVersionRaw -ge $WindowsSdkVersion)
                (((get-item -Path $_).VersionInfo).FileVersionRaw -ge $WindowsSdkVersion)
                ((get-item -Path $_).VersionInfo).CompanyName -eq 'Microsoft Corporation'
                ((Get-AuthenticodeSignature -FilePath $_).Status -eq 'Valid')
                ((Get-AuthenticodeSignature -FilePath $_).StatusMessage -eq 'Signature verified.')
            }, ErrorMessage = "The SignTool executable was found but couldn't be verified. Please download the latest Windows SDK to get the newest SignTool executable. Official download link: http://aka.ms/WinSDK")]
        [parameter(ValueFromPipelineByPropertyName = $true)]
        [System.String]$SignToolPath,
        
        [Parameter(Mandatory = $false)][Switch]$SkipVersionCheck
    )

    begin {
        # Importing resources such as functions by dot-sourcing so that they will run in the same scope and their variables will be usable
        . "$psscriptroot\Resources.ps1"
        # Stop operation as soon as there is an error anywhere, unless explicitly specified otherwise
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
            
            # Old Method:  & $SignToolPath sign -v -n $CertCN -p7 . -p7co 1.3.6.1.4.1.311.79.1 -fd certHash ".\$PolicyID.cip"
            # Configure the parameter splat
            $ProcessParams = @{
                'ArgumentList' = 'sign', '/v' , '/n', "`"$CertCN`"", '/p7', '.', '/p7co', '1.3.6.1.4.1.311.79.1', '/fd', 'certHash', ".\$PolicyID.cip"
                'FilePath'     = ($SignToolPath ? (Get-SignTool -SignToolExePath $SignToolPath) : (Get-SignTool))           
                'NoNewWindow'  = $true
                'Wait'         = $true
            }
            # Sign the files with the specified cert
            Start-Process @ProcessParams

            Remove-Item ".\$PolicyID.cip" -Force            
            Rename-Item "$PolicyID.cip.p7" -NewName "$PolicyID.cip" -Force
            CiTool --update-policy ".\$PolicyID.cip" -json
            Write-host "`n`npolicy with the following details has been Signed and Deployed in Enforced Mode:" -ForegroundColor Green        
            Write-Output "PolicyName = $PolicyName"
            Write-Output "PolicyGUID = $PolicyID`n"
        }
    }

    <#
.SYNOPSIS
Signs and Deploys WDAC policies, accepts signed or unsigned policies and deploys them

.LINK
https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-SignedWDACConfig

.DESCRIPTION
Using official Microsoft methods, Signs and Deploys WDAC policies, accepts signed or unsigned policies and deploys them (Windows Defender Application Control)

.COMPONENT
Windows Defender Application Control, ConfigCI PowerShell module

.FUNCTIONALITY
Using official Microsoft methods, Signs and Deploys WDAC policies, accepts signed or unsigned policies and deploys them (Windows Defender Application Control)

.PARAMETER CertPath
Path to the certificate .cer file

.PARAMETER PolicyPaths
Path to the policy xml files that are going to be signed

.PARAMETER CertCN
Certificate common name

.PARAMETER SignToolPath
Path to the SignTool.exe - optional parameter

.PARAMETER SkipVersionCheck
Can be used with any parameter to bypass the online version check - only to be used in rare cases

#>
}

# Importing argument completer ScriptBlocks
. "$psscriptroot\ArgumentCompleters.ps1"
# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete
Register-ArgumentCompleter -CommandName "Deploy-SignedWDACConfig" -ParameterName "CertCN" -ScriptBlock $ArgumentCompleterCertificateCN
Register-ArgumentCompleter -CommandName "Deploy-SignedWDACConfig" -ParameterName "PolicyPaths" -ScriptBlock $ArgumentCompleterPolicyPaths
Register-ArgumentCompleter -CommandName "Deploy-SignedWDACConfig" -ParameterName "CertPath" -ScriptBlock $ArgumentCompleterCertPath
Register-ArgumentCompleter -CommandName "Deploy-SignedWDACConfig" -ParameterName "SignToolPath" -ScriptBlock $ArgumentCompleterSignToolPath
