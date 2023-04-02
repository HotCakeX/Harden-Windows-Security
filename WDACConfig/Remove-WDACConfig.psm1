#requires -version 7.3.3
Function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
if (-NOT (Test-IsAdmin)) {
    write-host "Administrator privileges Required" -ForegroundColor Magenta
    break
}
function Remove-WDACConfig {
    [CmdletBinding(      
        DefaultParameterSetName = "set1",  
        HelpURI = "https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig",
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    Param(        
        [Parameter(Mandatory = $false, ParameterSetName = "set1", Position = 0, ValueFromPipeline = $true)][switch]$RemoveSignedPolicies,
        [Parameter(Mandatory = $false, ParameterSetName = "set2", Position = 0, ValueFromPipeline = $true)][switch]$RemovePolicies,

        [parameter(Mandatory = $true, ParameterSetName = "set1", ValueFromPipelineByPropertyName = $true)][string[]]$PolicyPaths,
        [parameter(Mandatory = $false, ParameterSetName = "set1", ValueFromPipelineByPropertyName = $true)][string]$SignToolPath,
        [parameter(Mandatory = $true, ParameterSetName = "set1", ValueFromPipelineByPropertyName = $true)][string]$CertCN,        
        
        [ValidateSet([PolicyIDz])][parameter(Mandatory = $false, ParameterSetName = "set2")][string[]]$PolicyIDs,
        [ValidateSet([PolicyNamez])][parameter(Mandatory = $false, ParameterSetName = "set2")][string[]]$PolicyNames,

        [Parameter(Mandatory = $false)][switch]$SkipVersionCheck
    )
    $ErrorActionPreference = 'Stop'
    
    # argument tab auto-completion and ValidateSet for Policy names 
    Class PolicyNamez : System.Management.Automation.IValidateSetValuesGenerator {
        [string[]] GetValidValues() {
            $PolicyNamez = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.IsSystemPolicy -ne "True" }).Friendlyname
           
            return [string[]]$PolicyNamez
        }
    }   
    
    # argument tab auto-completion and ValidateSet for Policy IDs     
    Class PolicyIDz : System.Management.Automation.IValidateSetValuesGenerator {
        [string[]] GetValidValues() {
            $PolicyIDz = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.IsSystemPolicy -ne "True" }).policyID
           
            return [string[]]$PolicyIDz
        }
    }
    

    if (-NOT $SkipVersionCheck) {
        # Make sure the latest version of the module is installed and if not, automatically update it, clean up any old versions
        $currentversion = (Test-modulemanifest "$psscriptroot\WDACConfig.psd1").Version.ToString()
        try {
            $latestversion = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/WDACConfig/version.txt"
        }
        catch {
            Write-Error "Couldn't verify if the latest version of the module is installed, please check your Internet connection. You can optionally bypass the online check by using -SkipVersionCheck parameter."
            break
        }
        if (-NOT ($currentversion -eq $latestversion)) {
            Write-Host "The currently installed module's version is $currentversion while the latest version is $latestversion - Auto Updating the module now and will run your command after that 💓"
            Remove-Module -Name WDACConfig -Force
            Uninstall-Module -Name WDACConfig -AllVersions -Force  
            Install-Module -Name WDACConfig -RequiredVersion $latestversion -Force              
            Import-Module -Name WDACConfig -RequiredVersion $latestversion -Force -Global
        }
    }


    if ($RemoveSignedPolicies) {
        foreach ($PolicyPath in $PolicyPaths) {
            # sanitize the policy file by removing SupplementalPolicySigners
            $xml = [xml](Get-Content $PolicyPath)
            $SuppSingerIDs = $xml.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
            $PolicyName = ($xml.SiPolicy.Settings.Setting | Where-Object { $_.provider -eq "PolicyInfo" -and $_.valuename -eq "Name" -and $_.key -eq "Information" }).value.string
            if ($SuppSingerIDs) {
                Write-host "`n$($SuppSingerIDs.count) SupplementalPolicySigners have been found in $PolicyName policy, removing them now..." -ForegroundColor Yellow    
                $SuppSingerIDs | ForEach-Object {
                    $PolContent = Get-Content -Raw -Path $PolicyPath        
                    $PolContent -match "<Signer ID=`"$_`"[\S\s]*</Signer>" | Out-Null
                    $PolContent = $PolContent -replace $Matches[0], ""
                    Set-Content -Value $PolContent -Path $PolicyPath
                }
                $PolContent -match "<SupplementalPolicySigners>[\S\s]*</SupplementalPolicySigners>" | Out-Null     
                $PolContent = $PolContent -replace $Matches[0], ""
                Set-Content -Value $PolContent -Path $PolicyPath
            
                # remove empty lines from the entire policy file       
                (Get-Content -Path $PolicyPath) | Where-Object { $_.trim() -ne "" } | set-content -Path $PolicyPath -Force
                Write-host "Policy successfully sanitized and all SupplementalPolicySigners have been removed." -ForegroundColor Green
            }
            else {
                Write-host "`nNo sanitization required because no SupplementalPolicySigners have been found in $PolicyName policy." -ForegroundColor Green
            }
                
            Set-RuleOption -FilePath $PolicyPath -Option 6       
            $PolicyID = $xml.SiPolicy.PolicyID
            ConvertFrom-CIPolicy $PolicyPath "$PolicyID.cip" | Out-Null
            
            if ($SignToolPath) {
                $SignToolPath = $SignToolPath
            }
            else {
                if ($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
                    if ( Test-Path -Path "C:\Program Files (x86)\Windows Kits\*\bin\*\x64\signtool.exe") {
                        $SignToolPath = "C:\Program Files (x86)\Windows Kits\*\bin\*\x64\signtool.exe" 
                    }
                    else {
                        Write-Error "signtool.exe couldn't be found"
                        break
                    }
                }
                elseif ($Env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
                    if (Test-Path -Path "C:\Program Files (x86)\Windows Kits\*\bin\*\arm64\signtool.exe") {
                        $SignToolPath = "C:\Program Files (x86)\Windows Kits\*\bin\*\arm64\signtool.exe"
                    }
                    else {
                        Write-Error "signtool.exe couldn't be found"
                        break
                    }
                }           
            }                    
            & $SignToolPath sign -v -n $CertCN -p7 . -p7co 1.3.6.1.4.1.311.79.1 -fd certHash ".\$PolicyID.cip"                          
            Remove-Item ".\$PolicyID.cip" -Force
            Rename-Item "$PolicyID.cip.p7" -NewName "$PolicyID.cip" -Force  
            CiTool --update-policy ".\$PolicyID.cip" -json
            Write-host "`n`nPolicy with the following details has been Re-signed and Re-deployed in Unsigned mode:" -ForegroundColor Green        
            Write-Output "PolicyName = $PolicyName"
            Write-Output "PolicyGUID = $PolicyID`n"           
        }
    }

    if ($RemovePolicies) {
        foreach ($ID in $PolicyIDs ) {
            citool --remove-policy "{$ID}"
        }
        foreach ($PolicyName in $PolicyNames) {                    
            $NameID = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.FriendlyName -eq $PolicyName }).PolicyID                                   
            citool --remove-policy "{$NameID}"
        }      
    }

    <#
.SYNOPSIS
Automate a lot of tasks related to WDAC (Windows Defender Application Control)

.LINK
https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig

.DESCRIPTION
Using official Microsoft methods, configure and use Windows Defender Application Control

.COMPONENT
Windows Defender Application Control

.FUNCTIONALITY
Automate various tasks related to Windows Defender Application Control (WDAC)

.PARAMETER RemoveSignedPolicies
Remove Signed WDAC Policies

.PARAMETER RemovePolicies
Removes Unsigned deployed WDAC policies as well as Signed deployed Supplemental WDAC policies


#>
}

# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete

# argument tab auto-completion for Certificate common name
$ArgumentCompleterCertificateCN = {

    $var = certutil -asn $CertPath

    $cnFound = $false
    $count = 0
    foreach ($line in $var -split "`n") {
        if ($line -match '\(cn\)') {
            if ($count -eq 0) {
                $count++
            }
            elseif ($count -eq 1) {
                $cnFound = $true
            }
            continue
        }
        if ($cnFound -and $line -match '"(.+)"') {
            $regexString = $matches[1]
            break
        }
    }                

    $CertStoreResults = (Get-ChildItem -Path 'Cert:\CurrentUser\My').Subject.Substring(3)
    foreach ($item in $CertStoreResults) {
        if ($item -eq $regexString) {
            $finalResult = $item 
        }
    }
    if (-NOT $finalResult) {
        $finalResult = (Get-ChildItem -Path 'Cert:\CurrentUser\My').Subject.Substring(3) | Where-Object { $_ -NotLike "*, DC=*" }
    }
    return "`"$finalResult`""
}
Register-ArgumentCompleter -CommandName "Remove-WDACConfig" -ParameterName "CertCN" -ScriptBlock $ArgumentCompleterCertificateCN


# argument tab auto-completion for Policy Paths to show only .xml files and only base policies
$ArgumentCompleterPolicyPaths = {
    Get-ChildItem | where-object { $_.extension -like '*.xml' } | foreach-object { return "`"$_`"" }
}
Register-ArgumentCompleter -CommandName "Remove-WDACConfig" -ParameterName "PolicyPaths" -ScriptBlock $ArgumentCompleterPolicyPaths


# argument tab auto-completion for Certificate Path to show only .cer files
$ArgumentCompleterCertPath = {
    Get-ChildItem | where-object { $_.extension -like '*.cer' } | foreach-object { return "`"$_`"" }   
}
Register-ArgumentCompleter -CommandName "Remove-WDACConfig" -ParameterName "CertPath" -ScriptBlock $ArgumentCompleterCertPath


# argument tab auto-completion for Certificate Path to show only .cer files
$ArgumentCompleterSignToolPath = {
    Get-ChildItem | where-object { $_.extension -like '*.exe' } | foreach-object { return "`"$_`"" }
}
Register-ArgumentCompleter -CommandName "Remove-WDACConfig" -ParameterName "SignToolPath" -ScriptBlock $ArgumentCompleterSignToolPath
