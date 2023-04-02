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
function Deploy-SignedWDACConfig {
    [CmdletBinding(
        HelpURI = "https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Module",
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    Param(
        [parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$CertPath,       
        [parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string[]]$PolicyPaths,
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][string]$SignToolPath,
        [parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][string]$CertCN,
        [Parameter(Mandatory = $false)][switch]$SkipVersionCheck
    )

    $ErrorActionPreference = 'Stop'         


    # Make sure the latest version of the module is installed and if not, automatically update it, clean up any old versions
    if (-NOT $SkipVersionCheck) {
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
            try {
                Uninstall-Module -Name WDACConfig -AllVersions -Force -ErrorAction Stop
                Install-Module -Name WDACConfig -RequiredVersion $latestversion -Force              
                Import-Module -Name WDACConfig -RequiredVersion $latestversion -Force -Global
            }
            catch {
                Install-Module -Name WDACConfig -RequiredVersion $latestversion -Force
                Import-Module -Name WDACConfig -RequiredVersion $latestversion -Force -Global
            }
            
        }
    }


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
            Write-host "`n`npolicy with the following details has been Signed and Deployed in Enforcement Mode:" -ForegroundColor Green        
            Write-Output "PolicyName = $PolicyName"
            Write-Output "PolicyGUID = $PolicyID`n"
        }


    <#
.SYNOPSIS
Automate a lot of tasks related to WDAC (Windows Defender Application Control)

.LINK
https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig

.DESCRIPTION
Using official Microsoft methods, configure and use Windows Defender Application Control

.COMPONENT
Windows Defender Application Control

.FUNCTIONALITY
Automate various tasks related to Windows Defender Application Control (WDAC)

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
Register-ArgumentCompleter -CommandName "Deploy-SignedWDACConfig" -ParameterName "CertCN" -ScriptBlock $ArgumentCompleterCertificateCN


# argument tab auto-completion for Policy Paths to show only .xml files and only base policies
$ArgumentCompleterPolicyPaths = {
    Get-ChildItem | where-object { $_.extension -like '*.xml' } | foreach-object { return "`"$_`"" }
}
Register-ArgumentCompleter -CommandName "Deploy-SignedWDACConfig" -ParameterName "PolicyPaths" -ScriptBlock $ArgumentCompleterPolicyPaths


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
