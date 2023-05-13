#Requires -RunAsAdministrator
function Remove-WDACConfig {
    [CmdletBinding(      
        DefaultParameterSetName = "Signed Base",
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    Param(        
        [Parameter(Mandatory = $false, ParameterSetName = "Signed Base")][Switch]$SignedBase,                                                                                            
        [Parameter(Mandatory = $false, ParameterSetName = "Unsigned Or Supplemental")][Switch]$UnsignedOrSupplemental,

        [ValidatePattern('\.xml$')]
        [ValidateScript({
                # Validate each Policy file in PolicyPaths parameter to make sure the user isn't accidentally trying to
                # remove an Unsigned policy
                $_ | ForEach-Object {                   
                    $xmlTest = [xml](Get-Content $_)
                    $RedFlag1 = $xmlTest.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
                    $RedFlag2 = $xmlTest.SiPolicy.UpdatePolicySigners.UpdatePolicySigner.SignerId
                    if ($RedFlag1 -or $RedFlag2) { return $True }                   
                }
            }, ErrorMessage = "The policy XML file(s) you chose are Unsigned policies. Please use Remove-WDACConfig cmdlet with -UnsignedOrSupplemental parameter instead.")]
        [parameter(Mandatory = $true, ParameterSetName = "Signed Base", ValueFromPipelineByPropertyName = $true)]
        [System.String[]]$PolicyPaths,
        
        [ValidateScript({
                try {
                    # TryCatch to show a custom error message instead of saying input is null when personal store is empty 
                ((Get-ChildItem -ErrorAction Stop -Path 'Cert:\CurrentUser\My').Subject.Substring(3)) -contains $_            
                }
                catch {
                    Write-Error -Message "A certificate with the provided common name doesn't exist in the personal store of the user certificates."
                } # this error msg is shown when cert CN is not available in the personal store of the user certs
            }, ErrorMessage = "A certificate with the provided common name doesn't exist in the personal store of the user certificates." )]
        [parameter(Mandatory = $true, ParameterSetName = "Signed Base", ValueFromPipelineByPropertyName = $true)]
        [System.String]$CertCN,

        # https://stackoverflow.com/questions/76143006/how-to-prevent-powershell-validateset-argument-completer-from-suggesting-the-sam/76143269
        [ArgumentCompleter({
                param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
                $candidates = [PolicyIDz]::new().GetValidValues()
                $existing = $commandAst.FindAll({ 
                        $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    }, 
                    $false
                ).Value  
                Compare-Object -PassThru $candidates $existing | Where-Object SideIndicator -eq '<='
            })]
        [ValidateScript({
                if ($_ -notin [PolicyIDz]::new().GetValidValues()) { throw "Invalid policy ID: $_" }
                $true
            })]
        [Parameter(Mandatory = $false, ParameterSetName = "Unsigned Or Supplemental")]
        [System.String[]]$PolicyIDs,

        # https://stackoverflow.com/questions/76143006/how-to-prevent-powershell-validateset-argument-completer-from-suggesting-the-sam/76143269
        [ArgumentCompleter({
                param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
                $candidates = [PolicyNamez]::new().GetValidValues()
                $existing = $commandAst.FindAll({ 
                        $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    }, 
                    $false
                ).Value  
          (Compare-Object -PassThru $candidates $existing | Where-Object SideIndicator -eq '<=').
                ForEach({ if ($_ -match ' ') { "'{0}'" -f $_ } else { $_ } })
            })]
        [ValidateScript({
                if ($_ -notin [PolicyNamez]::new().GetValidValues()) { throw "Invalid policy name: $_" }
                $true
            })]
        [Parameter(Mandatory = $false, ParameterSetName = "Unsigned Or Supplemental")]
        [System.String[]]$PolicyNames,

        [ValidatePattern('\.exe$')]
        [ValidateScript({ # Setting the minimum version of SignTool that is allowed to be executed as well as other checks
                [System.Version]$WindowsSdkVersion = '10.0.22621.755'
                (((get-item -Path $_).VersionInfo).ProductVersionRaw -ge $WindowsSdkVersion)
                (((get-item -Path $_).VersionInfo).FileVersionRaw -ge $WindowsSdkVersion)
                ((get-item -Path $_).VersionInfo).CompanyName -eq 'Microsoft Corporation'
                ((Get-AuthenticodeSignature -FilePath $_).Status -eq 'Valid')
                ((Get-AuthenticodeSignature -FilePath $_).StatusMessage -eq 'Signature verified.')
            }, ErrorMessage = "The SignTool executable was found but couldn't be verified. Please download the latest Windows SDK to get the newest SignTool executable. Official download link: http://aka.ms/WinSDK")]
        [parameter(Mandatory = $false, ParameterSetName = "Signed Base", ValueFromPipelineByPropertyName = $true)]
        [System.String]$SignToolPath,

        [Parameter(Mandatory = $false)][Switch]$SkipVersionCheck
    )

    begin {
        # Importing resources such as functions by dot-sourcing so that they will run in the same scope and their variables will be usable
        . "$psscriptroot\Resources.ps1"

        # Detecting if Debug switch is used, will do debugging actions based on that
        $Debug = $PSBoundParameters.Debug.IsPresent

        # Stop operation as soon as there is an error, anywhere, unless explicitly specified otherwise
        $ErrorActionPreference = 'Stop'
        if (-NOT $SkipVersionCheck) { . Update-self }

        # argument tab auto-completion and ValidateSet for Policy names 
        Class PolicyNamez : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $PolicyNamez = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.IsSystemPolicy -ne "True" }).Friendlyname
   
                return [System.String[]]$PolicyNamez
            }
        }   

        # argument tab auto-completion and ValidateSet for Policy IDs     
        Class PolicyIDz : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $PolicyIDz = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.IsSystemPolicy -ne "True" }).policyID
   
                return [System.String[]]$PolicyIDz
            }
        }    
    }
    
    process {

        if ($SignedBase) {
            foreach ($PolicyPath in $PolicyPaths) {
                $xml = [xml](Get-Content $PolicyPath)
                $PolicyID = $xml.SiPolicy.PolicyID
                # Prevent users from accidentally attempting to remove policies that aren't even deployed on the system
                $CurrentPolicyIDs = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.IsSystemPolicy -ne "True" }).policyID | ForEach-Object { "{$_}" }
                Write-Debug -Message "The policy ID of the currently processing xml file is $PolicyID"
                if ($CurrentPolicyIDs -notcontains $PolicyID) {                                        
                    Write-Error -Message "The selected policy file isn't deployed on the system." -ErrorAction Stop                    
                }

                ######################## Sanitize the policy file by removing SupplementalPolicySigners ######################## 
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
                ConvertFrom-CIPolicy $PolicyPath "$PolicyID.cip" | Out-Null
                
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
                Write-host "`n`nPolicy with the following details has been Re-signed and Re-deployed in Unsigned mode:" -ForegroundColor Green        
                Write-Output "PolicyName = $PolicyName"
                Write-Output "PolicyGUID = $PolicyID`n"           
            }
        }
    
        if ($UnsignedOrSupplemental) {

            # If IDs were supplied by user
            foreach ($ID in $PolicyIDs ) {
                citool --remove-policy "{$ID}" -json
            }
            
            # If names were supplied by user
            # Empty array to store Policy IDs based on the input name, this will take care of the situations where multiple policies with the same name are deployed
            $NameID = @()
            foreach ($PolicyName in $PolicyNames) {                    
                $NameID += ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.FriendlyName -eq $PolicyName }).PolicyID
            }
            
            Write-Debug -Message "The Following policy IDs have been gathered from the supplied policy names and are going to be removed from the system"
            if ($Debug) { $NameID | Select-Object -Unique | foreach-object { Write-Debug -Message "$_" } }
            
            $NameID | Select-Object -Unique | ForEach-Object {
                citool --remove-policy "{$_}" -json 
            }     
        }
    } 
   
    <#
.SYNOPSIS
Removes Signed and unsigned deployed WDAC policies (Windows Defender Application Control)

.LINK
https://github.com/HotCakeX/Harden-Windows-Security/wiki/Remove-WDACConfig

.DESCRIPTION
Using official Microsoft methods, Removes Signed and unsigned deployed WDAC policies (Windows Defender Application Control)

.COMPONENT
Windows Defender Application Control, ConfigCI PowerShell module

.FUNCTIONALITY
Using official Microsoft methods, Removes Signed and unsigned deployed WDAC policies (Windows Defender Application Control)

.PARAMETER SignedBase
Remove Signed Base WDAC Policies

.PARAMETER UnsignedOrSupplemental
Remove Unsigned deployed WDAC policies as well as Signed deployed Supplemental WDAC policies

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
Register-ArgumentCompleter -CommandName "Remove-WDACConfig" -ParameterName "CertCN" -ScriptBlock $ArgumentCompleterCertificateCN


# argument tab auto-completion for Policy Paths to show only .xml files and only suggest files that haven't been already selected by user 
# https://stackoverflow.com/questions/76141864/how-to-make-a-powershell-argument-completer-that-only-suggests-files-not-already/76142865
Register-ArgumentCompleter `
    -CommandName Remove-WDACConfig `
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
Register-ArgumentCompleter -CommandName "Remove-WDACConfig" -ParameterName "CertPath" -ScriptBlock $ArgumentCompleterCertPath


# argument tab auto-completion for Certificate Path to show only .cer files
$ArgumentCompleterSignToolPath = {
    Get-ChildItem | where-object { $_.extension -like '*.exe' } | foreach-object { return "`"$_`"" }
}
Register-ArgumentCompleter -CommandName "Remove-WDACConfig" -ParameterName "SignToolPath" -ScriptBlock $ArgumentCompleterSignToolPath
