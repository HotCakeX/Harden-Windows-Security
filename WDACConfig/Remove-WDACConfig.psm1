#Requires -RunAsAdministrator
function Remove-WDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = 'Signed Base',
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    Param(
        [Alias('S')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Signed Base')][Switch]$SignedBase,
        [Alias('U')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Unsigned Or Supplemental')][Switch]$UnsignedOrSupplemental,

        [ValidatePattern('\.xml$')]
        [ValidateScript({
                # Validate each Policy file in PolicyPaths parameter to make sure the user isn't accidentally trying to remove an Unsigned policy
                $_ | ForEach-Object -Process {
                    $xmlTest = [System.Xml.XmlDocument](Get-Content $_)
                    $RedFlag1 = $xmlTest.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
                    $RedFlag2 = $xmlTest.SiPolicy.UpdatePolicySigners.UpdatePolicySigner.SignerId
                    if ($RedFlag1 -or $RedFlag2) { return $True }
                }
            }, ErrorMessage = 'The policy XML file(s) you chose are Unsigned policies. Please use Remove-WDACConfig cmdlet with -UnsignedOrSupplemental parameter instead.')]
        [parameter(Mandatory = $true, ParameterSetName = 'Signed Base', ValueFromPipelineByPropertyName = $true)]
        [System.String[]]$PolicyPaths,

        [ValidateScript({
                $certs = foreach ($cert in (Get-ChildItem -Path 'Cert:\CurrentUser\my')) {
                (($cert.Subject -split ',' | Select-Object -First 1) -replace 'CN=', '').Trim()
                }
                $certs -contains $_
            }, ErrorMessage = "A certificate with the provided common name doesn't exist in the personal store of the user certificates." )]
        [parameter(Mandatory = $false, ParameterSetName = 'Signed Base', ValueFromPipelineByPropertyName = $true)]
        [System.String]$CertCN,

        # https://stackoverflow.com/questions/76143006/how-to-prevent-powershell-validateset-argument-completer-from-suggesting-the-sam/76143269
        # https://stackoverflow.com/questions/76267235/powershell-how-to-cross-reference-parameters-between-2-argument-completers
        [ArgumentCompleter({
                # Define the parameters that this script block will accept.
                param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

                # Get a list of policies using the CiTool, excluding system policies and policies that aren't on disk.
                # by adding "| Where-Object -FilterScript { $_.FriendlyName }" we make sure the auto completion works when at least one of the policies doesn't have a friendly name
                $policies = (CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsOnDisk -eq 'True' } | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' } | Where-Object -FilterScript { $_.FriendlyName }

                # Create a hashtable mapping policy names to policy IDs. This will be used later to check if a policy ID already exists.
                $NameIDMap = @{}
                foreach ($policy in $policies) {
                    $NameIDMap[$policy.Friendlyname] = $policy.policyID
                }

                # Get the IDs of existing policies that are already being used in the current command.
                $existingIDs = $fakeBoundParameters['PolicyIDs']

                # Get the policy names that are currently being used in the command. This is done by looking at the abstract syntax tree (AST)
                # of the command and finding all string literals, which are assumed to be policy names.
                $existing = $commandAst.FindAll({
                        $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    }, $false).Value

                # Filter out the policy names that are already being used or whose corresponding policy IDs are already being used.
                # The resulting list of policy names is what will be shown as autocomplete suggestions.
                $candidates = $policies.Friendlyname | Where-Object -FilterScript { $_ -notin $existing -and $NameIDMap[$_] -notin $existingIDs }

                # Additionally, if the policy name contains spaces, it's enclosed in single quotes to ensure it's treated as a single argument.
                # This is achieved using the Compare-Object cmdlet to compare the existing and candidate values, and outputting the resulting matches.
                # For each resulting match, it checks if the match contains a space, if so, it's enclosed in single quotes, if not, it's returned as is.
        (Compare-Object -PassThru $candidates $existing | Where-Object -FilterScript { SideIndicator -EQ '<=' }).
                ForEach({ if ($_ -match ' ') { "'{0}'" -f $_ } else { $_ } })
            })]
        [ValidateScript({
                if ($_ -notin [PolicyNamezx]::new().GetValidValues()) { throw "Invalid policy name: $_" }
                $true
            })]
        [Parameter(Mandatory = $false, ParameterSetName = 'Unsigned Or Supplemental')]
        [System.String[]]$PolicyNames,

        # https://stackoverflow.com/questions/76143006/how-to-prevent-powershell-validateset-argument-completer-from-suggesting-the-sam/76143269
        # https://stackoverflow.com/questions/76267235/powershell-how-to-cross-reference-parameters-between-2-argument-completers
        [ArgumentCompleter({
                param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

                # Get a list of policies using the CiTool, excluding system policies and policies that aren't on disk.
                $policies = (CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsOnDisk -eq 'True' } | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' }
                # Create a hashtable mapping policy IDs to policy names. This will be used later to check if a policy name already exists.
                $IDNameMap = @{}
                foreach ($policy in $policies) {
                    $IDNameMap[$policy.policyID] = $policy.Friendlyname
                }
                # Get the names of existing policies that are already being used in the current command.
                $existingNames = $fakeBoundParameters['PolicyNames']
                # Get the policy IDs that are currently being used in the command. This is done by looking at the abstract syntax tree (AST)
                # of the command and finding all string literals, which are assumed to be policy IDs.
                $existing = $commandAst.FindAll({
                        $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    }, $false).Value
                # Filter out the policy IDs that are already being used or whose corresponding policy names are already being used.
                # The resulting list of policy IDs is what will be shown as autocomplete suggestions.
                $candidates = $policies.policyID | Where-Object -FilterScript { $_ -notin $existing -and $IDNameMap[$_] -notin $existingNames }
                # Return the candidates.
                return $candidates
            })]
        [ValidateScript({
                if ($_ -notin [PolicyIDzx]::new().GetValidValues()) { throw "Invalid policy ID: $_" }
                $true
            })]
        [Parameter(Mandatory = $false, ParameterSetName = 'Unsigned Or Supplemental')]
        [System.String[]]$PolicyIDs,        

        [parameter(Mandatory = $false, ParameterSetName = 'Signed Base', ValueFromPipelineByPropertyName = $true)]
        [System.String]$SignToolPath,

        [Parameter(Mandatory = $false)][Switch]$SkipVersionCheck
    )

    begin {
        # Importing resources such as functions by dot-sourcing so that they will run in the same scope and their variables will be usable
        . "$psscriptroot\Resources.ps1"

        # Stop operation as soon as there is an error anywhere, unless explicitly specified otherwise
        $ErrorActionPreference = 'Stop'
        if (-NOT $SkipVersionCheck) { . Update-self }
        # Detecting if Debug switch is used, will do debugging actions based on that
        $Debug = $PSBoundParameters.Debug.IsPresent     
        
        # Fetch User account directory path
        [string]$global:UserAccountDirectoryPath = (Get-CimInstance Win32_UserProfile -Filter "SID = '$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)'").LocalPath

        #region User-Configurations-Processing-Validation
        if ($PSCmdlet.ParameterSetName -eq 'Signed Base') {
            # If any of these parameters, that are mandatory for all of the position 0 parameters, isn't supplied by user
            if (!$SignToolPath -or !$CertCN) {
                # Read User configuration file if it exists
                $UserConfig = Get-Content -Path "$global:UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json" -ErrorAction SilentlyContinue   
                if ($UserConfig) {
                    # Validate the Json file and read its content to make sure it's not corrupted
                    try { $UserConfig = $UserConfig | ConvertFrom-Json }
                    catch {            
                        Write-Error 'User Configuration Json file is corrupted, deleting it...' -ErrorAction Continue
                        # Calling this function with this parameter automatically does its job and breaks/stops the operation
                        Set-CommonWDACConfig -DeleteUserConfig         
                    }                
                }
            }
        
            # Get SignToolPath from user parameter or user config file or auto-detect it
            if ($SignToolPath) {
                $SignToolPathFinal = Get-SignTool -SignToolExePath $SignToolPath
            } # If it is null, then Get-SignTool will behave the same as if it was called without any arguments.
            else {
                $SignToolPathFinal = Get-SignTool -SignToolExePath ($UserConfig.SignToolCustomPath ?? $null)
            }            
                     
            # If CertCN was not provided by user
            if (!$CertCN) {
                if ($UserConfig.CertificateCommonName) {
                    # Check if the value in the User configuration file exists and is valid
                    if (Confirm-CertCN $($UserConfig.CertificateCommonName)) {
                        # if it's valid then use it
                        $CertCN = $UserConfig.CertificateCommonName
                    }
                    else {
                        throw 'The currently saved value for CertCN in user configurations is invalid.'
                    }
                }
                else {
                    throw "CertCN parameter can't be empty and no valid configuration was found for it."
                }
            }        
        }
        #endregion User-Configurations-Processing-Validation

        # ValidateSet for Policy names 
        Class PolicyNamezx : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $PolicyNamezx = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsOnDisk -eq 'True' } | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' }).Friendlyname | Select-Object -Unique
                return [System.String[]]$PolicyNamezx
            }
        }

        # ValidateSet for Policy IDs     
        Class PolicyIDzx : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $PolicyIDzx = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsOnDisk -eq 'True' } | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' }).policyID
   
                return [System.String[]]$PolicyIDzx
            }
        }    


        # argument tab auto-completion and ValidateSet for Policy names
        # Defines the PolicyNamez class that implements the IValidateSetValuesGenerator interface. This class is responsible for generating a list of valid values for the policy names.
        Class PolicyNamez : System.Management.Automation.IValidateSetValuesGenerator {
            # Creates a static hashtable to store a mapping of policy IDs to their respective friendly names.
            static [Hashtable] $IDNameMap = @{}

            # Defines a method to get valid policy names from the policies on disk that aren't system policies.
            [System.String[]] GetValidValues() {
                $policies = (CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsOnDisk -eq 'True' } | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' }
                self::$IDNameMap = @{}
                foreach ($policy in $policies) {
                    self::$IDNameMap[$policy.policyID] = $policy.Friendlyname
                }
                # Returns an array of unique policy names.
                return [System.String[]]($policies.Friendlyname | Select-Object -Unique)
            }

            # Defines a static method to get a policy name by its ID. This method will be used to check if a policy ID is already in use.
            static [System.String] GetPolicyNameByID($ID) {
                return self::$IDNameMap[$ID]
            }
        }

        # Defines the PolicyIDz class that also implements the IValidateSetValuesGenerator interface. This class is responsible for generating a list of valid values for the policy IDs.
        Class PolicyIDz : System.Management.Automation.IValidateSetValuesGenerator {
            # Creates a static hashtable to store a mapping of policy friendly names to their respective IDs.
            static [Hashtable] $NameIDMap = @{}

            # Defines a method to get valid policy IDs from the policies on disk that aren't system policies.
            [System.String[]] GetValidValues() {
                $policies = (CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsOnDisk -eq 'True' } | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' }
                self::$NameIDMap = @{}
                foreach ($policy in $policies) {
                    self::$NameIDMap[$policy.Friendlyname] = $policy.policyID
                }
                # Returns an array of unique policy IDs.
                return [System.String[]]($policies.policyID | Select-Object -Unique)
            }

            # Defines a static method to get a policy ID by its name. This method will be used to check if a policy name is already in use.
            static [System.String] GetPolicyIDByName($Name) {
                return self::$NameIDMap[$Name]
            }
        }
    }

    process {

        if ($SignedBase) {
            foreach ($PolicyPath in $PolicyPaths) {
                $xml = [System.Xml.XmlDocument](Get-Content $PolicyPath)
                [System.String]$PolicyID = $xml.SiPolicy.PolicyID
                # Prevent users from accidentally attempting to remove policies that aren't even deployed on the system
                $CurrentPolicyIDs = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' }).policyID | ForEach-Object -Process { "{$_}" }
                Write-Debug -Message "The policy ID of the currently processing xml file is $PolicyID"
                if ($CurrentPolicyIDs -notcontains $PolicyID) {
                    Write-Error -Message "The selected policy file isn't deployed on the system." -ErrorAction Stop
                }

                ######################## Sanitize the policy file by removing SupplementalPolicySigners ########################
                $SuppSingerIDs = $xml.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
                $PolicyName = ($xml.SiPolicy.Settings.Setting | Where-Object -FilterScript { $_.provider -eq 'PolicyInfo' -and $_.valuename -eq 'Name' -and $_.key -eq 'Information' }).value.string
                if ($SuppSingerIDs) {
                    Write-Debug -Message "`n$($SuppSingerIDs.count) SupplementalPolicySigners have been found in $PolicyName policy, removing them now..."
                    $SuppSingerIDs | ForEach-Object -Process {
                        $PolContent = Get-Content -Raw -Path $PolicyPath
                        $PolContent -match "<Signer ID=`"$_`"[\S\s]*</Signer>" | Out-Null
                        $PolContent = $PolContent -replace $Matches[0], ''
                        Set-Content -Value $PolContent -Path $PolicyPath
                    }
                    $PolContent -match '<SupplementalPolicySigners>[\S\s]*</SupplementalPolicySigners>' | Out-Null
                    $PolContent = $PolContent -replace $Matches[0], ''
                    Set-Content -Value $PolContent -Path $PolicyPath

                    # remove empty lines from the entire policy file
                    (Get-Content -Path $PolicyPath) | Where-Object -FilterScript { $_.trim() -ne '' } | Set-Content -Path $PolicyPath -Force
                    Write-Debug -Message 'Policy successfully sanitized and all SupplementalPolicySigners have been removed.'
                }
                else {
                    Write-Debug -Message "`nNo sanitization required because no SupplementalPolicySigners have been found in $PolicyName policy."
                }

                Set-RuleOption -FilePath $PolicyPath -Option 6
                ConvertFrom-CIPolicy $PolicyPath "$PolicyID.cip" | Out-Null

                # Configure the parameter splat
                $ProcessParams = @{
                    'ArgumentList' = 'sign', '/v' , '/n', "`"$CertCN`"", '/p7', '.', '/p7co', '1.3.6.1.4.1.311.79.1', '/fd', 'certHash', ".\$PolicyID.cip"
                    'FilePath'     = $SignToolPathFinal
                    'NoNewWindow'  = $true
                    'Wait'         = $true
                    'ErrorAction'  = 'Stop'
                }
                if (!$Debug) { $ProcessParams['RedirectStandardOutput'] = 'NUL' } 
                # Sign the files with the specified cert
                Start-Process @ProcessParams

                Remove-Item ".\$PolicyID.cip" -Force
                Rename-Item "$PolicyID.cip.p7" -NewName "$PolicyID.cip" -Force
                CiTool --update-policy ".\$PolicyID.cip" -json | Out-Null 
                Write-Host "`nPolicy with the following details has been Re-signed and Re-deployed in Unsigned mode.`nPlease restart your system." -ForegroundColor Green
                Write-Output "PolicyName = $PolicyName"
                Write-Output "PolicyGUID = $PolicyID`n"
            }
        }

        if ($UnsignedOrSupplemental) {

            # If IDs were supplied by user
            foreach ($ID in $PolicyIDs ) {
                citool --remove-policy "{$ID}" -json | Out-Null                
                Write-Host "Policy with the ID $ID has been successfully removed." -ForegroundColor Green                
            }

            # If names were supplied by user
            # Empty array to store Policy IDs based on the input name, this will take care of the situations where multiple policies with the same name are deployed
            [System.Object[]]$NameID = @()
            foreach ($PolicyName in $PolicyNames) {
                $NameID += ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsOnDisk -eq 'True' } | Where-Object -FilterScript { $_.FriendlyName -eq $PolicyName }).PolicyID
            }

            Write-Debug -Message 'The Following policy IDs have been gathered from the supplied policy names and are going to be removed from the system'
            if ($Debug) { $NameID | Select-Object -Unique | ForEach-Object -Process { Write-Debug -Message "$_" } }

            $NameID | Select-Object -Unique | ForEach-Object -Process {
                citool --remove-policy "{$_}" -json | Out-Null               
                Write-Host "Policy with the ID $_ has been successfully removed." -ForegroundColor Green                
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

# Importing argument completer ScriptBlocks
. "$psscriptroot\ArgumentCompleters.ps1"
# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
Register-ArgumentCompleter -CommandName 'Remove-WDACConfig' -ParameterName 'CertCN' -ScriptBlock $ArgumentCompleterCertificateCN
Register-ArgumentCompleter -CommandName 'Remove-WDACConfig' -ParameterName 'PolicyPaths' -ScriptBlock $ArgumentCompleterPolicyPathsBasePoliciesOnly
Register-ArgumentCompleter -CommandName 'Remove-WDACConfig' -ParameterName 'SignToolPath' -ScriptBlock $ArgumentCompleterExeFilePathsPicker
