Function Remove-WDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = 'Signed Base',
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    Param(
        [Alias('S')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Signed Base')][System.Management.Automation.SwitchParameter]$SignedBase,
        [Alias('U')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Unsigned Or Supplemental')][System.Management.Automation.SwitchParameter]$UnsignedOrSupplemental,

        [ValidatePattern('\.xml$')]
        [ValidateScript({
                # Validate each Policy file in PolicyPaths parameter to make sure the user isn't accidentally trying to remove an Unsigned policy
                $_ | ForEach-Object -Process {
                    $xmlTest = [System.Xml.XmlDocument](Get-Content -Path $_)
                    $RedFlag1 = $xmlTest.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
                    $RedFlag2 = $xmlTest.SiPolicy.UpdatePolicySigners.UpdatePolicySigner.SignerId
                    if ($RedFlag1 -or $RedFlag2) { return $True }
                }
            }, ErrorMessage = 'The policy XML file(s) you chose are Unsigned policies. Please use Remove-WDACConfig cmdlet with -UnsignedOrSupplemental parameter instead.')]
        [parameter(Mandatory = $true, ParameterSetName = 'Signed Base', ValueFromPipelineByPropertyName = $true)]
        [System.String[]]$PolicyPaths,

        [ValidateScript({
                [System.String[]]$Certificates = foreach ($Cert in (Get-ChildItem -Path 'Cert:\CurrentUser\my')) {
                (($Cert.Subject -split ',' | Select-Object -First 1) -replace 'CN=', '').Trim()
                }
                $Certificates -contains $_
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
                $policies = (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsOnDisk -eq 'True' } | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' } | Where-Object -FilterScript { $_.FriendlyName }

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
                $policies = (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsOnDisk -eq 'True' } | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' }
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

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )

    begin {
        # Importing the required sub-modules
        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Update-self.psm1" -Force -Verbose:$false
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-SignTool.psm1" -Force -Verbose:$false
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Confirm-CertCN.psm1" -Force -Verbose:$false
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Write-ColorfulText.psm1" -Force -Verbose:$false

        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null

        # if -SkipVersionCheck wasn't passed, run the updater
        # Redirecting the Update-Self function's information Stream to $null because Write-Host
        # Used by Write-ColorfulText outputs to both information stream and host console
        if (-NOT $SkipVersionCheck) { Update-self -Verbose:$Verbose 6> $null }

        #region User-Configurations-Processing-Validation

        Write-Verbose -Message 'Validating and processing user configurations'

        if ($PSCmdlet.ParameterSetName -eq 'Signed Base') {
            # If any of these parameters, that are mandatory for all of the position 0 parameters, isn't supplied by user
            if (!$SignToolPath -or !$CertCN) {
                # Read User configuration file if it exists
                $UserConfig = Get-Content -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json" -ErrorAction SilentlyContinue
                if ($UserConfig) {
                    # Validate the Json file and read its content to make sure it's not corrupted
                    try { $UserConfig = $UserConfig | ConvertFrom-Json }
                    catch {
                        Write-Error -Message 'User Configuration Json file is corrupted, deleting it...' -ErrorAction Continue
                        # Calling this function with this parameter automatically does its job and breaks/stops the operation
                        Set-CommonWDACConfig -DeleteUserConfig
                    }
                }
            }

            # Get SignToolPath from user parameter or user config file or auto-detect it
            if ($SignToolPath) {
                $SignToolPathFinal = Get-SignTool -SignToolExePath $SignToolPath -Verbose:$Verbose
            } # If it is null, then Get-SignTool will behave the same as if it was called without any arguments.
            else {
                $SignToolPathFinal = Get-SignTool -SignToolExePath ($UserConfig.SignToolCustomPath ?? $null) -Verbose:$Verbose
            }

            # If CertCN was not provided by user
            if (!$CertCN) {
                if ($UserConfig.CertificateCommonName) {
                    # Check if the value in the User configuration file exists and is valid
                    if (Confirm-CertCN -CN $($UserConfig.CertificateCommonName) -Verbose:$Verbose) {
                        # if it's valid then use it
                        $CertCN = $UserConfig.CertificateCommonName
                    }
                    else {
                        throw 'The currently saved value for CertCN in user configurations is invalid.'
                    }
                }
                else {
                    throw 'CertCN parameter cannot be empty and no valid configuration was found for it.'
                }
            }
        }
        #endregion User-Configurations-Processing-Validation

        # ValidateSet for Policy names
        Class PolicyNamezx : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $PolicyNamezx = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsOnDisk -eq 'True' } | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' }).Friendlyname | Select-Object -Unique
                return [System.String[]]$PolicyNamezx
            }
        }

        # ValidateSet for Policy IDs
        Class PolicyIDzx : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $PolicyIDzx = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsOnDisk -eq 'True' } | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' }).policyID

                return [System.String[]]$PolicyIDzx
            }
        }


        # argument tab auto-completion and ValidateSet for Policy names
        # Defines the PolicyNamez class that implements the IValidateSetValuesGenerator interface. This class is responsible for generating a list of valid values for the policy names.
        Class PolicyNamez : System.Management.Automation.IValidateSetValuesGenerator {
            # Creates a static hashtable to store a mapping of policy IDs to their respective friendly names.
            static [System.Collections.Hashtable] $IDNameMap = @{}

            # Defines a method to get valid policy names from the policies on disk that aren't system policies.
            [System.String[]] GetValidValues() {
                $policies = (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsOnDisk -eq 'True' } | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' }
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
            static [System.Collections.Hashtable] $NameIDMap = @{}

            # Defines a method to get valid policy IDs from the policies on disk that aren't system policies.
            [System.String[]] GetValidValues() {
                $policies = (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsOnDisk -eq 'True' } | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' }
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
        # If a signed policy is being removed
        if ($SignedBase) {

            Write-Verbose -Message 'Looping over each selected policy XML file'
            foreach ($PolicyPath in $PolicyPaths) {

                # Convert the XML file into an XML object
                Write-Verbose -Message 'Converting the XML file to an XML object'
                $xml = [System.Xml.XmlDocument](Get-Content -Path $PolicyPath)

                # Extract the Policy ID from the XML object
                Write-Verbose -Message 'Extracting the Policy ID from the XML object'
                [System.String]$PolicyID = $xml.SiPolicy.PolicyID
                Write-Verbose -Message "The policy ID of the currently processing xml file is $PolicyID"

                # Prevent users from accidentally attempting to remove policies that aren't even deployed on the system
                Write-Verbose -Message 'Making sure the selected XML policy is deployed on the system'
                $CurrentPolicyIDs = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' }).policyID | ForEach-Object -Process { "{$_}" }
                if ($CurrentPolicyIDs -notcontains $PolicyID) {
                    Throw 'The selected policy file is not deployed on the system.'
                }

                # Sanitize the policy file by removing SupplementalPolicySigners from it
                Write-Verbose -Message 'Sanitizing the XML policy file by removing SupplementalPolicySigners from it'

                # Extracting the SupplementalPolicySigner ID from the selected XML policy file, if any
                $SuppSingerIDs = $xml.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
                # Extracting the policy name from the selected XML policy file
                $PolicyName = ($xml.SiPolicy.Settings.Setting | Where-Object -FilterScript { $_.provider -eq 'PolicyInfo' -and $_.valuename -eq 'Name' -and $_.key -eq 'Information' }).value.string

                if ($SuppSingerIDs) {
                    Write-Verbose -Message "`n$($SuppSingerIDs.count) SupplementalPolicySigners have been found in $PolicyName policy, removing them now..."

                    # Looping over each SupplementalPolicySigner and removing it
                    $SuppSingerIDs | ForEach-Object -Process {
                        $PolContent = Get-Content -Path -Raw -Path $PolicyPath
                        $PolContent -match "<Signer ID=`"$_`"[\S\s]*</Signer>" | Out-Null
                        $PolContent = $PolContent -replace $Matches[0], ''
                        Set-Content -Value $PolContent -Path $PolicyPath
                    }

                    # Removing the Supplemental policy signers block from the XML file
                    $PolContent -match '<SupplementalPolicySigners>[\S\s]*</SupplementalPolicySigners>' | Out-Null
                    $PolContent = $PolContent -replace $Matches[0], ''
                    Set-Content -Value $PolContent -Path $PolicyPath

                    # Remove empty lines from the entire policy file
                    (Get-Content -Path $PolicyPath) | Where-Object -FilterScript { $_.trim() -ne '' } | Set-Content -Path $PolicyPath -Force
                    Write-Verbose -Message 'Policy successfully sanitized and all SupplementalPolicySigners have been removed.'
                }
                else {
                    Write-Verbose -Message "`nNo sanitization required because no SupplementalPolicySigners have been found in $PolicyName policy."
                }

                # Adding policy rule option "Unsigned System Integrity Policy" to the selected XML policy file
                Set-RuleOption -FilePath $PolicyPath -Option 6
                # Converting the Policy XML file to CIP binary file
                ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath "$PolicyID.cip" | Out-Null

                # Configure the parameter splat
                $ProcessParams = @{
                    'ArgumentList' = 'sign', '/v' , '/n', "`"$CertCN`"", '/p7', '.', '/p7co', '1.3.6.1.4.1.311.79.1', '/fd', 'certHash', ".\$PolicyID.cip"
                    'FilePath'     = $SignToolPathFinal
                    'NoNewWindow'  = $true
                    'Wait'         = $true
                    'ErrorAction'  = 'Stop'
                }
                if (!$Verbose) { $ProcessParams['RedirectStandardOutput'] = 'NUL' }

                # Sign the files with the specified cert
                Write-Verbose -Message 'Signing the new CIP binary'
                Start-Process @ProcessParams

                # Removing the unsigned CIP file
                Remove-Item -Path ".\$PolicyID.cip" -Force
                # Fixing the extension name of the newly signed CIP file
                Rename-Item -Path "$PolicyID.cip.p7" -NewName "$PolicyID.cip" -Force

                # Deploying the newly signed CIP file
                Write-Verbose -Message 'Deploying the newly signed CIP file'
                &'C:\Windows\System32\CiTool.exe' --update-policy ".\$PolicyID.cip" -json | Out-Null

                Write-Host -Object "`nPolicy with the following details has been Re-signed and Re-deployed in Unsigned mode.`nPlease restart your system." -ForegroundColor Green
                Write-Output -InputObject "PolicyName = $PolicyName"
                Write-Output -InputObject "PolicyGUID = $PolicyID`n"
            }
        }

        # If an unsigned policy is being removed
        if ($UnsignedOrSupplemental) {

            # If IDs were supplied by user
            foreach ($ID in $PolicyIDs ) {
                &'C:\Windows\System32\CiTool.exe' --remove-policy "{$ID}" -json | Out-Null
                Write-Host -Object "Policy with the ID $ID has been successfully removed." -ForegroundColor Green
            }

            # If names were supplied by user
            # Empty array to store Policy IDs based on the input name, this will take care of the situations where multiple policies with the same name are deployed
            [System.Object[]]$NameID = @()
            foreach ($PolicyName in $PolicyNames) {
                $NameID += ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsOnDisk -eq 'True' } | Where-Object -FilterScript { $_.FriendlyName -eq $PolicyName }).PolicyID
            }

            Write-Verbose -Message 'The Following policy IDs have been gathered from the supplied policy names and are going to be removed from the system'
            $NameID | Select-Object -Unique | ForEach-Object -Process { Write-Verbose -Message "$_" }

            $NameID | Select-Object -Unique | ForEach-Object -Process {
                &'C:\Windows\System32\CiTool.exe' --remove-policy "{$_}" -json | Out-Null
                Write-Host -Object "Policy with the ID $_ has been successfully removed." -ForegroundColor Green
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

.INPUTS
    System.String
    System.String[]

.OUTPUTS
    System.String
#>
}

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\Resources\ArgumentCompleters.ps1"
Register-ArgumentCompleter -CommandName 'Remove-WDACConfig' -ParameterName 'CertCN' -ScriptBlock $ArgumentCompleterCertificateCN
Register-ArgumentCompleter -CommandName 'Remove-WDACConfig' -ParameterName 'PolicyPaths' -ScriptBlock $ArgumentCompleterPolicyPathsBasePoliciesOnly
Register-ArgumentCompleter -CommandName 'Remove-WDACConfig' -ParameterName 'SignToolPath' -ScriptBlock $ArgumentCompleterExeFilePathsPicker
