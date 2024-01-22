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
                    $XmlTest = [System.Xml.XmlDocument](Get-Content -Path $_)
                    $RedFlag1 = $XmlTest.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
                    $RedFlag2 = $XmlTest.SiPolicy.UpdatePolicySigners.UpdatePolicySigner.SignerId
                    if ($RedFlag1 -or $RedFlag2) { return $True }
                }
            }, ErrorMessage = 'The policy XML file(s) you chose are Unsigned policies. Please use Remove-WDACConfig cmdlet with -UnsignedOrSupplemental parameter instead.')]
        [parameter(Mandatory = $true, ParameterSetName = 'Signed Base', ValueFromPipelineByPropertyName = $true)]
        [System.String[]]$PolicyPaths,

        [ValidateScript({
                # Assign the input value to a variable because $_ is going to be used to access another pipeline object
                [System.String]$InputCN = $_

                # Create an empty array to store the output objects
                [System.String[]]$Output = @()

                # Loop through each certificate that uses RSA algorithm (Because ECDSA is not supported for signing WDAC policies) in the current user's personal store and extract the relevant properties
                foreach ($Cert in (Get-ChildItem -Path 'Cert:\CurrentUser\My' | Where-Object -FilterScript { $_.PublicKey.Oid.FriendlyName -eq 'RSA' })) {

                    # Takes care of certificate subjects that include comma in their CN
                    # Determine if the subject contains a comma
                    if ($Cert.Subject -match 'CN=(?<RegexTest>.*?),.*') {
                        # If the CN value contains double quotes, use split to get the value between the quotes
                        if ($matches['RegexTest'] -like '*"*') {
                            $SubjectCN = ($Element.Certificate.Subject -split 'CN="(.+?)"')[1]
                        }
                        # Otherwise, use the named group RegexTest to get the CN value
                        else {
                            $SubjectCN = $matches['RegexTest']
                        }
                    }
                    # If the subject does not contain a comma, use a lookbehind to get the CN value
                    elseif ($Cert.Subject -match '(?<=CN=).*') {
                        $SubjectCN = $matches[0]
                    }
                    $Output += $SubjectCN
                }

                # Count the number of duplicate CNs in the output array
                [System.Int64]$NumberOfDuplicateCNs = @($Output | Where-Object -FilterScript { $_ -eq $InputCN }).Count

                # If the certificate with the provided common name exists in the personal store of the user certificates
                if ($Output -contains $_) {
                    # if there are more than 1 certificate with the same common name on the system
                    if ($NumberOfDuplicateCNs -eq 1) {
                        # Return true if the certificate exists and there are no duplicates
                        return $true
                    }
                    else {
                        Throw "There are $NumberOfDuplicateCNs certificates with the same common name ($_) on the system, please remove the duplicate certificates and try again."
                    }
                }
                else {
                    Throw 'A certificate with the provided common name does not exist in the personal store of the user certificates.'
                }

            })]
        [parameter(Mandatory = $false, ParameterSetName = 'Signed Base', ValueFromPipelineByPropertyName = $true)]
        [System.String]$CertCN,

        [ArgumentCompleter({
                # Define the parameters that this script block will accept.
                param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

                # Get a list of policies using the CiTool, excluding system policies and policies that aren't on disk.
                # by adding "| Where-Object -FilterScript { $_.FriendlyName }" we make sure the auto completion works when at least one of the policies doesn't have a friendly name
                $Policies = (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { ($_.IsOnDisk -eq 'True') -and ($_.IsSystemPolicy -ne 'True') -and $_.FriendlyName }

                # Create a hashtable mapping policy names to policy IDs. This will be used later to check if a policy ID already exists.
                $NameIDMap = @{}
                foreach ($Policy in $Policies) {
                    $NameIDMap[$Policy.Friendlyname] = $Policy.policyID
                }

                # Get the IDs of existing policies that are already being used in the current command.
                $ExistingIDs = $fakeBoundParameters['PolicyIDs']

                # Get the policy names that are currently being used in the command. This is done by looking at the abstract syntax tree (AST)
                # of the command and finding all string literals, which are assumed to be policy names.
                $Existing = $commandAst.FindAll({
                        $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    }, $false).Value

                # Filter out the policy names that are already being used or whose corresponding policy IDs are already being used.
                # The resulting list of policy names is what will be shown as autocomplete suggestions.
                $Candidates = $Policies.Friendlyname | Where-Object -FilterScript { $_ -notin $Existing -and $NameIDMap[$_] -notin $ExistingIDs }

                # Additionally, if the policy name contains spaces, it's enclosed in single quotes to ensure it's treated as a single argument.
                # This is achieved using the Compare-Object cmdlet to compare the existing and candidate values, and outputting the resulting matches.
                # For each resulting match, it checks if the match contains a space, if so, it's enclosed in single quotes, if not, it's returned as is.
        (Compare-Object -ReferenceObject $Candidates -DifferenceObject $Existing -PassThru | Where-Object -Property SideIndicator -EQ '<=' ).
                ForEach({ if ($_ -match ' ') { "'{0}'" -f $_ } else { $_ } })
            })]
        [ValidateScript({
                if ($_ -notin [PolicyNamezx]::new().GetValidValues()) { throw "Invalid policy name: $_" }
                $true
            })]
        [Parameter(Mandatory = $false, ParameterSetName = 'Unsigned Or Supplemental')]
        [System.String[]]$PolicyNames,

        [ArgumentCompleter({
                param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

                # Get a list of policies using the CiTool, excluding system policies and policies that aren't on disk.
                $Policies = (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { ($_.IsOnDisk -eq 'True') -and ($_.IsSystemPolicy -ne 'True') }
                # Create a hashtable mapping policy IDs to policy names. This will be used later to check if a policy name already exists.
                $IDNameMap = @{}
                foreach ($Policy in $Policies) {
                    $IDNameMap[$Policy.policyID] = $Policy.Friendlyname
                }
                # Get the names of existing policies that are already being used in the current command.
                $ExistingNames = $fakeBoundParameters['PolicyNames']
                # Get the policy IDs that are currently being used in the command. This is done by looking at the abstract syntax tree (AST)
                # of the command and finding all string literals, which are assumed to be policy IDs.
                $Existing = $commandAst.FindAll({
                        $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    }, $false).Value
                # Filter out the policy IDs that are already being used or whose corresponding policy names are already being used.
                # The resulting list of policy IDs is what will be shown as autocomplete suggestions.
                $Candidates = $Policies.policyID | Where-Object -FilterScript { $_ -notin $Existing -and $IDNameMap[$_] -notin $ExistingNames }
                # Return the candidates.
                return $Candidates
            })]
        [ValidateScript({
                if ($_ -notin [PolicyIDzx]::new().GetValidValues()) { throw "Invalid policy ID: $_" }
                $true
            })]
        [Parameter(Mandatory = $false, ParameterSetName = 'Unsigned Or Supplemental')]
        [System.String[]]$PolicyIDs,

        [parameter(Mandatory = $false, ParameterSetName = 'Signed Base', ValueFromPipelineByPropertyName = $true)]
        [System.String]$SignToolPath,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$Force,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )

    begin {
        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null

        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Importing the required sub-modules
        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Update-self.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-SignTool.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Confirm-CertCN.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Write-ColorfulText.psm1" -Force

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-self -InvocationStatement $MyInvocation.Statement }

        #Region User-Configurations-Processing-Validation
        Write-Verbose -Message 'Validating and processing user configurations'

        if ($PSCmdlet.ParameterSetName -eq 'Signed Base') {

            # Get SignToolPath from user parameter or user config file or auto-detect it
            if ($SignToolPath) {
                $SignToolPathFinal = Get-SignTool -SignToolExePathInput $SignToolPath
            } # If it is null, then Get-SignTool will behave the same as if it was called without any arguments.
            else {
                $SignToolPathFinal = Get-SignTool -SignToolExePathInput (Get-CommonWDACConfig -SignToolPath)

            }

            # If CertCN was not provided by user, check if a valid value exists in user configs, if so, use it, otherwise throw an error
            if (!$CertCN) {
                if (Confirm-CertCN -CN (Get-CommonWDACConfig -CertCN)) {
                    $CertCN = Get-CommonWDACConfig -CertCN
                }
                else {
                    throw 'CertCN parameter cannot be empty and no valid user configuration was found for it.'
                }
            }
        }
        #Endregion User-Configurations-Processing-Validation

        # ValidateSet for Policy names
        Class PolicyNamezx : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $PolicyNamezx = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { ($_.IsOnDisk -eq 'True') -and ($_.IsSystemPolicy -ne 'True') }).Friendlyname | Select-Object -Unique
                return [System.String[]]$PolicyNamezx
            }
        }

        # ValidateSet for Policy IDs
        Class PolicyIDzx : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $PolicyIDzx = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { ($_.IsOnDisk -eq 'True') -and ($_.IsSystemPolicy -ne 'True') }).policyID

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
                $Policies = (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { ($_.IsOnDisk -eq 'True') -and ($_.IsSystemPolicy -ne 'True') }
                self::$IDNameMap = @{}
                foreach ($Policy in $Policies) {
                    self::$IDNameMap[$Policy.policyID] = $Policy.Friendlyname
                }
                # Returns an array of unique policy names.
                return [System.String[]]($Policies.Friendlyname | Select-Object -Unique)
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
                $Policies = (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { ($_.IsOnDisk -eq 'True') -and ($_.IsSystemPolicy -ne 'True') }
                self::$NameIDMap = @{}
                foreach ($Policy in $Policies) {
                    self::$NameIDMap[$Policy.Friendlyname] = $Policy.policyID
                }
                # Returns an array of unique policy IDs.
                return [System.String[]]($Policies.policyID | Select-Object -Unique)
            }

            # Defines a static method to get a policy ID by its name. This method will be used to check if a policy name is already in use.
            static [System.String] GetPolicyIDByName($Name) {
                return self::$NameIDMap[$Name]
            }
        }

        # Detecting if Confirm switch is used to bypass the confirmation prompts
        if ($Force -and -Not $Confirm) {
            $ConfirmPreference = 'None'
        }
    }

    process {
        # If a signed policy is being removed
        if ($SignedBase) {

            Write-Verbose -Message 'Looping over each selected policy XML file'
            foreach ($PolicyPath in $PolicyPaths) {

                # The total number of the main steps for the progress bar to render
                [System.Int16]$TotalSteps = 3
                [System.Int16]$CurrentStep = 0

                $CurrentStep++
                Write-Progress -Id 18 -Activity 'Parsing the XML Policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Convert the XML file into an XML object
                Write-Verbose -Message 'Converting the XML file to an XML object'
                $Xml = [System.Xml.XmlDocument](Get-Content -Path $PolicyPath)

                # Extract the Policy ID from the XML object
                Write-Verbose -Message 'Extracting the Policy ID from the XML object'
                [System.String]$PolicyID = $Xml.SiPolicy.PolicyID
                Write-Verbose -Message "The policy ID of the currently processing xml file is $PolicyID"

                # Prevent users from accidentally attempting to remove policies that aren't even deployed on the system
                Write-Verbose -Message 'Making sure the selected XML policy is deployed on the system'
                $CurrentPolicyIDs = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' }).policyID | ForEach-Object -Process { "{$_}" }
                if ($CurrentPolicyIDs -notcontains $PolicyID) {
                    Throw 'The selected policy file is not deployed on the system.'
                }

                $CurrentStep++
                Write-Progress -Id 18 -Activity 'Processing the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Sanitize the policy file by removing SupplementalPolicySigners from it
                Write-Verbose -Message 'Sanitizing the XML policy file by removing SupplementalPolicySigners from it'

                # Extracting the SupplementalPolicySigner ID from the selected XML policy file, if any
                $SuppSingerIDs = $Xml.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
                # Extracting the policy name from the selected XML policy file
                [System.String]$PolicyName = ($Xml.SiPolicy.Settings.Setting | Where-Object -FilterScript { $_.provider -eq 'PolicyInfo' -and $_.valuename -eq 'Name' -and $_.key -eq 'Information' }).value.string

                if ($SuppSingerIDs) {
                    Write-Verbose -Message "`n$($SuppSingerIDs.count) SupplementalPolicySigners have been found in $PolicyName policy, removing them now..."

                    # Looping over each SupplementalPolicySigner and removing it
                    $SuppSingerIDs | ForEach-Object -Process {
                        $PolContent = Get-Content -Raw -Path $PolicyPath
                        $PolContent -match "<Signer ID=`"$_`"[\S\s]*</Signer>" | Out-Null
                        $PolContent = $PolContent -replace $Matches[0], ''
                        Set-Content -Value $PolContent -Path $PolicyPath
                    }

                    # Removing the Supplemental policy signers block from the XML file
                    $PolContent -match '<SupplementalPolicySigners>[\S\s]*</SupplementalPolicySigners>' | Out-Null
                    $PolContent = $PolContent -replace $Matches[0], ''
                    Set-Content -Value $PolContent -Path $PolicyPath -Force

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

                $CurrentStep++
                Write-Progress -Id 18 -Activity 'Signing the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

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

                # Prompt for confirmation before proceeding
                if ($PSCmdlet.ShouldProcess('This PC', 'Deploying the signed policy')) {

                    Write-Verbose -Message 'Deploying the newly signed CIP file'
                    &'C:\Windows\System32\CiTool.exe' --update-policy ".\$PolicyID.cip" -json | Out-Null

                    Write-ColorfulText -Color Lavender -InputText "Policy with the following details has been Re-signed and Re-deployed in Unsigned mode.`nPlease restart your system."
                    Write-ColorfulText -Color MintGreen -InputText "PolicyName = $PolicyName"
                    Write-ColorfulText -Color MintGreen -InputText "PolicyGUID = $PolicyID"

                    Write-Verbose -Message 'Removing the newly signed CIP file from the current directory after deployment'
                    Remove-Item -Path ".\$PolicyID.cip" -Force
                }
                Write-Progress -Id 18 -Activity 'Complete.' -Completed
            }
        }

        # If an unsigned policy is being removed
        if ($UnsignedOrSupplemental) {

            # If IDs were supplied by user
            foreach ($ID in $PolicyIDs ) {
                &'C:\Windows\System32\CiTool.exe' --remove-policy "{$ID}" -json | Out-Null
                Write-ColorfulText -Color Lavender -InputText "Policy with the ID $ID has been successfully removed."
            }

            # If names were supplied by user
            # Empty array to store Policy IDs based on the input name, this will take care of the situations where multiple policies with the same name are deployed
            [System.Object[]]$NameID = @()
            foreach ($PolicyName in $PolicyNames) {
                $NameID += ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { ($_.IsOnDisk -eq 'True') -and ($_.FriendlyName -eq $PolicyName) }).PolicyID
            }

            Write-Verbose -Message 'The Following policy IDs have been gathered from the supplied policy names and are going to be removed from the system'
            $NameID | Select-Object -Unique | ForEach-Object -Process { Write-Verbose -Message "$_" }

            $NameID | Select-Object -Unique | ForEach-Object -Process {
                &'C:\Windows\System32\CiTool.exe' --remove-policy "{$_}" -json | Out-Null
                Write-ColorfulText -Color Lavender -InputText "Policy with the ID $_ has been successfully removed."
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
.PARAMETER PolicyNames
    Names of the deployed policies to be removed
    https://stackoverflow.com/questions/76143006/how-to-prevent-powershell-validateset-argument-completer-from-suggesting-the-sam/76143269
    https://stackoverflow.com/questions/76267235/powershell-how-to-cross-reference-parameters-between-2-argument-completers
.PARAMETER PolicyIDs
    IDs of the deployed policies to be removed
    https://stackoverflow.com/questions/76143006/how-to-prevent-powershell-validateset-argument-completer-from-suggesting-the-sam/76143269
    https://stackoverflow.com/questions/76267235/powershell-how-to-cross-reference-parameters-between-2-argument-completers
.PARAMETER SignedBase
    Remove Signed Base WDAC Policies
.PARAMETER PolicyPaths
    Path to the XML policy file(s) of the deployed policies to be removed
.PARAMETER CertCN
    Certificate common name to be used to sign the policy file(s) that are going to be removed in unsigned mode
.PARAMETER SignToolPath
    Path to the SignTool.exe
.PARAMETER UnsignedOrSupplemental
    Remove Unsigned deployed WDAC policies as well as Signed deployed Supplemental WDAC policies
.PARAMETER Force
    Bypasses the confirmation prompt
.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases
.PARAMETER Verbose
    Shows verbose output
.INPUTS
    System.String
    System.String[]
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
#>
}

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\Resources\ArgumentCompleters.ps1"
Register-ArgumentCompleter -CommandName 'Remove-WDACConfig' -ParameterName 'CertCN' -ScriptBlock $ArgumentCompleterCertificateCN
Register-ArgumentCompleter -CommandName 'Remove-WDACConfig' -ParameterName 'PolicyPaths' -ScriptBlock $ArgumentCompleterPolicyPathsBasePoliciesOnly
Register-ArgumentCompleter -CommandName 'Remove-WDACConfig' -ParameterName 'SignToolPath' -ScriptBlock $ArgumentCompleterExeFilePathsPicker

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB3e2uK/BNmaZad
# Y6oeXDFVS92d47ftgq6yPcn0joNAzqCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
# LDQz/68TAAAAAAAEMA0GCSqGSIb3DQEBDQUAME8xEzARBgoJkiaJk/IsZAEZFgNj
# b20xIjAgBgoJkiaJk/IsZAEZFhJIT1RDQUtFWC1DQS1Eb21haW4xFDASBgNVBAMT
# C0hPVENBS0VYLUNBMCAXDTIzMTIyNzExMjkyOVoYDzIyMDgxMTEyMTEyOTI5WjB5
# MQswCQYDVQQGEwJVSzEeMBwGA1UEAxMVSG90Q2FrZVggQ29kZSBTaWduaW5nMSMw
# IQYJKoZIhvcNAQkBFhRob3RjYWtleEBvdXRsb29rLmNvbTElMCMGCSqGSIb3DQEJ
# ARYWU3B5bmV0Z2lybEBvdXRsb29rLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAKb1BJzTrpu1ERiwr7ivp0UuJ1GmNmmZ65eckLpGSF+2r22+7Tgm
# pEifj9NhPw0X60F9HhdSM+2XeuikmaNMvq8XRDUFoenv9P1ZU1wli5WTKHJ5ayDW
# k2NP22G9IPRnIpizkHkQnCwctx0AFJx1qvvd+EFlG6ihM0fKGG+DwMaFqsKCGh+M
# rb1bKKtY7UEnEVAsVi7KYGkkH+ukhyFUAdUbh/3ZjO0xWPYpkf/1ldvGes6pjK6P
# US2PHbe6ukiupqYYG3I5Ad0e20uQfZbz9vMSTiwslLhmsST0XAesEvi+SJYz2xAQ
# x2O4n/PxMRxZ3m5Q0WQxLTGFGjB2Bl+B+QPBzbpwb9JC77zgA8J2ncP2biEguSRJ
# e56Ezx6YpSoRv4d1jS3tpRL+ZFm8yv6We+hodE++0tLsfpUq42Guy3MrGQ2kTIRo
# 7TGLOLpayR8tYmnF0XEHaBiVl7u/Szr7kmOe/CfRG8IZl6UX+/66OqZeyJ12Q3m2
# fe7ZWnpWT5sVp2sJmiuGb3atFXBWKcwNumNuy4JecjQE+7NF8rfIv94NxbBV/WSM
# pKf6Yv9OgzkjY1nRdIS1FBHa88RR55+7Ikh4FIGPBTAibiCEJMc79+b8cdsQGOo4
# ymgbKjGeoRNjtegZ7XE/3TUywBBFMf8NfcjF8REs/HIl7u2RHwRaUTJdAgMBAAGj
# ggJzMIICbzA8BgkrBgEEAYI3FQcELzAtBiUrBgEEAYI3FQiG7sUghM++I4HxhQSF
# hqV1htyhDXuG5sF2wOlDAgFkAgEIMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1Ud
# DwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYB
# BQUHAwMwHQYDVR0OBBYEFOlnnQDHNUpYoPqECFP6JAqGDFM6MB8GA1UdIwQYMBaA
# FICT0Mhz5MfqMIi7Xax90DRKYJLSMIHUBgNVHR8EgcwwgckwgcaggcOggcCGgb1s
# ZGFwOi8vL0NOPUhPVENBS0VYLUNBLENOPUhvdENha2VYLENOPUNEUCxDTj1QdWJs
# aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
# LERDPU5vbkV4aXN0ZW50RG9tYWluLERDPWNvbT9jZXJ0aWZpY2F0ZVJldm9jYXRp
# b25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwgccG
# CCsGAQUFBwEBBIG6MIG3MIG0BggrBgEFBQcwAoaBp2xkYXA6Ly8vQ049SE9UQ0FL
# RVgtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZp
# Y2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Tm9uRXhpc3RlbnREb21haW4sREM9Y29t
# P2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0
# aG9yaXR5MA0GCSqGSIb3DQEBDQUAA4ICAQA7JI76Ixy113wNjiJmJmPKfnn7brVI
# IyA3ZudXCheqWTYPyYnwzhCSzKJLejGNAsMlXwoYgXQBBmMiSI4Zv4UhTNc4Umqx
# pZSpqV+3FRFQHOG/X6NMHuFa2z7T2pdj+QJuH5TgPayKAJc+Kbg4C7edL6YoePRu
# HoEhoRffiabEP/yDtZWMa6WFqBsfgiLMlo7DfuhRJ0eRqvJ6+czOVU2bxvESMQVo
# bvFTNDlEcUzBM7QxbnsDyGpoJZTx6M3cUkEazuliPAw3IW1vJn8SR1jFBukKcjWn
# aau+/BE9w77GFz1RbIfH3hJ/CUA0wCavxWcbAHz1YoPTAz6EKjIc5PcHpDO+n8Fh
# t3ULwVjWPMoZzU589IXi+2Ol0IUWAdoQJr/Llhub3SNKZ3LlMUPNt+tXAs/vcUl0
# 7+Dp5FpUARE2gMYA/XxfU9T6Q3pX3/NRP/ojO9m0JrKv/KMc9sCGmV9sDygCOosU
# 5yGS4Ze/DJw6QR7xT9lMiWsfgL96Qcw4lfu1+5iLr0dnDFsGowGTKPGI0EvzK7H+
# DuFRg+Fyhn40dOUl8fVDqYHuZJRoWJxCsyobVkrX4rA6xUTswl7xYPYWz88WZDoY
# gI8AwuRkzJyUEA07IYtsbFCYrcUzIHME4uf8jsJhCmb0va1G2WrWuyasv3K/G8Nn
# f60MsDbDH1mLtzGCAxgwggMUAgEBMGYwTzETMBEGCgmSJomT8ixkARkWA2NvbTEi
# MCAGCgmSJomT8ixkARkWEkhPVENBS0VYLUNBLURvbWFpbjEUMBIGA1UEAxMLSE9U
# Q0FLRVgtQ0ECEx4AAAAEjzQsNDP/rxMAAAAAAAQwDQYJYIZIAWUDBAIBBQCggYQw
# GAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
# NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQx
# IgQgmki1IWersNkR3U2DtZZCYJ6fq/wuXsk8CYtkA6K6SXMwDQYJKoZIhvcNAQEB
# BQAEggIATFUO6nWaM2gOef7zRdcreBoN7XDckaAtsYQp5OadUh4ltyegqPfp+YsZ
# BcRqoq9bLvgJu/pChRnjV3ci61e2us2oNKTbhs6+LrL0afaTGBDvooWuyywsgAh5
# 0raNhMFDU5GjvEjp8CwZlbiE4eZoUwrLHgf3DGg9kUJEQqhL4Qcn1THcHxzi3tnA
# Pe+AYGPztjl7YyJOhAe7XMOGxbLT6C179aHQ/HKCvKu2318HeEAKveIADuMXOG4z
# CP3fWTHo8O+t6geVOXu9Lq1IYW1aydgQl+qrCSaLlWqvkcgLhjc+Rz/ZivFAi8sT
# md2RKv49zcr3wuEFI/54udFJTTk6K+UimKg47kbxSD5nwkwAzR790cMICWVunwRJ
# wNqwbUbVk6mF5eTV2R5oI5VBjektiEQrGPqAo/tD2G7gV5M/1Ugb2pXkhhxdCpIk
# u72+KkTTMCsWS3vCY4avWx09UvWP5+JNUVDIo3yfhsRojUa+mnqi2AyvXo1p6rUF
# aTZ1g41l4BKQc5rxsetAS5LFDq0UpUms6g1R7NkiH82kvHPCQ1LQO+ltv/vhFVrV
# UAQy97DSEpo+wpm13ym79Fmta6gtkgkPKFpYhklfHP3cwdJa5GOa+j2oMg0U9hCm
# 41iw1ca9RXNjleTza3+4PMqTYiIGaONyY2yhYzoGoWixYp02Cvs=
# SIG # End signature block
