Function Remove-WDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = 'Signed Base',
        SupportsShouldProcess = $true,
        PositionalBinding = $False,
        ConfirmImpact = 'High'
    )]
    [OutputType([System.String])]
    Param(
        [Alias('S')]
        [Parameter(Mandatory = $False, ParameterSetName = 'Signed Base')][System.Management.Automation.SwitchParameter]$SignedBase,
        [Alias('U')]
        [Parameter(Mandatory = $False, ParameterSetName = 'Unsigned Or Supplemental')][System.Management.Automation.SwitchParameter]$UnsignedOrSupplemental,

        [ArgumentCompleter([WDACConfig.ArgCompleter.XmlFileMultiSelectPicker])]
        [ValidateScript({
                # Validate each Policy file in PolicyPaths parameter to make sure the user isn't accidentally trying to remove an Unsigned policy
                $_ | ForEach-Object -Process {
                    [System.Xml.XmlDocument]$XmlTest = Get-Content -Path $_
                    [System.String]$RedFlag1 = $XmlTest.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
                    [System.String]$RedFlag2 = $XmlTest.SiPolicy.UpdatePolicySigners.UpdatePolicySigner.SignerId

                    if ($RedFlag1 -or $RedFlag2) {

                        # Ensure the selected base policy xml file is valid
                        if ( Test-CiPolicy -XmlFile $_ ) {
                            return $True
                        }
                    }
                }
            }, ErrorMessage = 'One of the selected XML policy files is unsigned. Please use Remove-WDACConfig cmdlet with -UnsignedOrSupplemental parameter instead.')]
        [parameter(Mandatory = $true, ParameterSetName = 'Signed Base', ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo[]]$PolicyPaths,

        [ArgumentCompleter({
                foreach ($Item in [WDACConfig.CertCNz]::new().GetValidValues()) {
                    if ($Item.Contains(' ')) {
                        "'$Item'"
                    }
                }
            })]
        [parameter(Mandatory = $False, ParameterSetName = 'Signed Base', ValueFromPipelineByPropertyName = $true)]
        [System.String]$CertCN,

        [ArgumentCompleter({
                # Define the parameters that this script block will accept.
                param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)

                # Get a list of policies using the CiTool, excluding system policies and policies that aren't on disk.
                # by adding "{ $_.FriendlyName }" we make sure the auto completion works when at least one of the policies doesn't have a friendly name
                $Policies = foreach ($Item in (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies) {
                    if (($Item.IsOnDisk -eq 'True') -and ($Item.IsSystemPolicy -ne 'True') -and $Item.FriendlyName) {
                        $Item
                    }
                }

                # Create a hashtable mapping policy names to policy IDs. This will be used later to check if a policy ID already exists.
                [System.Collections.Hashtable]$NameIDMap = @{}
                foreach ($Policy in $Policies) {
                    $NameIDMap[$Policy.Friendlyname] = $Policy.policyID
                }

                # Get the IDs of existing policies that are already being used in the current command.
                $ExistingIDs = $FakeBoundParameters['PolicyIDs']

                # Get the policy names that are currently being used in the command. This is done by looking at the abstract syntax tree (AST)
                # of the command and finding all string literals, which are assumed to be policy names.
                $Existing = $CommandAst.FindAll({
                        $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    }, $False).Value

                # Filter out the policy names that are already being used or whose corresponding policy IDs are already being used.
                # The resulting list of policy names is what will be shown as autocomplete suggestions.
                $Candidates = foreach ($Item in $Policies.Friendlyname) {
                    if ($Item -notin $Existing -and $NameIDMap[$Item] -notin $ExistingIDs) {
                        $Item
                    }
                }

                # Additionally, if the policy name contains spaces, it's enclosed in single quotes to ensure it's treated as a single argument.
                # This is achieved using the Compare-Object cmdlet to compare the existing and candidate values, and outputting the resulting matches.
                # For each resulting match, it checks if the match contains a space, if so, it's enclosed in single quotes, if not, it's returned as is.
                foreach ($Item in (Compare-Object -ReferenceObject $Candidates -DifferenceObject $Existing -PassThru)) {
                    if ($Item.SideIndicator -eq '<=') {
                        if ($Item -match ' ') {
                            "'{0}'" -f $Item
                        }
                        else {
                            $Item
                        }
                    }
                }
            })]
        [ValidateScript({
                if (
                    !([System.Collections.Generic.HashSet[System.String]]@([PolicyNamezx]::new().GetValidValues())).Contains($_)
                ) {
                    throw "Invalid policy name: $_"
                }
                $true
            })]
        [Parameter(Mandatory = $False, ParameterSetName = 'Unsigned Or Supplemental')]
        [System.String[]]$PolicyNames,

        [ArgumentCompleter({
                param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)

                # Get a list of policies using the CiTool, excluding system policies and policies that aren't on disk.
                $Policies = foreach ($Item in (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies) {
                    if (($Item.IsOnDisk -eq 'True') -and ($Item.IsSystemPolicy -ne 'True')) {
                        $Item
                    }
                }

                # Create a hashtable mapping policy IDs to policy names. This will be used later to check if a policy name already exists.
                [System.Collections.Hashtable]$IDNameMap = @{}
                foreach ($Policy in $Policies) {
                    $IDNameMap[$Policy.policyID] = $Policy.Friendlyname
                }

                # Get the names of existing policies that are already being used in the current command.
                $ExistingNames = $FakeBoundParameters['PolicyNames']

                # Get the policy IDs that are currently being used in the command. This is done by looking at the abstract syntax tree (AST)
                # of the command and finding all string literals, which are assumed to be policy IDs.
                $Existing = $CommandAst.FindAll({
                        $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    }, $False).Value

                # Filter out the policy IDs that are already being used or whose corresponding policy names are already being used.
                # The resulting list of policy IDs is what will be shown as autocomplete suggestions.
                $Candidates = foreach ($Item in $Policies.policyID) {
                    if ($Item -notin $Existing -and $IDNameMap[$Item] -notin $ExistingNames) {
                        $Item
                    }
                }

                # Return the candidates
                return $Candidates
            })]
        [ValidateScript({
                if ($_ -notin [PolicyIDzx]::new().GetValidValues()) { throw "Invalid policy ID: $_" }
                $true
            })]
        [Parameter(Mandatory = $False, ParameterSetName = 'Unsigned Or Supplemental')]
        [System.String[]]$PolicyIDs,

        [ArgumentCompleter([WDACConfig.ArgCompleter.ExeFilePathsPicker])]
        [parameter(Mandatory = $False, ParameterSetName = 'Signed Base', ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo]$SignToolPath,

        [Parameter(Mandatory = $False)][System.Management.Automation.SwitchParameter]$Force,

        [Parameter(Mandatory = $False)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )
    Begin {
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $False
        [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)
        . "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\PSDefaultParameterValues.ps1"

        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -Force -FullyQualifiedName @(
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Update-Self.psm1",
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Get-SignTool.psm1",
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Write-ColorfulText.psm1",
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Remove-SupplementalSigners.psm1"
        )

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-Self -InvocationStatement $MyInvocation.Statement }

        [System.IO.DirectoryInfo]$StagingArea = [WDACConfig.StagingArea]::NewStagingArea('Remove-WDACConfig')

        #Region User-Configurations-Processing-Validation
        Write-Verbose -Message 'Validating and processing user configurations'

        if ($PSCmdlet.ParameterSetName -eq 'Signed Base') {

            # Get SignToolPath from user parameter or user config file or auto-detect it
            if ($SignToolPath) {
                [System.IO.FileInfo]$SignToolPathFinal = Get-SignTool -SignToolExePathInput $SignToolPath
            } # If it is null, then Get-SignTool will behave the same as if it was called without any arguments.
            else {
                [System.IO.FileInfo]$SignToolPathFinal = Get-SignTool -SignToolExePathInput (Get-CommonWDACConfig -SignToolPath)
            }

            # If CertCN was not provided by user, check if a valid value exists in user configs, if so, use it, otherwise throw an error
            if (!$CertCN) {
                if ([WDACConfig.CertCNz]::new().GetValidValues() -contains (Get-CommonWDACConfig -CertCN)) {
                    [System.String]$CertCN = Get-CommonWDACConfig -CertCN
                }
                else {
                    throw 'CertCN parameter cannot be empty and no valid user configuration was found for it.'
                }
            }
            else {
                if ([WDACConfig.CertCNz]::new().GetValidValues() -notcontains $CertCN) {
                    throw "$CertCN does not belong to a subject CN of any of the deployed certificates"
                }
            }
        }
        #Endregion User-Configurations-Processing-Validation

        # ValidateSet for Policy names
        Class PolicyNamezx : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {

                $PolicyNamezx = [System.Collections.Generic.HashSet[System.String]]@(foreach ($Policy in (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies) {
                        if ( ($Policy.IsOnDisk -eq 'True') -and ($Policy.IsSystemPolicy -ne 'True')) {
                            $Policy.Friendlyname
                        }
                    })
                return $PolicyNamezx
            }
        }

        # ValidateSet for Policy IDs
        Class PolicyIDzx : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {

                [System.String[]]$PolicyIDzx = foreach ($Item in (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies) {
                    if (($Item.IsOnDisk -eq 'True') -and ($Item.IsSystemPolicy -ne 'True')) {
                        $Item.PolicyID
                    }
                }

                return $PolicyIDzx
            }
        }

        # Detecting if Confirm switch is used to bypass the confirmation prompts
        if ($Force -and -Not $Confirm) {
            $ConfirmPreference = 'None'
        }
    }

    process {

        Try {

            # If a signed policy is being removed
            if ($SignedBase) {

                Write-Verbose -Message 'Looping over each selected policy XML file'
                foreach ($PolicyPath in $PolicyPaths) {

                    # The total number of the main steps for the progress bar to render
                    $TotalSteps = 3us
                    $CurrentStep = 0us

                    $CurrentStep++
                    Write-Progress -Id 18 -Activity 'Parsing the XML Policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Converting the XML file to an XML object'
                    [System.Xml.XmlDocument]$Xml = Get-Content -Path $PolicyPath

                    Write-Verbose -Message 'Extracting the Policy ID from the XML object'
                    [System.String]$PolicyID = $Xml.SiPolicy.PolicyID
                    Write-Verbose -Message "The policy ID of the currently processing xml file is $PolicyID"

                    # Extracting the policy name from the selected XML policy file
                    [System.String]$PolicyName = foreach ($Item in $Xml.SiPolicy.Settings.Setting) {
                        if ($Item.Provider -eq 'PolicyInfo' -and $Item.ValueName -eq 'Name' -and $Item.Key -eq 'Information') {
                            $Item.Value.String
                        }
                    }

                    # Prevent users from accidentally attempting to remove policies that aren't even deployed on the system
                    Write-Verbose -Message 'Making sure the selected XML policy is deployed on the system'

                    Try {
                        [System.Guid[]]$CurrentPolicyIDs = foreach ($Item in (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies) {
                            if ($Item.IsSystemPolicy -ne 'True') {
                                "{$($Item.PolicyID)}"
                            }
                        }
                    }
                    catch {
                        Throw 'No policy is deployed on the system.'
                    }

                    if ($CurrentPolicyIDs -notcontains $PolicyID) {
                        Throw 'The selected policy file is not deployed on the system.'
                    }

                    $CurrentStep++
                    Write-Progress -Id 18 -Activity 'Processing the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Making sure SupplementalPolicySigners do not exist in the XML policy'
                    Remove-SupplementalSigners -Path $PolicyPath

                    Set-CiRuleOptions -FilePath $PolicyPath -RulesToAdd 'Enabled:Unsigned System Integrity Policy'

                    [System.IO.FileInfo]$PolicyCIPPath = Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip"

                    # Converting the Policy XML file to CIP binary file
                    $null = ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath $PolicyCIPPath

                    $CurrentStep++
                    Write-Progress -Id 18 -Activity 'Signing the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [WDACConfig.CodeIntegritySigner]::InvokeCiSigning($PolicyCIPPath, $SignToolPathFinal, $CertCN)

                    # Fixing the extension name of the newly signed CIP file
                    Move-Item -Path (Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip.p7") -Destination $PolicyCIPPath -Force

                    # Deploying the newly signed CIP file

                    # Prompt for confirmation before proceeding
                    if ($PSCmdlet.ShouldProcess('This PC', 'Deploying the signed policy')) {

                        Write-Verbose -Message 'Deploying the newly signed CIP file'
                        $null = &'C:\Windows\System32\CiTool.exe' --update-policy $PolicyCIPPath -json

                        Write-ColorfulText -Color Lavender -InputText "Policy with the following details has been Re-signed and Re-deployed in Unsigned mode.`nPlease restart your system."
                        Write-ColorfulText -Color MintGreen -InputText "PolicyName = $PolicyName"
                        Write-ColorfulText -Color MintGreen -InputText "PolicyGUID = $PolicyID"
                    }
                    Write-Progress -Id 18 -Activity 'Complete.' -Completed
                }
            }

            # If an unsigned policy is being removed
            if ($UnsignedOrSupplemental) {

                # If IDs were supplied by user
                foreach ($ID in $PolicyIDs ) {
                    $null = &'C:\Windows\System32\CiTool.exe' --remove-policy "{$ID}" -json
                    Write-ColorfulText -Color Lavender -InputText "Policy with the ID $ID has been successfully removed."
                }

                # If names were supplied by user
                # HashSet to store Unique Policy IDs based on the input name, this will take care of the situations where multiple policies with the same name are deployed
                $NameID = [System.Collections.Generic.HashSet[System.String]]@(foreach ($PolicyName in $PolicyNames) {
                        foreach ($Item in (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies ) {
                            if (($Item.IsOnDisk -eq 'True') -and ($Item.FriendlyName -eq $PolicyName)) {
                                $Item.PolicyID
                            }
                        }
                    })

                Write-Verbose -Message "$($NameID.count) policy IDs have been gathered from the supplied policy names and are going to be removed from the system"

                foreach ($ID in $NameID) {
                    $null = &'C:\Windows\System32\CiTool.exe' --remove-policy "{$ID}" -json
                    Write-ColorfulText -Color Lavender -InputText "Policy with the ID $ID has been successfully removed."
                }
            }
        }
        catch {
            throw $_
        }
        Finally {
            # Clean up the staging area
            Remove-Item -Path $StagingArea -Recurse -Force
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
    System.IO.FileInfo
    System.IO.FileInfo[]
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
#>
}
