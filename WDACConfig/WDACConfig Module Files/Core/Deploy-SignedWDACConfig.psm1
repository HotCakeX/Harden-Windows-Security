Function Deploy-SignedWDACConfig {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    [OutputType([System.String])]
    Param(
        [ArgumentCompleter([WDACConfig.ArgCompleter.XmlFileMultiSelectPicker])]
        [ValidateScript({ Test-CiPolicy -XmlFile $_ })]
        [parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [System.IO.FileInfo[]]$PolicyPaths,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$Deploy,

        [ArgumentCompleter([WDACConfig.ArgCompleter.SingleCerFilePicker])]
        [ValidatePattern('\.cer$')]
        [ValidateScript({ [System.IO.File]::Exists($_) }, ErrorMessage = 'The path you selected is not a file path.')]
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)][System.IO.FileInfo]$CertPath,

        [ArgumentCompleter({
                foreach ($Item in [WDACConfig.CertCNz]::new().GetValidValues()) {
                    if ($Item.Contains(' ')) {
                        "'$Item'"
                    }
                }
            })]
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)][System.String]$CertCN,

        [ArgumentCompleter([WDACConfig.ArgCompleter.ExeFilePathsPicker])]
        [ValidatePattern('\.exe$')]
        [ValidateScript({ [System.IO.File]::Exists($_) }, ErrorMessage = 'The path you selected is not a file path.')]
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [System.IO.FileInfo]$SignToolPath,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$Force,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )
    Begin {
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false
        [System.Boolean]$Debug = $PSBoundParameters.Debug.IsPresent ? $true : $false
        [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)
        . "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\PSDefaultParameterValues.ps1"

        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -Force -FullyQualifiedName @(
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Update-Self.psm1",
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Get-SignTool.psm1"
        )

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-Self -InvocationStatement $MyInvocation.Statement }

        if ([WDACConfig.GlobalVars]::ConfigCIBootstrap -eq $false) {
            Invoke-MockConfigCIBootstrap
            [WDACConfig.GlobalVars]::ConfigCIBootstrap = $true
        }

        [System.IO.DirectoryInfo]$StagingArea = [WDACConfig.StagingArea]::NewStagingArea('Deploy-SignedWDACConfig')

        #Region User-Configurations-Processing-Validation
        # Get SignToolPath from user parameter or user config file or auto-detect it
        if ($SignToolPath) {
            [System.IO.FileInfo]$SignToolPathFinal = Get-SignTool -SignToolExePathInput $SignToolPath
        } # If it is null, then Get-SignTool will behave the same as if it was called without any arguments.
        else {
            [System.IO.FileInfo]$SignToolPathFinal = Get-SignTool -SignToolExePathInput (Get-CommonWDACConfig -SignToolPath)
        }

        # If CertPath parameter wasn't provided by user, check if a valid value exists in user configs, if so, use it, otherwise throw an error
        if (!$CertPath ) {
            if ([System.IO.File]::Exists((Get-CommonWDACConfig -CertPath))) {
                [System.IO.FileInfo]$CertPath = Get-CommonWDACConfig -CertPath
            }
            else {
                throw 'CertPath parameter cannot be empty and no valid user configuration was found for it. Use the Build-WDACCertificate cmdlet to create one.'
            }
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
        #Endregion User-Configurations-Processing-Validation

        # Detecting if Confirm switch is used to bypass the confirmation prompts
        if ($Force -and -Not $Confirm) {
            $ConfirmPreference = 'None'
        }
    }

    process {

        Try {

            foreach ($PolicyPath in $PolicyPaths) {
                # The total number of the main steps for the progress bar to render
                [System.UInt16]$TotalSteps = $Deploy ? 4 : 3
                [System.UInt16]$CurrentStep = 0

                $CurrentStep++
                Write-Progress -Id 13 -Activity 'Gathering policy details' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message "Gathering policy details from: $PolicyPath"
                $Xml = [System.Xml.XmlDocument](Get-Content -Path $PolicyPath)
                [System.String]$PolicyType = $Xml.SiPolicy.PolicyType
                [System.String]$PolicyID = $Xml.SiPolicy.PolicyID
                [System.String]$PolicyName = ($Xml.SiPolicy.Settings.Setting | Where-Object -FilterScript { $_.provider -eq 'PolicyInfo' -and $_.valuename -eq 'Name' -and $_.key -eq 'Information' }).value.string
                [System.String[]]$PolicyRuleOptions = $Xml.SiPolicy.Rules.Rule.Option

                Write-Verbose -Message 'Checking if the policy type is Supplemental and if so, removing the -Supplemental parameter from the SignerRule command'
                if ($PolicyType -eq 'Supplemental Policy') {

                    Write-Verbose -Message 'Policy type is Supplemental'

                    # Make sure -User is not added if the UMCI policy rule option doesn't exist in the policy, typically for Strict kernel mode policies
                    if ('Enabled:UMCI' -in $PolicyRuleOptions) {
                        Add-SignerRule -FilePath $PolicyPath -CertificatePath $CertPath -Update -User -Kernel
                    }
                    else {
                        Write-Verbose -Message 'UMCI policy rule option does not exist in the policy, typically for Strict kernel mode policies'
                        Add-SignerRule -FilePath $PolicyPath -CertificatePath $CertPath -Update -Kernel
                    }
                }
                elseif ($PolicyType -eq 'Base Policy') {

                    Write-Verbose -Message 'Policy type is Base'

                    # Make sure -User is not added if the UMCI policy rule option doesn't exist in the policy, typically for Strict kernel mode policies
                    if ('Enabled:UMCI' -in $PolicyRuleOptions) {

                        Write-Verbose -Message 'Checking whether SignTool.exe is allowed to execute in the policy or not'
                        if (-NOT (Invoke-WDACSimulation -FilePath $SignToolPathFinal -XmlFilePath $PolicyPath -BooleanOutput -NoCatalogScanning -ThreadsCount 1 -SkipVersionCheck)) {

                            Write-Verbose -Message 'The policy type is base policy and it applies to user mode files, yet the policy prevents SignTool.exe from executing. As a precautionary measure, scanning and including the SignTool.exe in the policy before deployment so you can modify/remove the signed policy later from the system.'

                            Write-Verbose -Message 'Creating a temporary folder to store the symbolic link to the SignTool.exe'
                            [System.IO.DirectoryInfo]$SymLinksStorage = New-Item -Path (Join-Path -Path $StagingArea -ChildPath 'SymLinkStorage') -ItemType Directory -Force

                            Write-Verbose -Message 'Creating symbolic link to the SignTool.exe'
                            $null = New-Item -ItemType SymbolicLink -Path "$SymLinksStorage\SignTool.exe" -Target $SignToolPathFinal -Force

                            Write-Verbose -Message 'Scanning the SignTool.exe and generating the SignTool.xml policy'
                            New-CIPolicy -ScanPath $SymLinksStorage -Level FilePublisher -Fallback None -UserPEs -UserWriteablePaths -MultiplePolicyFormat -AllowFileNameFallbacks -FilePath "$SymLinksStorage\SignTool.xml" -PathToCatroot 'C:\Program Files\Windows Defender\Offline'

                            [System.IO.FileInfo]$AugmentedPolicyPath = Join-Path -Path $SymLinksStorage -ChildPath $PolicyPath.Name

                            Write-Verbose -Message 'Merging the SignTool.xml policy with the policy being signed'
                            # First policy in the array should always be the main one so that its settings will be used in the merged policy
                            $null = Merge-CIPolicy -PolicyPaths $PolicyPath, "$SymLinksStorage\SignTool.xml" -OutputFilePath $AugmentedPolicyPath

                            Write-Verbose -Message 'Making sure policy rule options stay the same after merging the policies'
                            [WDACConfig.CiPolicyUtility]::CopyCiRules($PolicyPath, $AugmentedPolicyPath)

                            Write-Verbose -Message 'Replacing the new policy with the old one'
                            Move-Item -Path $AugmentedPolicyPath -Destination $PolicyPath -Force
                        }
                        else {
                            Write-Verbose -Message 'The base policy allows SignTool.exe to execute, no need to scan and include it in the policy'
                        }

                        Add-SignerRule -FilePath $PolicyPath -CertificatePath $CertPath -Update -User -Kernel -Supplemental
                    }
                    else {
                        Write-Verbose -Message 'UMCI policy rule option does not exist in the policy, typically for Strict kernel mode policies'
                        Add-SignerRule -FilePath $PolicyPath -CertificatePath $CertPath -Update -Kernel -Supplemental
                    }
                }
                else {
                    Throw "Policy type is not Base or Supplemental, it is: $PolicyType"
                }

                $CurrentStep++
                Write-Progress -Id 13 -Activity 'Creating CIP file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Set-CiRuleOptions -FilePath $PolicyPath -RulesToRemove 'Enabled:Unsigned System Integrity Policy'

                [system.io.FileInfo]$PolicyCIPPath = Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip"

                Write-Verbose -Message 'Converting the policy to .CIP file'
                $null = ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath $PolicyCIPPath

                $CurrentStep++
                Write-Progress -Id 13 -Activity 'Signing the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)
                [WDACConfig.CodeIntegritySigner]::InvokeCiSigning($PolicyCIPPath, $SignToolPathFinal, $CertCN)

                Write-Verbose -Message 'Renaming the .p7 file to .cip'
                Move-Item -LiteralPath "$StagingArea\$PolicyID.cip.p7" -Destination $PolicyCIPPath -Force

                if ($Deploy) {

                    $CurrentStep++
                    Write-Progress -Id 13 -Activity 'Deploying' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    # Prompt for confirmation before proceeding
                    if ($PSCmdlet.ShouldProcess('This PC', 'Deploying the signed policy')) {

                        Write-Verbose -Message 'Deploying the policy'
                        $null = &'C:\Windows\System32\CiTool.exe' --update-policy $PolicyCIPPath -json

                        Write-ColorfulTextWDACConfig -Color Lavender -InputText 'policy with the following details has been Signed and Deployed in Enforced Mode:'
                        Write-ColorfulTextWDACConfig -Color MintGreen -InputText "PolicyName = $PolicyName"
                        Write-ColorfulTextWDACConfig -Color MintGreen -InputText "PolicyGUID = $PolicyID"

                        #Region Detecting Strict Kernel mode policy and removing it from User Configs
                        if ('Enabled:UMCI' -notin $PolicyRuleOptions) {

                            [System.String]$StrictKernelPolicyGUID = Get-CommonWDACConfig -StrictKernelPolicyGUID
                            [System.String]$StrictKernelNoFlightRootsPolicyGUID = Get-CommonWDACConfig -StrictKernelNoFlightRootsPolicyGUID

                            if (($PolicyName -like '*Strict Kernel mode policy Enforced*')) {

                                Write-Verbose -Message 'The deployed policy is Strict Kernel mode'

                                if ($StrictKernelPolicyGUID) {
                                    if ($($PolicyID.TrimStart('{').TrimEnd('}')) -eq $StrictKernelPolicyGUID) {

                                        Write-Verbose -Message 'Removing the GUID of the deployed Strict Kernel mode policy from the User Configs'
                                        $null = Remove-CommonWDACConfig -StrictKernelPolicyGUID
                                    }
                                }
                            }
                            elseif (($PolicyName -like '*Strict Kernel No Flights mode policy Enforced*')) {

                                Write-Verbose -Message 'The deployed policy is Strict Kernel No Flights mode'

                                if ($StrictKernelNoFlightRootsPolicyGUID) {
                                    if ($($PolicyID.TrimStart('{').TrimEnd('}')) -eq $StrictKernelNoFlightRootsPolicyGUID) {

                                        Write-Verbose -Message 'Removing the GUID of the deployed Strict Kernel No Flights mode policy from the User Configs'
                                        $null = Remove-CommonWDACConfig -StrictKernelNoFlightRootsPolicyGUID
                                    }
                                }
                            }
                        }
                        #Endregion Detecting Strict Kernel mode policy and removing it from User Configs
                    }
                }
                else {
                    Copy-Item -Path $PolicyCIPPath -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force

                    Write-ColorfulTextWDACConfig -Color Lavender -InputText 'policy with the following details has been Signed and is ready for deployment:'
                    Write-ColorfulTextWDACConfig -Color MintGreen -InputText "PolicyName = $PolicyName"
                    Write-ColorfulTextWDACConfig -Color MintGreen -InputText "PolicyGUID = $PolicyID"
                }
                Write-Progress -Id 13 -Activity 'Complete.' -Completed
            }
        }
        catch {
            throw $_
        }
        Finally {
            if (-NOT $Debug) {
                Remove-Item -Path $StagingArea -Recurse -Force
            }
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
.PARAMETER Deploy
    Indicates that the cmdlet will deploy the signed policy on the current system
.PARAMETER Force
    Indicates that the cmdlet will bypass the confirmation prompts
.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases
.INPUTS
    System.String
    System.String[]
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
.EXAMPLE
    Deploy-SignedWDACConfig -PolicyPaths 'C:\Users\WDACConfig\Policy.xml' -CertPath 'C:\Users\WDACConfig\MyCert.cer' -CertCN 'MyCertCN' -Deploy
    This example signs and deploys the policy.xml file using the MyCert.cer certificate and deploys it on the current system
.EXAMPLE
    Deploy-SignedWDACConfig -PolicyPaths 'C:\Users\WDACConfig\Policy.xml'
    This example signs the policy.xml file using the MyCert.cer certificate but does not deploy it on the current system.
    It accesses the user configs to get the certificate path and common name, if they are not found, it throws an error.
#>
}
