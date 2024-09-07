Function New-KernelModeWDACConfig {
    [CmdletBinding(
        PositionalBinding = $false
    )]
    [OutputType([System.String])]
    Param(
        [ValidateSet('Prep', 'AuditAndEnforce')]
        [Parameter(Mandatory = $true)]
        [System.String]$Mode,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$Deploy,
        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$EVSigners,

        [ValidateSet('Default', 'NoFlightRoots')]
        [Parameter(Mandatory = $false)]
        [System.String]$Base = 'Default',

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
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Get-KernelModeDriversAudit.psm1"
        )

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-Self -InvocationStatement $MyInvocation.Statement }

        [System.IO.DirectoryInfo]$StagingArea = [WDACConfig.StagingArea]::NewStagingArea('New-KernelModeWDACConfig')

        # Create a directory to store the kernel mode drivers symbolic links for both modes
        [System.IO.DirectoryInfo]$KernelModeDriversDirectory = New-Item -ItemType Directory -Path (Join-Path -Path $StagingArea -ChildPath 'KernelModeDriversDirectory') -Force

        # Defining the path to the driver files scan results policy for both modes
        [System.IO.FileInfo]$DriverFilesScanPolicyPath = Join-Path -Path $StagingArea -ChildPath 'DriverFilesScanPolicy.xml'

        # Defining the path to the final Enforced mode policy for both modes
        [System.IO.FileInfo]$FinalEnforcedPolicyPath = Join-Path -Path $StagingArea -ChildPath 'DefaultWindows_Enforced_Kernel.xml'

        # Defining the paths to the kernel-mode template policies for each mode
        [System.IO.FileInfo]$TemplatePolicyPath = $Base -eq 'Default' ? "$([WDACConfig.GlobalVars]::ModuleRootPath)\Resources\WDAC Policies\DefaultWindows_Enforced_Kernel.xml" : "$([WDACConfig.GlobalVars]::ModuleRootPath)\Resources\WDAC Policies\DefaultWindows_Enforced_Kernel_NoFlights.xml"

        # A flag that will be set to true if errors occur
        [System.Boolean]$NoCopy = $false

        Function Build-PrepModeStrictKernelPolicy {
            <#
            .SYNOPSIS
                A helper function to build Audit mode policy only and returns a PSCustomObject with the policy path and policy ID
            .INPUTS
                System.Management.Automation.SwitchParameter
            .OUTPUTS
                PSCustomObject
            #>
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$Normal,
                [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$NoFlights
            )
            begin {
                Write-Verbose -Message 'Executing the Build-PrepModeStrictKernelPolicy helper function'

                [System.IO.FileInfo]$OutputPolicyPath = Join-Path -Path $StagingArea -ChildPath ($Normal ? 'DefaultWindows_Audit_Kernel.xml' : 'DefaultWindows_Audit_Kernel_NoFlights.xml')
                [System.String]$PolicyName = $Normal ? 'Strict Kernel mode policy Audit' : 'Strict Kernel No Flights mode policy Audit'

                if ($Normal) {
                    # Check if there is a pending Audit mode Kernel mode WDAC policy already available in User Config file
                    [System.String]$CurrentStrictKernelPolicyGUID = Get-CommonWDACConfig -StrictKernelPolicyGUID

                    If ($null -ne $CurrentStrictKernelPolicyGUID) {
                        # Check if the pending Audit mode Kernel mode WDAC policy is deployed on the system
                        [System.String]$CurrentStrictKernelPolicyGUIDConfirmation = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.PolicyID -eq $CurrentStrictKernelPolicyGUID }).policyID
                    }
                }

                if ($NoFlights) {
                    # Check if there is a pending Audit mode Kernel mode WDAC NoFlightRoots policy already available in User Config file
                    [System.String]$CurrentStrictKernelNoFlightRootsPolicyGUID = Get-CommonWDACConfig -StrictKernelNoFlightRootsPolicyGUID

                    If ($null -ne $CurrentStrictKernelNoFlightRootsPolicyGUID) {
                        # Check if the pending Audit mode Kernel mode WDAC NoFlightRoots policy is deployed on the system
                        [System.String]$CurrentStrictKernelPolicyGUIDConfirmation = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.PolicyID -eq $CurrentStrictKernelNoFlightRootsPolicyGUID }).policyID
                    }
                }
            }

            process {
                Write-Verbose -Message 'Copying the base policy to the Staging Area'
                Copy-Item -Path $TemplatePolicyPath -Destination $OutputPolicyPath -Force

                Write-Verbose -Message 'Resetting the policy ID and assigning a name for the policy'
                [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath $OutputPolicyPath -PolicyName "$PolicyName" -ResetPolicyID
                $PolicyID = $PolicyID.Substring(11)

                Write-Verbose -Message 'Setting the policy version to 1.0.0.0'
                Set-CIPolicyVersion -FilePath $OutputPolicyPath -Version '1.0.0.0'

                Set-CiRuleOptions -FilePath $OutputPolicyPath -Template BaseKernel -RulesToAdd 'Enabled:Audit Mode' -RequireEVSigners:$EVSigners -DisableFlightSigning:$NoFlights

                # Set the already available and deployed GUID as the new PolicyID to prevent deploying duplicate Audit mode policies
                if ($CurrentStrictKernelPolicyGUIDConfirmation) {
                    [WDACConfig.PolicyEditor]::EditGUIDs($CurrentStrictKernelPolicyGUIDConfirmation, $OutputPolicyPath)
                    $PolicyID = $CurrentStrictKernelPolicyGUIDConfirmation
                }
            }
            End {
                Return [PSCustomObject]@{
                    PolicyPath = $OutputPolicyPath
                    PolicyID   = $PolicyID
                }
            }
        }
    }

    process {

        Try {

            :MainSwitch Switch ($Base) {

                'Default' {

                    Switch ($Mode) {

                        'Prep' {

                            # The total number of the main steps for the progress bar to render
                            [System.UInt16]$TotalSteps = $Deploy ? 2 : 1
                            [System.UInt16]$CurrentStep = 0

                            $CurrentStep++
                            Write-Progress -Id 25 -Activity 'Creating the prep mode policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                            Write-Verbose -Message 'Building the Audit mode policy'
                            [PSCustomObject]$AuditPolicy = Build-PrepModeStrictKernelPolicy -Normal
                            [System.String]$PolicyID = $AuditPolicy.PolicyID
                            [System.IO.FileInfo]$AuditPolicyPath = $AuditPolicy.PolicyPath

                            [System.IO.FileInfo]$FinalAuditCIPPath = Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip"

                            Write-Verbose -Message 'Converting the XML policy file to CIP binary'
                            $null = ConvertFrom-CIPolicy -XmlFilePath $AuditPolicyPath -BinaryFilePath $FinalAuditCIPPath

                            # Deploy the policy if Deploy parameter is used and perform additional tasks on the system
                            if ($Deploy) {

                                $CurrentStep++
                                Write-Progress -Id 25 -Activity 'Deploying the prep mode policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                                Write-Verbose -Message 'Setting the GUID and time of deployment of the Audit mode policy in the User Configuration file'
                                $null = Set-CommonWDACConfig -StrictKernelPolicyGUID $PolicyID -StrictKernelModePolicyTimeOfDeployment (Get-Date)

                                Write-Verbose -Message 'Deploying the Strict Kernel mode policy'
                                $null = &'C:\Windows\System32\CiTool.exe' --update-policy $FinalAuditCIPPath -json
                                Write-ColorfulTextWDACConfig -Color HotPink -InputText 'Strict Kernel mode policy has been deployed in Audit mode, please restart your system.'
                            }
                            else {
                                Write-ColorfulTextWDACConfig -Color HotPink -InputText 'Strict Kernel mode Audit policy has been created in the Staging Area.'
                            }
                            Write-Progress -Id 25 -Activity 'Done' -Completed

                            break MainSwitch
                        }

                        'AuditAndEnforce' {

                            # The total number of the main steps for the progress bar to render
                            [System.UInt16]$TotalSteps = $Deploy ? 3 : 2
                            [System.UInt16]$CurrentStep = 0

                            # Get the Strict Kernel Audit mode policy's GUID to use for the Enforced mode policy
                            # This will eliminate the need for an extra reboot
                            Write-Verbose -Message 'Trying to get the GUID of Strict Kernel Audit mode policy to use for the Enforced mode policy, from the user configurations'
                            [System.String]$PolicyID = Get-CommonWDACConfig -StrictKernelPolicyGUID

                            Write-Verbose -Message 'Verifying the Policy ID in the User Config exists and is valid'
                            $ObjectGuid = [System.Guid]::Empty
                            if ([System.Guid]::TryParse($PolicyID, [ref]$ObjectGuid)) {
                                Write-Verbose -Message 'Valid GUID found in User Configs for Audit mode policy'
                            }
                            else {
                                Throw 'Invalid or nonexistent GUID in User Configs for Audit mode policy, Use the -PrepMode parameter first.'
                            }

                            $CurrentStep++
                            Write-Progress -Id 26 -Activity 'Scanning the Event logs' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                            # Get the kernel mode drivers directory path containing symlinks
                            Get-KernelModeDriversAudit -SavePath $KernelModeDriversDirectory

                            powershell.exe -NoProfile -Command {
                                # Prep the environment as a workaround for the ConfigCI bug
                                if ([System.IO.Directory]::Exists('C:\Program Files\Windows Defender\Offline')) {
                                    [System.String]$RandomGUID = [System.Guid]::NewGuid().ToString()
                                    New-CIPolicy -UserPEs -ScanPath 'C:\Program Files\Windows Defender\Offline' -Level hash -FilePath ".\$RandomGUID.xml" -NoShadowCopy -PathToCatroot 'C:\Program Files\Windows Defender\Offline' -WarningAction SilentlyContinue
                                    Remove-Item -LiteralPath ".\$RandomGUID.xml" -Force
                                }

                                Write-Verbose -Message 'Scanning the kernel-mode drivers detected in Event viewer logs'
                                [System.Collections.ArrayList]$DriverFilesObj = Get-SystemDriver -ScanPath $args[0]

                                Write-Verbose -Message 'Creating a policy xml file from the driver files'
                                New-CIPolicy -MultiplePolicyFormat -Level WHQLFilePublisher -Fallback None -AllowFileNameFallbacks -FilePath $args[1] -DriverFiles $DriverFilesObj
                            } -args $KernelModeDriversDirectory, $DriverFilesScanPolicyPath

                            $CurrentStep++
                            Write-Progress -Id 26 -Activity 'Creating the final policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                            Write-Verbose -Message 'Not trusting the policy xml file made before restart, so building the same policy again after restart, this time in Enforced mode instead of Audit mode'
                            Copy-Item -Path $TemplatePolicyPath -Destination (Join-Path -Path $StagingArea -ChildPath 'Raw_Normal.xml') -Force

                            Write-Verbose -Message 'Merging the base policy with the policy made from driver files, to deploy them as one policy'
                            $null = Merge-CIPolicy -PolicyPaths (Join-Path -Path $StagingArea -ChildPath 'Raw_Normal.xml'), $DriverFilesScanPolicyPath -OutputFilePath $FinalEnforcedPolicyPath

                            Write-Verbose -Message 'Moving all AllowedSigners from Usermode to Kernel mode signing scenario'
                            [WDACConfig.MoveUserModeToKernelMode]::Move($FinalEnforcedPolicyPath)

                            Write-Verbose -Message 'Setting the GUIDs for the XML policy file'
                            [WDACConfig.PolicyEditor]::EditGUIDs($PolicyID, $FinalEnforcedPolicyPath)

                            Write-Verbose -Message 'Setting a new policy name with the current date attached to it'
                            Set-CIPolicyIdInfo -FilePath $FinalEnforcedPolicyPath -PolicyName "Strict Kernel mode policy Enforced - $(Get-Date -Format 'MM-dd-yyyy')"

                            Write-Verbose -Message 'Setting the policy version to 1.0.0.0'
                            Set-CIPolicyVersion -FilePath $FinalEnforcedPolicyPath -Version '1.0.0.0'

                            Set-CiRuleOptions -FilePath $FinalEnforcedPolicyPath -Template BaseKernel -RequireEVSigners:$EVSigners

                            [System.IO.FileInfo]$FinalEnforcedCIPPath = Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip"

                            Write-Verbose -Message 'Converting the policy XML file to CIP binary'
                            $null = ConvertFrom-CIPolicy -XmlFilePath $FinalEnforcedPolicyPath -BinaryFilePath $FinalEnforcedCIPPath

                            # Deploy the policy if Deploy parameter is used
                            if ($Deploy) {

                                $CurrentStep++
                                Write-Progress -Id 26 -Activity 'Deploying the final policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                                Write-Verbose -Message 'Deploying the enforced mode policy with the same ID as the Audit mode policy, effectively overwriting it'
                                $null = &'C:\Windows\System32\CiTool.exe' --update-policy $FinalEnforcedCIPPath -json
                                Write-ColorfulTextWDACConfig -Color HotPink -InputText 'Strict Kernel mode policy has been deployed in Enforced mode, no restart required.'

                                Write-Verbose -Message 'Removing the GUID and time of deployment of the StrictKernelPolicy from user configuration'
                                $null = Remove-CommonWDACConfig -StrictKernelPolicyGUID -StrictKernelModePolicyTimeOfDeployment
                            }
                            else {
                                # Remove the Audit mode policy from the system
                                # This step is necessary if user didn't use the -Deploy parameter
                                # And instead wants to first Sign and then deploy it using the Deploy-SignedWDACConfig cmdlet
                                Write-Verbose -Message 'Removing the deployed Audit mode policy from the system since -Deploy parameter was not used to overwrite it with the enforced mode policy.'
                                $null = &'C:\Windows\System32\CiTool.exe' --remove-policy "{$PolicyID}" -json
                                Write-ColorfulTextWDACConfig -Color HotPink -InputText "Strict Kernel mode Enforced policy has been created`n$FinalEnforcedPolicyPath"
                            }
                            Write-Progress -Id 26 -Activity 'Complete.' -Completed

                            break MainSwitch
                        }
                    }
                }

                'NoFlightRoots' {

                    Switch ($Mode) {

                        'Prep' {

                            # The total number of the main steps for the progress bar to render
                            [System.UInt16]$TotalSteps = $Deploy ? 2 : 1
                            [System.UInt16]$CurrentStep = 0

                            $CurrentStep++
                            Write-Progress -Id 27 -Activity 'Creating the prep mode policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                            Write-Verbose -Message 'Building the Audit mode policy'
                            [PSCustomObject]$AuditPolicy = Build-PrepModeStrictKernelPolicy -NoFlights
                            [System.String]$PolicyID = $AuditPolicy.PolicyID
                            [System.IO.FileInfo]$AuditPolicyPath = $AuditPolicy.PolicyPath

                            [System.IO.FileInfo]$FinalAuditCIPPath = Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip"

                            Write-Verbose -Message 'Converting the XML policy file to CIP binary'
                            $null = ConvertFrom-CIPolicy -XmlFilePath $AuditPolicyPath -BinaryFilePath $FinalAuditCIPPath

                            # Deploy the policy if Deploy parameter is used and perform additional tasks on the system
                            if ($Deploy) {

                                $CurrentStep++
                                Write-Progress -Id 27 -Activity 'Deploying the prep mode policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                                Write-Verbose -Message 'Setting the GUID and time of deployment of the Audit mode policy in the User Configuration file'
                                $null = Set-CommonWDACConfig -StrictKernelNoFlightRootsPolicyGUID $PolicyID -StrictKernelModePolicyTimeOfDeployment (Get-Date)

                                Write-Verbose -Message 'Deploying the Strict Kernel mode policy'
                                $null = &'C:\Windows\System32\CiTool.exe' --update-policy $FinalAuditCIPPath -json
                                Write-ColorfulTextWDACConfig -Color HotPink -InputText 'Strict Kernel mode policy with no flighting root certs has been deployed in Audit mode, please restart your system.'
                            }
                            else {
                                Write-ColorfulTextWDACConfig -Color HotPink -InputText 'Strict Kernel mode Audit policy with no flighting root certs has been created in the Staging Area.'
                            }
                            Write-Progress -Id 27 -Activity 'Complete.' -Completed

                            break MainSwitch
                        }

                        'AuditAndEnforce' {

                            # The total number of the main steps for the progress bar to render
                            [System.UInt16]$TotalSteps = $Deploy ? 3 : 2
                            [System.UInt16]$CurrentStep = 0

                            # Get the Strict Kernel Audit mode policy's GUID to use for the Enforced mode policy
                            # This will eliminate the need for an extra reboot
                            Write-Verbose -Message 'Trying to get the GUID of Strict Kernel Audit mode policy to use for the Enforced mode policy, from the user configurations'
                            [System.String]$PolicyID = Get-CommonWDACConfig -StrictKernelNoFlightRootsPolicyGUID

                            Write-Verbose -Message 'Verifying the Policy ID in the User Config exists and is valid'
                            $ObjectGuid = [System.Guid]::Empty
                            if ([System.Guid]::TryParse($PolicyID, [ref]$ObjectGuid)) {
                                Write-Verbose -Message 'Valid GUID found in User Configs for Audit mode policy'
                            }
                            else {
                                Throw 'Invalid or nonexistent GUID in User Configs for Audit mode policy, Use the -PrepMode parameter first.'
                            }

                            $CurrentStep++
                            Write-Progress -Id 28 -Activity 'Scanning the Event logs' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                            # Get the kernel mode drivers directory path containing symlinks
                            Get-KernelModeDriversAudit -SavePath $KernelModeDriversDirectory

                            powershell.exe -NoProfile -Command {
                                # Prep the environment as a workaround for the ConfigCI bug
                                if ([System.IO.Directory]::Exists('C:\Program Files\Windows Defender\Offline')) {
                                    [System.String]$RandomGUID = [System.Guid]::NewGuid().ToString()
                                    New-CIPolicy -UserPEs -ScanPath 'C:\Program Files\Windows Defender\Offline' -Level hash -FilePath ".\$RandomGUID.xml" -NoShadowCopy -PathToCatroot 'C:\Program Files\Windows Defender\Offline' -WarningAction SilentlyContinue
                                    Remove-Item -LiteralPath ".\$RandomGUID.xml" -Force
                                }

                                Write-Verbose -Message 'Scanning the kernel-mode drivers detected in Event viewer logs'
                                [System.Collections.ArrayList]$DriverFilesObj = Get-SystemDriver -ScanPath $args[0]

                                Write-Verbose -Message 'Creating a policy xml file from the driver files'
                                New-CIPolicy -MultiplePolicyFormat -Level WHQLFilePublisher -Fallback None -AllowFileNameFallbacks -FilePath $args[1] -DriverFiles $DriverFilesObj
                            } -args $KernelModeDriversDirectory, $DriverFilesScanPolicyPath

                            $CurrentStep++
                            Write-Progress -Id 28 -Activity 'Creating the final policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                            Write-Verbose -Message 'Not trusting the policy xml file made before restart, so building the same policy again after restart, this time in Enforced mode instead of Audit mode'
                            Copy-Item -Path $TemplatePolicyPath -Destination (Join-Path -Path $StagingArea -ChildPath 'Raw_NoFlights.xml') -Force

                            Write-Verbose -Message 'Merging the base policy with the policy made from driver files, to deploy them as one policy'
                            $null = Merge-CIPolicy -PolicyPaths (Join-Path -Path $StagingArea -ChildPath 'Raw_NoFlights.xml'), $DriverFilesScanPolicyPath -OutputFilePath $FinalEnforcedPolicyPath

                            Write-Verbose -Message 'Moving all AllowedSigners from Usermode to Kernel mode signing scenario'
                            [WDACConfig.MoveUserModeToKernelMode]::Move($FinalEnforcedPolicyPath)

                            Write-Verbose -Message 'Setting the GUIDs for the XML policy file'
                            [WDACConfig.PolicyEditor]::EditGUIDs($PolicyID, $FinalEnforcedPolicyPath)

                            Write-Verbose -Message 'Setting a new policy name with the current date attached to it'
                            Set-CIPolicyIdInfo -FilePath $FinalEnforcedPolicyPath -PolicyName "Strict Kernel No Flights mode policy Enforced - $(Get-Date -Format 'MM-dd-yyyy')"

                            Write-Verbose -Message 'Setting the policy version to 1.0.0.0'
                            Set-CIPolicyVersion -FilePath $FinalEnforcedPolicyPath -Version '1.0.0.0'

                            Set-CiRuleOptions -FilePath $FinalEnforcedPolicyPath -Template BaseKernel -RulesToAdd 'Disabled:Flight Signing' -RequireEVSigners:$EVSigners

                            [System.IO.FileInfo]$FinalEnforcedCIPPath = Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip"

                            Write-Verbose -Message 'Converting the policy XML file to CIP binary'
                            $null = ConvertFrom-CIPolicy -XmlFilePath $FinalEnforcedPolicyPath -BinaryFilePath $FinalEnforcedCIPPath

                            # Deploy the policy if Deploy parameter is used
                            if ($Deploy) {

                                if ([System.IO.File]::Exists('C:\Windows\System32\ntoskrnl.exe')) {

                                    Write-Verbose -Message 'Making sure the current Windows build can work with the NoFlightRoots Strict WDAC Policy'

                                    if (-NOT (Invoke-WDACSimulation -FilePath 'C:\Windows\System32\ntoskrnl.exe' -XmlFilePath $FinalEnforcedPolicyPath -BooleanOutput -NoCatalogScanning -ThreadsCount 1 -SkipVersionCheck)) {
                                        Throw 'The current Windows build cannot work with the NoFlightRoots Strict Kernel-mode Policy, please change the base to Default instead.'
                                    }
                                }
                                else {
                                    Write-Verbose -Message "'C:\Windows\System32\ntoskrnl.exe' could not be found."
                                }

                                $CurrentStep++
                                Write-Progress -Id 28 -Activity 'Deploying the final policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                                Write-Verbose -Message 'Deploying the enforced mode policy with the same ID as the Audit mode policy, effectively overwriting it'
                                $null = &'C:\Windows\System32\CiTool.exe' --update-policy $FinalEnforcedCIPPath -json
                                Write-ColorfulTextWDACConfig -Color HotPink -InputText 'Strict Kernel mode policy with no flighting root certs has been deployed in Enforced mode, no restart required.'

                                Write-Verbose -Message 'Removing the GUID and time of deployment of the StrictKernelNoFlightRootsPolicy from user configuration'
                                $null = Remove-CommonWDACConfig -StrictKernelNoFlightRootsPolicyGUID -StrictKernelModePolicyTimeOfDeployment
                            }
                            else {
                                # Remove the Audit mode policy from the system
                                # This step is necessary if user didn't use the -Deploy parameter
                                # And instead wants to first Sign and then deploy it using the Deploy-SignedWDACConfig cmdlet
                                Write-Verbose -Message 'Removing the deployed Audit mode policy from the system since -Deploy parameter was not used to overwrite it with the enforced mode policy.'
                                $null = &'C:\Windows\System32\CiTool.exe' --remove-policy "{$PolicyID}" -json
                                Write-ColorfulTextWDACConfig -Color HotPink -InputText "Strict Kernel mode Enforced policy with no flighting root certs has been created`n$FinalEnforcedPolicyPath"
                            }
                            Write-Progress -Id 28 -Activity 'Complete.' -Completed

                            break MainSwitch
                        }
                    }
                }
            }
        }
        catch {
            $NoCopy = $true
            Throw $_
        }
        finally {
            # Copy the final policy files to the User Config directory
            if (-NOT $NoCopy) {
                Copy-Item -Path ($Mode -eq 'Prep' ? ($Deploy ? $AuditPolicyPath : $AuditPolicyPath, $FinalAuditCIPPath) : ($Deploy ? $FinalEnforcedPolicyPath : $FinalEnforcedPolicyPath, $FinalEnforcedCIPPath)) -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force
            }
            if (-NOT $Debug) {
                Remove-Item -Path $StagingArea -Recurse -Force
            }
        }
    }

    <#
.SYNOPSIS
    Creates Kernel only mode WDAC policy capable of protecting against BYOVD attacks category
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/New%E2%80%90KernelModeWDACConfig
.DESCRIPTION
    Using official Microsoft methods, configure and use Windows Defender Application Control
.COMPONENT
    Windows Defender Application Control, ConfigCI PowerShell module
.FUNCTIONALITY
    Creates Kernel only mode WDAC policy capable of protecting against BYOVD attacks category
.PARAMETER Base
    The base policy to use for creating the strict Kernel mode WDAC policy, offers 2 options:
    Default: meaning flight root certs will be allowed, suitable for most users.
    NoFlightRoots: is for users who don't want to allow flighting/insider builds from Dev/Canary channels.
    If not specified, Default will be used.
.PARAMETER Mode
    The mode to use for creating the strict Kernel mode WDAC policy, offers 2 options:
    Prep: Deploys the Kernel mode WDAC policy in Audit mode so that you can restart your system and start capturing any blocked drivers to be automatically allowed.
    AuditAndEnforce: Deploys the final Kernel mode WDAC policy in Enforced mode
.PARAMETER EVSigners
    Adds EVSigners policy rule option to the deployed policy. Applicable for both Audit and Enforced modes. Drivers not EV (Extended Validation) signed cannot run nor can they be allowed in a Supplemental policy.
.PARAMETER Deploy
    Deploys the selected policy type instead of just creating it
.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases
.INPUTS
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
.EXAMPLE
    New-KernelModeWDACConfig -Default -PrepMode -Deploy
    This example creates the strict Kernel mode WDAC policy based off of the default Windows WDAC example policy, deploys it in Audit mode. System restart will be required after this.
.EXAMPLE
    New-KernelModeWDACConfig -Default -AuditAndEnforce -Deploy
    This example creates the strict Kernel mode WDAC policy based off of the default Windows WDAC example policy, deploys it in Enforced mode. It will also contain the drivers that were blocked during the Audit mode.
#>
}
