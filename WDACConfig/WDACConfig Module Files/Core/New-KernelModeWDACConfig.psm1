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

    begin {
        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null
        # Detecting if Debug switch is used, will do debugging actions based on that
        $PSBoundParameters.Debug.IsPresent ? ([System.Boolean]$Debug = $true) : ([System.Boolean]$Debug = $false) | Out-Null

        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Update-Self.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Write-ColorfulText.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Move-UserModeToKernelMode.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-KernelModeDriversAudit.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\New-StagingArea.psm1" -Force

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-Self -InvocationStatement $MyInvocation.Statement }

        [System.IO.DirectoryInfo]$StagingArea = New-StagingArea -CmdletName 'New-KernelModeWDACConfig'

        # Create a directory to store the kernel mode drivers symbolic links for both modes
        [System.IO.DirectoryInfo]$KernelModeDriversDirectory = New-Item -ItemType Directory -Path (Join-Path -Path $StagingArea -ChildPath 'KernelModeDriversDirectory') -Force

        # Defining the path to the driver files scan results policy for both modes
        [System.IO.FileInfo]$DriverFilesScanPolicyPath = Join-Path -Path $StagingArea -ChildPath 'DriverFilesScanPolicy.xml'

        # Defining the path to the final Enforced mode policy for both modes
        [System.IO.FileInfo]$FinalEnforcedPolicyPath = Join-Path -Path $StagingArea -ChildPath 'DefaultWindows_Enforced_Kernel.xml'

        # Defining the paths to the kernel-mode template policies for each mode
        [System.IO.FileInfo]$TemplatePolicyPath = $Base -eq 'Default' ? "$ModuleRootPath\Resources\WDAC Policies\DefaultWindows_Enforced_Kernel.xml" : "$ModuleRootPath\Resources\WDAC Policies\DefaultWindows_Enforced_Kernel_NoFlights.xml"

        # A flag that will be set to true if errors occur
        [System.Boolean]$NoCopy = $false

        Function Edit-GUIDs {
            <#
            .SYNOPSIS
                A helper function to swap GUIDs in a WDAC policy XML file
            .INPUTS
                System.String
            .OUTPUTS
                System.Void
            #>
            [CmdletBinding()]
            [OutputType([System.Void])]
            param(
                [System.String]$PolicyIDInput,
                [System.IO.FileInfo]$PolicyFilePathInput
            )

            [System.String]$PolicyID = "{$PolicyIDInput}"

            # Read the xml file as an xml object
            [System.Xml.XmlDocument]$Xml = Get-Content -Path $PolicyFilePathInput

            # Define the new values for PolicyID and BasePolicyID
            [System.String]$newPolicyID = $PolicyID
            [System.String]$newBasePolicyID = $PolicyID

            # Replace the old values with the new ones
            $Xml.SiPolicy.PolicyID = $newPolicyID
            $Xml.SiPolicy.BasePolicyID = $newBasePolicyID

            # Save the modified xml file
            $Xml.Save($PolicyFilePathInput)
        }

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
                    Edit-GUIDs -PolicyIDInput $CurrentStrictKernelPolicyGUIDConfirmation -PolicyFilePathInput $OutputPolicyPath
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
                            ConvertFrom-CIPolicy -XmlFilePath $AuditPolicyPath -BinaryFilePath $FinalAuditCIPPath | Out-Null

                            # Deploy the policy if Deploy parameter is used and perform additional tasks on the system
                            if ($Deploy) {

                                $CurrentStep++
                                Write-Progress -Id 25 -Activity 'Deploying the prep mode policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                                Write-Verbose -Message 'Setting the GUID and time of deployment of the Audit mode policy in the User Configuration file'
                                Set-CommonWDACConfig -StrictKernelPolicyGUID $PolicyID -StrictKernelModePolicyTimeOfDeployment (Get-Date) | Out-Null

                                Write-Verbose -Message 'Deploying the Strict Kernel mode policy'
                                &'C:\Windows\System32\CiTool.exe' --update-policy $FinalAuditCIPPath -json | Out-Null
                                Write-ColorfulText -Color HotPink -InputText 'Strict Kernel mode policy has been deployed in Audit mode, please restart your system.'
                            }
                            else {
                                Write-ColorfulText -Color HotPink -InputText 'Strict Kernel mode Audit policy has been created in the Staging Area.'
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

                            powershell.exe -Command {
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
                            Merge-CIPolicy -PolicyPaths (Join-Path -Path $StagingArea -ChildPath 'Raw_Normal.xml'), $DriverFilesScanPolicyPath -OutputFilePath $FinalEnforcedPolicyPath | Out-Null

                            Write-Verbose -Message 'Moving all AllowedSigners from Usermode to Kernel mode signing scenario'
                            Move-UserModeToKernelMode -FilePath $FinalEnforcedPolicyPath | Out-Null

                            Write-Verbose -Message 'Setting the GUIDs for the XML policy file'
                            Edit-GUIDs -PolicyIDInput $PolicyID -PolicyFilePathInput $FinalEnforcedPolicyPath

                            Write-Verbose -Message 'Setting a new policy name with the current date attached to it'
                            Set-CIPolicyIdInfo -FilePath $FinalEnforcedPolicyPath -PolicyName "Strict Kernel mode policy Enforced - $(Get-Date -Format 'MM-dd-yyyy')"

                            Write-Verbose -Message 'Setting the policy version to 1.0.0.0'
                            Set-CIPolicyVersion -FilePath $FinalEnforcedPolicyPath -Version '1.0.0.0'

                            Set-CiRuleOptions -FilePath $FinalEnforcedPolicyPath -Template BaseKernel -RequireEVSigners:$EVSigners
                           
                            [System.IO.FileInfo]$FinalEnforcedCIPPath = Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip"

                            Write-Verbose -Message 'Converting the policy XML file to CIP binary'
                            ConvertFrom-CIPolicy -XmlFilePath $FinalEnforcedPolicyPath -BinaryFilePath $FinalEnforcedCIPPath | Out-Null

                            # Deploy the policy if Deploy parameter is used
                            if ($Deploy) {

                                $CurrentStep++
                                Write-Progress -Id 26 -Activity 'Deploying the final policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                                Write-Verbose -Message 'Deploying the enforced mode policy with the same ID as the Audit mode policy, effectively overwriting it'
                                &'C:\Windows\System32\CiTool.exe' --update-policy $FinalEnforcedCIPPath -json | Out-Null
                                Write-ColorfulText -Color HotPink -InputText 'Strict Kernel mode policy has been deployed in Enforced mode, no restart required.'

                                Write-Verbose -Message 'Removing the GUID and time of deployment of the StrictKernelPolicy from user configuration'
                                Remove-CommonWDACConfig -StrictKernelPolicyGUID -StrictKernelModePolicyTimeOfDeployment | Out-Null
                            }
                            else {
                                # Remove the Audit mode policy from the system
                                # This step is necessary if user didn't use the -Deploy parameter
                                # And instead wants to first Sign and then deploy it using the Deploy-SignedWDACConfig cmdlet
                                Write-Verbose -Message 'Removing the deployed Audit mode policy from the system since -Deploy parameter was not used to overwrite it with the enforced mode policy.'
                                &'C:\Windows\System32\CiTool.exe' --remove-policy "{$PolicyID}" -json | Out-Null
                                Write-ColorfulText -Color HotPink -InputText "Strict Kernel mode Enforced policy has been created`n$FinalEnforcedPolicyPath"
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
                            ConvertFrom-CIPolicy -XmlFilePath $AuditPolicyPath -BinaryFilePath $FinalAuditCIPPath | Out-Null

                            # Deploy the policy if Deploy parameter is used and perform additional tasks on the system
                            if ($Deploy) {

                                $CurrentStep++
                                Write-Progress -Id 27 -Activity 'Deploying the prep mode policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                                Write-Verbose -Message 'Setting the GUID and time of deployment of the Audit mode policy in the User Configuration file'
                                Set-CommonWDACConfig -StrictKernelNoFlightRootsPolicyGUID $PolicyID -StrictKernelModePolicyTimeOfDeployment (Get-Date) | Out-Null

                                Write-Verbose -Message 'Deploying the Strict Kernel mode policy'
                                &'C:\Windows\System32\CiTool.exe' --update-policy $FinalAuditCIPPath -json | Out-Null
                                Write-ColorfulText -Color HotPink -InputText 'Strict Kernel mode policy with no flighting root certs has been deployed in Audit mode, please restart your system.'
                            }
                            else {
                                Write-ColorfulText -Color HotPink -InputText 'Strict Kernel mode Audit policy with no flighting root certs has been created in the Staging Area.'
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

                            powershell.exe -Command {
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
                            Merge-CIPolicy -PolicyPaths (Join-Path -Path $StagingArea -ChildPath 'Raw_NoFlights.xml'), $DriverFilesScanPolicyPath -OutputFilePath $FinalEnforcedPolicyPath | Out-Null

                            Write-Verbose -Message 'Moving all AllowedSigners from Usermode to Kernel mode signing scenario'
                            Move-UserModeToKernelMode -FilePath $FinalEnforcedPolicyPath | Out-Null

                            Write-Verbose -Message 'Setting the GUIDs for the XML policy file'
                            Edit-GUIDs -PolicyIDInput $PolicyID -PolicyFilePathInput $FinalEnforcedPolicyPath

                            Write-Verbose -Message 'Setting a new policy name with the current date attached to it'
                            Set-CIPolicyIdInfo -FilePath $FinalEnforcedPolicyPath -PolicyName "Strict Kernel No Flights mode policy Enforced - $(Get-Date -Format 'MM-dd-yyyy')"

                            Write-Verbose -Message 'Setting the policy version to 1.0.0.0'
                            Set-CIPolicyVersion -FilePath $FinalEnforcedPolicyPath -Version '1.0.0.0'

                            Set-CiRuleOptions -FilePath $FinalEnforcedPolicyPath -Template BaseKernel -RulesToAdd 'Disabled:Flight Signing' -RequireEVSigners:$EVSigners

                            [System.IO.FileInfo]$FinalEnforcedCIPPath = Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip"

                            Write-Verbose -Message 'Converting the policy XML file to CIP binary'
                            ConvertFrom-CIPolicy -XmlFilePath $FinalEnforcedPolicyPath -BinaryFilePath $FinalEnforcedCIPPath | Out-Null

                            # Deploy the policy if Deploy parameter is used
                            if ($Deploy) {

                                $CurrentStep++
                                Write-Progress -Id 28 -Activity 'Deploying the final policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                                Write-Verbose -Message 'Deploying the enforced mode policy with the same ID as the Audit mode policy, effectively overwriting it'
                                &'C:\Windows\System32\CiTool.exe' --update-policy $FinalEnforcedCIPPath -json | Out-Null
                                Write-ColorfulText -Color HotPink -InputText 'Strict Kernel mode policy with no flighting root certs has been deployed in Enforced mode, no restart required.'

                                Write-Verbose -Message 'Removing the GUID and time of deployment of the StrictKernelNoFlightRootsPolicy from user configuration'
                                Remove-CommonWDACConfig -StrictKernelNoFlightRootsPolicyGUID -StrictKernelModePolicyTimeOfDeployment | Out-Null
                            }
                            else {
                                # Remove the Audit mode policy from the system
                                # This step is necessary if user didn't use the -Deploy parameter
                                # And instead wants to first Sign and then deploy it using the Deploy-SignedWDACConfig cmdlet
                                Write-Verbose -Message 'Removing the deployed Audit mode policy from the system since -Deploy parameter was not used to overwrite it with the enforced mode policy.'
                                &'C:\Windows\System32\CiTool.exe' --remove-policy "{$PolicyID}" -json | Out-Null
                                Write-ColorfulText -Color HotPink -InputText "Strict Kernel mode Enforced policy with no flighting root certs has been created`n$FinalEnforcedPolicyPath"
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
                Copy-Item -Path ($Mode -eq 'Prep' ? ($Deploy ? $AuditPolicyPath : $AuditPolicyPath, $FinalAuditCIPPath) : ($Deploy ? $FinalEnforcedPolicyPath : $FinalEnforcedPolicyPath, $FinalEnforcedCIPPath)) -Destination $UserConfigDir -Force
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

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDbLF95DL242YJt
# oxdNmHybKhPlvew4nFSowMAAe3ONyaCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgGNG/dSqO0Ba4enwsjwu87JbS9vUIjorQ4SAWcZUm3B4wDQYJKoZIhvcNAQEB
# BQAEggIAFbWnHZLKAFctOov91GAiuTDO81yT+NQNk4fCaZxtl2acltBvkesWICHP
# Yu88n2mNxhrukGnVPvnsyJ8H0M6iefE41PikCZ8qOmML2svzqtyEBGLVxyPeP2Vg
# AgucS2rolqWC9LBnt9v0hjCT+V+70Dit55g4VI9J0kbkfrBEAodv1cDPejbaM0y+
# p+LIST0fFvqUZ3I5uXb5TF28Dgibv5lbYHWFqnRpu4dxtUp5YQvbfWOL0OcHdmwi
# F6QbL3Oy5BqJiA554OhjCKXlWasMd5+0T0KaRED5iwUC7cohmSFmPlDGotArDDr8
# 3g/P8Z/eAjTJK05jeYuHgGbVWDcEGfGzKeUCMJbWT4hL7GaOsQQjGYR/aCz3dDSM
# JzcmaQNOHGxzdFzHIEH/hRt8vssLnGpY6imVuBOSiheQRwl4QPSyw8cUgY4NmwGy
# K+GFWtW1Ri8TJ+WrUFk7yhEDVnGkyihjDbN6E/Q6/xGb9dZp6REwJ2hcWkR6+w9h
# EwcBwUH1mdT/CN8q8QgPAxARnB/GIQ6tDrpERwYJLAyCGsDFfSaV2og9/l8OZLUi
# BLl3kiYpBC1O/HcbUEFlJcJtZDh688xRRw3/M+UpAz1wKIBsQ1vXKmgKnsyTKFPC
# zbgWBENlHXc8le7E4Ap4HzXayINe4DGlKqCHCT0AKszbOkH8pFs=
# SIG # End signature block
