function New-KernelModeWDACConfig {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    Param(
        [Parameter(Mandatory = $false, ParameterSetName = 'Default Strict Kernel')][System.Management.Automation.SwitchParameter]$Default,
        [Parameter(Mandatory = $false, ParameterSetName = 'No Flight Roots')][System.Management.Automation.SwitchParameter]$NoFlightRoots,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default Strict Kernel')]
        [Parameter(Mandatory = $false, ParameterSetName = 'No Flight Roots')]
        [System.Management.Automation.SwitchParameter]$PrepMode,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default Strict Kernel')]
        [Parameter(Mandatory = $false, ParameterSetName = 'No Flight Roots')]
        [System.Management.Automation.SwitchParameter]$AuditAndEnforce,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default Strict Kernel')]
        [Parameter(Mandatory = $false, ParameterSetName = 'No Flight Roots')]
        [System.Management.Automation.SwitchParameter]$Deploy,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default Strict Kernel')]
        [Parameter(Mandatory = $false, ParameterSetName = 'No Flight Roots')]
        [System.Management.Automation.SwitchParameter]$EVSigners,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )

    begin {
        # Importing resources such as functions by dot-sourcing so that they will run in the same scope and their variables will be usable
        . "$psscriptroot\Resources.ps1"

        # Stop operation as soon as there is an error anywhere, unless explicitly specified otherwise
        $ErrorActionPreference = 'Stop'

        # Detecting if Debug switch is used, will do debugging actions based on that
        $Debug = $PSBoundParameters.Debug.IsPresent

        if (-NOT $SkipVersionCheck) { . Update-self }

        # Check if the PrepMode and AuditAndEnforce parameters are used together and ensure one of them is used
        if (-not ($PSBoundParameters.ContainsKey('PrepMode') -xor $PSBoundParameters.ContainsKey('AuditAndEnforce'))) {
            # Write an error message
            Write-Error -Message 'You must specify either -PrepMode or -AuditAndEnforce, but not both.' -Category InvalidArgument
        }

        # Function to swap GUIDs in a WDAC policy XML file
        function Edit-GUIDs {
            param(
                [System.String]$PolicyIDInput,
                [System.String]$PolicyFilePathInput
            )

            [System.String]$PolicyID = "{$PolicyIDInput}"

            # Read the xml file as an xml object
            [System.Xml.XmlDocument]$xml = Get-Content -Path $PolicyFilePathInput

            # Define the new values for PolicyID and BasePolicyID
            [System.String]$newPolicyID = $PolicyID
            [System.String]$newBasePolicyID = $PolicyID

            # Replace the old values with the new ones
            $xml.SiPolicy.PolicyID = $newPolicyID
            $xml.SiPolicy.BasePolicyID = $newBasePolicyID

            # Save the modified xml file
            $xml.Save($PolicyFilePathInput)
        }

        # Function to build Audit mode policy only
        function Build-PrepModeStrictKernelPolicy {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$DefaultWindowsKernel,
                [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$DefaultWindowsKernelNoFlights
            )

            begin {

                if ($DefaultWindowsKernel) {
                    $PolicyPath = "$psscriptroot\WDAC Policies\DefaultWindows_Enforced_Kernel.xml"
                    $PolicyFileName = '.\DefaultWindows_Enforced_Kernel.xml'
                    $PolicyName = 'Strict Kernel mode policy Audit'

                    # Check if there is a pending Audit mode Kernel mode WDAC policy already available in User Config file
                    [System.String]$CurrentStrictKernelPolicyGUID = Get-CommonWDACConfig -StrictKernelPolicyGUID

                    If ($CurrentStrictKernelPolicyGUID) {
                        # Check if the pending Audit mode Kernel mode WDAC policy is deployed on the system
                        [System.String]$CurrentStrictKernelPolicyGUIDConfirmation = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.PolicyID -eq $CurrentStrictKernelPolicyGUID }).policyID
                    }
                }

                if ($DefaultWindowsKernelNoFlights) {
                    $PolicyPath = "$psscriptroot\WDAC Policies\DefaultWindows_Enforced_Kernel_NoFlights.xml"
                    $PolicyFileName = '.\DefaultWindows_Enforced_Kernel_NoFlights.xml'
                    $PolicyName = 'Strict Kernel No Flights mode policy Audit'

                    # Check if there is a pending Audit mode Kernel mode WDAC No Flight Roots policy already available in User Config file
                    [System.String]$CurrentStrictKernelNoFlightRootsPolicyGUID = Get-CommonWDACConfig -StrictKernelNoFlightRootsPolicyGUID

                    If ($CurrentStrictKernelNoFlightRootsPolicyGUID) {
                        # Check if the pending Audit mode Kernel mode WDAC No Flight Roots policy is deployed on the system
                        [System.String]$CurrentStrictKernelPolicyGUIDConfirmation = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.PolicyID -eq $CurrentStrictKernelNoFlightRootsPolicyGUID }).policyID
                    }
                }

            }

            process {
                Copy-Item -Path $PolicyPath -Destination "$PolicyFileName" -Force
                # Setting them to global so they can be accessed outside of this function's scope too
                $Global:PolicyID = Set-CIPolicyIdInfo -FilePath "$PolicyFileName" -PolicyName "$PolicyName" -ResetPolicyID
                $Global:PolicyID = $PolicyID.Substring(11)
                Set-CIPolicyVersion -FilePath "$PolicyFileName" -Version '1.0.0.0'
                # Setting policy rule options for the audit mode policy
                @(2, 3, 6, 16, 17, 20) | ForEach-Object -Process { Set-RuleOption -FilePath "$PolicyFileName" -Option $_ }
                @(0, 4, 8, 9, 10, 11, 12, 13, 14, 15, 18, 19) | ForEach-Object -Process { Set-RuleOption -FilePath "$PolicyFileName" -Option $_ -Delete }
                # If user chooses to add EVSigners, add it to the policy
                if ($EVSigners) { Set-RuleOption -FilePath "$PolicyFileName" -Option 8 }
                # If user chooses to go with no flight root certs then block flight/insider builds in policy rule options
                if ($DefaultWindowsKernelNoFlights) { Set-RuleOption -FilePath "$PolicyFileName" -Option 4 }

                # Set the already available and deployed GUID as the new PolicyID to prevent deploying duplicate Audit mode policies
                if ($CurrentStrictKernelPolicyGUIDConfirmation) {
                    Edit-GUIDs -PolicyIDInput $CurrentStrictKernelPolicyGUIDConfirmation -PolicyFilePathInput "$PolicyFileName"
                    $Global:PolicyID = $CurrentStrictKernelPolicyGUIDConfirmation
                }

                Set-HVCIOptions -Strict -FilePath "$PolicyFileName"
            }
        }
    }

    process {

        if ($PSCmdlet.ParameterSetName -eq 'Default Strict Kernel' -and $PSBoundParameters.ContainsKey('Default')) {

            if ($PrepMode) {
                # Build the Audit mode policy
                Build-PrepModeStrictKernelPolicy -DefaultWindowsKernel
                # Convert the xml to CIP binary
                ConvertFrom-CIPolicy -XmlFilePath .\DefaultWindows_Enforced_Kernel.xml -BinaryFilePath "$PolicyID.cip" | Out-Null

                # Deploy the policy if Deploy parameter is used and perform additional tasks on the system
                if ($Deploy) {

                    # Set the GUID of the Audit mode policy in the User Configuration file
                    Set-CommonWDACConfig -StrictKernelPolicyGUID $PolicyID | Out-Null
                    CiTool.exe --update-policy "$PolicyID.cip" -json | Out-Null
                    &$WriteHotPink 'Strict Kernel mode policy has been deployed in Audit mode, please restart your system.'

                    # Clear Code Integrity operational before system restart so that after boot it will only have the correct and new logs
                    wevtutil cl 'Microsoft-Windows-CodeIntegrity/Operational'
                    wevtutil cl 'Microsoft-Windows-AppLocker/MSI and Script'

                    if (!$Debug) {
                        Remove-Item -Path '.\DefaultWindows_Enforced_Kernel.xml', ".\$PolicyID.cip" -Force -ErrorAction SilentlyContinue
                    }
                }
                else {
                    &$WriteHotPink 'Strict Kernel mode Audit policy has been created in the current working directory.'
                }
            }

            if ($AuditAndEnforce) {

                # Get the Strict Kernel Audit mode policy's GUID to use for the Enforced mode policy
                # This will eliminate the need for an extra reboot
                [System.String]$PolicyID = Get-CommonWDACConfig -StrictKernelPolicyGUID
                # Verify the Policy ID in the User Config exists and is valid
                $ObjectGuid = [System.Guid]::Empty
                if ([System.Guid]::TryParse($PolicyID, [ref]$ObjectGuid)) {
                    Write-Debug 'Valid GUID found in User Configs for Audit mode policy'
                }
                else {
                    Write-Error 'Invalid or nonexistent GUID in User Configs for Audit mode policy, Use the -PrepMode parameter first.'
                }

                powershell.exe {
                    # Scan Event viewer logs for drivers
                    $DriverFilesObj = Get-SystemDriver -Audit
                    # Create a policy xml file from the driver files
                    New-CIPolicy -MultiplePolicyFormat -Level FilePublisher -Fallback None -FilePath '.\DriverFilesScanPolicy.xml' -DriverFiles $DriverFilesObj
                }

                # Build the same policy again after restart, do not trust the policy xml file made before restart
                Copy-Item -Path "$psscriptroot\WDAC Policies\DefaultWindows_Enforced_Kernel.xml" -Destination .\DefaultWindows_Enforced_Kernel.xml -Force

                # Merge the base policy with the policy made from driver files to deploy it as one
                Merge-CIPolicy -PolicyPaths '.\DefaultWindows_Enforced_Kernel.xml', '.\DriverFilesScanPolicy.xml' -OutputFilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' | Out-Null

                # Remove the old policy again because we used it in merge and don't need it anymore
                Remove-Item -Path '.\DefaultWindows_Enforced_Kernel.xml' -Force

                # Move all AllowedSigners from Usermode to Kernel mode signing scenario
                Move-UserModeToKernelMode -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' | Out-Null

                # Set the GUIDs for the XML policy file
                Edit-GUIDs -PolicyIDInput $PolicyID -PolicyFilePathInput '.\Final_DefaultWindows_Enforced_Kernel.xml'

                Set-CIPolicyIdInfo -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' -PolicyName "Strict Kernel mode policy Enforced - $(Get-Date -Format 'MM-dd-yyyy')"

                Set-CIPolicyVersion -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' -Version '1.0.0.0'
                # Setting policy rule options for the final Enforced mode policy
                @(2, 6, 16, 17, 20) | ForEach-Object -Process { Set-RuleOption -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' -Option $_ }
                @(0, 3, 4, 8, 9, 10, 11, 12, 13, 14, 15, 18, 19) | ForEach-Object -Process { Set-RuleOption -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' -Option $_ -Delete }

                if ($EVSigners) { Set-RuleOption -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' -Option 8 }

                Set-HVCIOptions -Strict -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml'

                # Deploy the policy if Deploy parameter is used
                if ($Deploy) {
                    ConvertFrom-CIPolicy -XmlFilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' -BinaryFilePath "$PolicyID.cip" | Out-Null
                    CiTool.exe --update-policy "$PolicyID.cip" -json | Out-Null
                    &$WritePink 'Strict Kernel mode policy has been deployed in Enforced mode, no restart required.'

                    # Delete its GUID from User Configurations
                    Remove-CommonWDACConfig -StrictKernelPolicyGUID | Out-Null
                }
                else {
                    # Remove the Audit mode policy from the system
                    # This step is necessary if user didn't use the -Deploy parameter
                    # And instead wants to first Sign and then deploy it using the Deploy-SignedWDACConfig cmdlet
                    CiTool.exe --remove-policy "{$PolicyID}" -json | Out-Null
                    &$WritePink 'Strict Kernel mode Enforced policy has been created in the current working directory.'
                }
                if (!$Debug) {
                    Remove-Item -Path ".\$PolicyID.cip", '.\DriverFilesScanPolicy.xml' -Force -ErrorAction SilentlyContinue
                }
            }
        }

        # For Strict Kernel mode WDAC policy without allowing Flight root certs (i.e. not allowing insider builds)
        if ($PSCmdlet.ParameterSetName -eq 'No Flight Roots' -and $PSBoundParameters.ContainsKey('NoFlightRoots')) {

            if ($PrepMode) {
                # Creating the audit mode policy
                Build-PrepModeStrictKernelPolicy -DefaultWindowsKernelNoFlights
                # Convert the xml to CIP binary
                ConvertFrom-CIPolicy -XmlFilePath .\DefaultWindows_Enforced_Kernel_NoFlights.xml -BinaryFilePath "$PolicyID.cip" | Out-Null

                # Deploy the policy if Deploy parameter is used and perform additional tasks on the system
                if ($Deploy) {
                    # Set the GUID of the Audit mode policy in the User Configuration file
                    Set-CommonWDACConfig -StrictKernelNoFlightRootsPolicyGUID $PolicyID | Out-Null
                    CiTool.exe --update-policy "$PolicyID.cip" -json | Out-Null
                    &$WriteHotPink 'Strict Kernel mode policy with no flighting root certs has been deployed in Audit mode, please restart your system.'

                    # Clear Code Integrity operational before system restart so that after boot it will only have the correct and new logs
                    wevtutil cl 'Microsoft-Windows-CodeIntegrity/Operational'
                    wevtutil cl 'Microsoft-Windows-AppLocker/MSI and Script'

                    if (!$Debug) {
                        Remove-Item -Path '.\DefaultWindows_Enforced_Kernel_NoFlights.xml', ".\$PolicyID.cip" -Force -ErrorAction SilentlyContinue
                    }
                }
                else {
                    &$WriteHotPink 'Strict Kernel mode Audit policy with no flighting root certs has been created in the current working directory.'
                }
            }

            if ($AuditAndEnforce) {

                # Get the Strict Kernel Audit mode policy's GUID to use for the Enforced mode policy
                # This will eliminate the need for an extra reboot
                [System.String]$PolicyID = Get-CommonWDACConfig -StrictKernelNoFlightRootsPolicyGUID
                # Verify the Policy ID in the User Config exists and is valid
                $ObjectGuid = [System.Guid]::Empty
                if ([System.Guid]::TryParse($PolicyID, [ref]$ObjectGuid)) {
                    Write-Debug 'Valid GUID found in User Configs for Audit mode policy'
                }
                else {
                    Write-Error 'Invalid or nonexistent GUID in User Configs for Audit mode policy, Use the -PrepMode parameter first.'
                }

                powershell.exe {
                    # Scan Event viewer logs for drivers
                    $DriverFilesObj = Get-SystemDriver -Audit
                    # Create a policy xml file from the driver files
                    New-CIPolicy -MultiplePolicyFormat -Level FilePublisher -Fallback None -FilePath '.\DriverFilesScanPolicy.xml' -DriverFiles $DriverFilesObj
                }

                # Build the same policy again after restart, do not trust the policy xml file made before restart
                Copy-Item -Path "$psscriptroot\WDAC Policies\DefaultWindows_Enforced_Kernel_NoFlights.xml" -Destination '.\DefaultWindows_Enforced_Kernel_NoFlights.xml' -Force

                # Merge the base policy with the policy made from driver files to deploy it as one
                Merge-CIPolicy -PolicyPaths '.\DefaultWindows_Enforced_Kernel_NoFlights.xml', '.\DriverFilesScanPolicy.xml' -OutputFilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' | Out-Null

                # Remove the old policy again because we used it in merge and don't need it anymore
                Remove-Item -Path '.\DefaultWindows_Enforced_Kernel_NoFlights.xml' -Force

                # Move all AllowedSigners from Usermode to Kernel mode signing scenario
                Move-UserModeToKernelMode -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' | Out-Null

                # Set the GUIDs for the XML policy file
                Edit-GUIDs -PolicyIDInput $PolicyID -PolicyFilePathInput '.\Final_DefaultWindows_Enforced_Kernel.xml'

                Set-CIPolicyIdInfo -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' -PolicyName "Strict Kernel No Flights mode policy Enforced - $(Get-Date -Format 'MM-dd-yyyy')"

                Set-CIPolicyVersion -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' -Version '1.0.0.0'
                # Setting policy rule options for the final Enforced mode policy
                @(2, 4, 6, 16, 17, 20) | ForEach-Object -Process { Set-RuleOption -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' -Option $_ }
                @(0, 3, 8, 9, 10, 11, 12, 13, 14, 15, 18, 19) | ForEach-Object -Process { Set-RuleOption -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' -Option $_ -Delete }

                if ($EVSigners) { Set-RuleOption -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' -Option 8 }

                Set-HVCIOptions -Strict -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml'

                # Deploy the policy if Deploy parameter is used
                if ($Deploy) {
                    ConvertFrom-CIPolicy -XmlFilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' -BinaryFilePath "$PolicyID.cip" | Out-Null
                    CiTool.exe --update-policy "$PolicyID.cip" -json | Out-Null
                    &$WritePink 'Strict Kernel mode policy with no flighting root certs has been deployed in Enforced mode, no restart required.'

                    # Delete its GUID from User Configurations
                    Remove-CommonWDACConfig -StrictKernelNoFlightRootsPolicyGUID | Out-Null
                }
                else {
                    # Remove the Audit mode policy from the system
                    # This step is necessary if user didn't use the -Deploy parameter
                    # And instead wants to first Sign and then deploy it using the Deploy-SignedWDACConfig cmdlet
                    CiTool.exe --remove-policy "{$PolicyID}" -json | Out-Null
                    &$WritePink 'Strict Kernel mode Enforced policy with no flighting root certs has been created in the current working directory.'
                }
                if (!$Debug) {
                    Remove-Item -Path ".\$PolicyID.cip", '.\DriverFilesScanPolicy.xml' -Force -ErrorAction SilentlyContinue
                }
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

.PARAMETER Default
Creates the strict Kernel mode WDAC policy based off of the default Windows WDAC example policy.

.PARAMETER NoFlightRoots
Creates the strict Kernel mode WDAC policy based off of the default Windows WDAC example policy, doesn't allow flighting/insider builds.

.PARAMETER PrepMode
Deploys the Kernel mode WDAC policy in Audit mode so that you can restart your system and start capturing any blocked drivers to be automatically allowed.

.PARAMETER AuditAndEnforce
Deploys the final Kernel mode WDAC policy in Enforced mode

.PARAMETER EVSigners
Adds EVSigners policy rule option to the deployed policy. Applicable for both Audit and Enforced modes. Drivers not EV (Extended Validation) signed cannot run nor can they be allowed in a Supplemental policy.

.PARAMETER Deploy
Deploys the selected policy type instead of just creating it

.PARAMETER SkipVersionCheck
Can be used with any parameter to bypass the online version check - only to be used in rare cases

#>
}
# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
