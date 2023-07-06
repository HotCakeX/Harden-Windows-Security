#Requires -RunAsAdministrator
function New-KernelModeWDACConfig {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    Param(       
        [Parameter(Mandatory = $false, ParameterSetName = "Default Strict Kernel")][switch]$Default,
        [Parameter(Mandatory = $false, ParameterSetName = "No Flight Roots")][switch]$NoFlightRoots,

        [Parameter(Mandatory = $false, ParameterSetName = "Default Strict Kernel")]
        [Parameter(Mandatory = $false, ParameterSetName = "No Flight Roots")]
        [switch]$PrepMode,

        [Parameter(Mandatory = $false, ParameterSetName = "Default Strict Kernel")]
        [Parameter(Mandatory = $false, ParameterSetName = "No Flight Roots")]
        [switch]$AuditAndEnforce,

        [Parameter(Mandatory = $false, ParameterSetName = "Default Strict Kernel")]
        [Parameter(Mandatory = $false, ParameterSetName = "No Flight Roots")]
        [switch]$EVSigners,
        
        [Parameter(Mandatory = $false)][Switch]$SkipVersionCheck    
    )

    begin {
        # Importing resources such as functions by dot-sourcing so that they will run in the same scope and their variables will be usable
        . "$psscriptroot\Resources.ps1"

        # Stop operation as soon as there is an error anywhere, unless explicitly specified otherwise
        $ErrorActionPreference = 'Stop'

        # Detecting if Debug switch is used, will do debugging actions based on that
        $Debug = $PSBoundParameters.Debug.IsPresent 

        if (-NOT $SkipVersionCheck) { . Update-self }
    
        # Check if the Default parameter was used from the Default Strict Kernel parameter set
        if ($PSCmdlet.ParameterSetName -eq "Default Strict Kernel" -and $PSBoundParameters.ContainsKey("Default")) {
            # Check if either the PrepMode or the AuditAndEnforce parameters were used as well
            if (-not ($PSBoundParameters.ContainsKey("PrepMode") -or $PSBoundParameters.ContainsKey("AuditAndEnforce"))) {
                # Write an error message
                Write-Error -Message "You must specify either -PrepMode or -AuditAndEnforce when using -Default from the Default Strict Kernel parameter set." -Category InvalidArgument -TargetObject $Default
            }
        }

        # Check if the NoFlightRoots parameter was used from the No Flight Roots parameter set
        if ($PSCmdlet.ParameterSetName -eq "No Flight Roots" -and $PSBoundParameters.ContainsKey("NoFlightRoots")) {
            # Check if either the PrepMode or the AuditAndEnforce parameters were used as well
            if (-not ($PSBoundParameters.ContainsKey("PrepMode") -or $PSBoundParameters.ContainsKey("AuditAndEnforce"))) {
                # Write an error message
                Write-Error -Message "You must specify either -PrepMode or -AuditAndEnforce when using -NoFlightRoots from the No Flight Roots parameter set." -Category InvalidArgument -TargetObject $NoFlightRoots
            }
        }

        # Function to build Audit mode policy only
        function Build-PrepModeStrictKernelPolicy {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $false)][switch]$DefaultWindowsKernel,
                [Parameter(Mandatory = $false)][switch]$DefaultWindowsKernelNoFlights
            )
            if ($DefaultWindowsKernel) {
                $PolicyPath = "$psscriptroot\WDAC Policies\DefaultWindows_Enforced_Kernel.xml"
                $PolicyFileName = ".\DefaultWindows_Enforced_Kernel.xml"
                $PolicyName = "Strict Kernel mode policy Audit"
            }
            if ($DefaultWindowsKernelNoFlights) { 
                $PolicyPath = "$psscriptroot\WDAC Policies\DefaultWindows_Enforced_Kernel_NoFlights.xml"
                $PolicyFileName = ".\DefaultWindows_Enforced_Kernel_NoFlights.xml"
                $PolicyName = "Strict Kernel No Flights mode policy Audit"
            }

            Copy-Item -Path $PolicyPath -Destination "$PolicyFileName" -Force
            # Setting them to global so they can be accessed outside of this function's scope too
            $Global:PolicyID = Set-CIPolicyIdInfo -FilePath "$PolicyFileName" -PolicyName "$PolicyName" -ResetPolicyID
            $Global:PolicyID = $PolicyID.Substring(11)
            Set-CIPolicyVersion -FilePath "$PolicyFileName" -Version "1.0.0.0"
            # Setting policy rule options for the audit mode policy
            @(2, 3, 6, 16, 17, 20) | ForEach-Object { Set-RuleOption -FilePath "$PolicyFileName" -Option $_ }
            @(0, 4, 8, 9, 10, 11, 12, 13, 14, 15, 18, 19) | ForEach-Object { Set-RuleOption -FilePath "$PolicyFileName" -Option $_ -Delete }
            # If user chooses to add EVSigners, add it to the policy
            if ($EVSigners) { Set-RuleOption -FilePath "$PolicyFileName" -Option 8 }
            # If user chooses to go with no flight root certs then block flight/insider builds in policy rule options
            if ($DefaultWindowsKernelNoFlights) { Set-RuleOption -FilePath "$PolicyFileName" -Option 4 }        
            Set-HVCIOptions -Strict -FilePath "$PolicyFileName"           
        }
    }

    process {

        if ($PSCmdlet.ParameterSetName -eq "Default Strict Kernel" -and $PSBoundParameters.ContainsKey("Default")) {

            if ($PrepMode) {
                Build-PrepModeStrictKernelPolicy -DefaultWindowsKernel  
                ConvertFrom-CIPolicy .\DefaultWindows_Enforced_Kernel.xml "$PolicyID.cip" | Out-Null
                CiTool.exe --update-policy "$PolicyID.cip" -json | Out-Null

                # Clear Code Integrity operational before system restart so that after boot it will only have the correct and new logs
                wevtutil cl 'Microsoft-Windows-CodeIntegrity/Operational'
                wevtutil cl 'Microsoft-Windows-AppLocker/MSI and Script'

                &$WriteViolet "Strict Kernel mode policy has been deployed in Audit mode, please restart your system."

                if (!$Debug) {
                    Remove-Item -Path .\DefaultWindows_Enforced_Kernel.xml, ".\$PolicyID.cip" -Force
                }                
            }

            if ($AuditAndEnforce) {
              
                powershell.exe {
                    # Scan Event viewer logs for drivers
                    $DriverFilesObj = Get-SystemDriver -Audit
                    # Create a policy xml file from the driver files
                    New-CIPolicy -MultiplePolicyFormat -Level FilePublisher -Fallback None -FilePath '.\DriverFilesScanPolicy.xml' -DriverFiles $DriverFilesObj        
                } 

                # Remove the Prep mode policy
                $IDToRemove = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.FriendlyName -eq "Strict Kernel mode policy Audit" }).PolicyID
                CiTool --remove-policy "{$IDToRemove}" -json | Out-Null       

                # Build the same policy again after restart, do not trust the policy xml file made before restart                 
                Copy-Item -Path "$psscriptroot\WDAC Policies\DefaultWindows_Enforced_Kernel.xml" -Destination .\DefaultWindows_Enforced_Kernel.xml -Force
              
                # Merge the base policy with the policy made from driver files to deploy it as one
                Merge-CIPolicy -PolicyPaths '.\DefaultWindows_Enforced_Kernel.xml', '.\DriverFilesScanPolicy.xml' -OutputFilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' | Out-Null
                
                # Remove the old policy again because we used it in merge and don't need it anymore
                Remove-Item -Path '.\DefaultWindows_Enforced_Kernel.xml' -Force

                # Move all AllowedSigners from Usermode to Kernel mode signing scenario
                Move-UserModeToKernelMode -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml'

                $PolicyID = Set-CIPolicyIdInfo -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' -PolicyName "Strict Kernel mode policy Enforced - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID
                $PolicyID = $PolicyID.Substring(11)
                Set-CIPolicyVersion -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' -Version "1.0.0.0"
                # Setting policy rule options for the final Enforced mode policy
                @(2, 6, 16, 17, 20) | ForEach-Object { Set-RuleOption -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' -Option $_ }
                @(0, 3, 4, 8, 9, 10, 11, 12, 13, 14, 15, 18, 19) | ForEach-Object { Set-RuleOption -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' -Option $_ -Delete }

                if ($EVSigners) { Set-RuleOption -FilePath '.\DefaultWindows_Enforced_Kernel.xml' -Option 8 }
                
                Set-HVCIOptions -Strict -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml'
          
                ConvertFrom-CIPolicy '.\Final_DefaultWindows_Enforced_Kernel.xml' "$PolicyID.cip" | Out-Null
                CiTool.exe --update-policy "$PolicyID.cip" -json | Out-Null

                &$WritePink "Strict Kernel mode policy has been deployed in Enforced mode, please restart your system."

                if (!$Debug) {
                    Remove-Item -Path '.\Final_DefaultWindows_Enforced_Kernel.xml', ".\$PolicyID.cip" -Force
                } 
            }
        }
    
        # For Strict Kernel mode WDAC policy without allowing Flight root certs (i.e. not allowing insider builds)
        if ($PSCmdlet.ParameterSetName -eq "No Flight Roots" -and $PSBoundParameters.ContainsKey("NoFlightRoots")) {

            if ($PrepMode) {
                Build-PrepModeStrictKernelPolicy -DefaultWindowsKernelNoFlights
                ConvertFrom-CIPolicy .\DefaultWindows_Enforced_Kernel_NoFlights.xml "$PolicyID.cip" | Out-Null
                CiTool.exe --update-policy "$PolicyID.cip" -json | Out-Null

                # Clear Code Integrity operational before system restart so that after boot it will only have the correct and new logs
                wevtutil cl 'Microsoft-Windows-CodeIntegrity/Operational'
                wevtutil cl 'Microsoft-Windows-AppLocker/MSI and Script'

                &$WriteViolet "Strict Kernel mode policy with no flighting root certs has been deployed in Audit mode, please restart your system."

                if (!$Debug) {
                    Remove-Item -Path .\DefaultWindows_Enforced_Kernel_NoFlights.xml, ".\$PolicyID.cip" -Force
                }                
            }

            if ($AuditAndEnforce) {                       

                powershell.exe {
                    # Scan Event viewer logs for drivers
                    $DriverFilesObj = Get-SystemDriver -Audit
                    # Create a policy xml file from the driver files
                    New-CIPolicy -MultiplePolicyFormat -Level FilePublisher -Fallback None -FilePath '.\DriverFilesScanPolicy.xml' -DriverFiles $DriverFilesObj        
                } 

                # Remove the Prep mode policy
                $IDToRemove = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.FriendlyName -eq "Strict Kernel No Flights mode policy Audit" }).PolicyID
                CiTool --remove-policy "{$IDToRemove}" -json | Out-Null       

                # Build the same policy again after restart, do not trust the policy xml file made before restart                 
                Copy-Item -Path "$psscriptroot\WDAC Policies\DefaultWindows_Enforced_Kernel_NoFlights.xml" -Destination ".\DefaultWindows_Enforced_Kernel_NoFlights.xml" -Force
              
                # Merge the base policy with the policy made from driver files to deploy it as one
                Merge-CIPolicy -PolicyPaths ".\DefaultWindows_Enforced_Kernel_NoFlights.xml", '.\DriverFilesScanPolicy.xml' -OutputFilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' | Out-Null
                
                # Remove the old policy again because we used it in merge and don't need it anymore
                Remove-Item -Path ".\DefaultWindows_Enforced_Kernel_NoFlights.xml" -Force

                # Move all AllowedSigners from Usermode to Kernel mode signing scenario
                Move-UserModeToKernelMode -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml'

                $PolicyID = Set-CIPolicyIdInfo -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' -PolicyName "Strict Kernel No Flights mode policy Enforced - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID
                $PolicyID = $PolicyID.Substring(11)
                Set-CIPolicyVersion -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' -Version "1.0.0.0"
                # Setting policy rule options for the final Enforced mode policy
                @(2, 4, 6, 16, 17, 20) | ForEach-Object { Set-RuleOption -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' -Option $_ }
                @(0, 3, 8, 9, 10, 11, 12, 13, 14, 15, 18, 19) | ForEach-Object { Set-RuleOption -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml' -Option $_ -Delete }

                if ($EVSigners) { Set-RuleOption -FilePath '.\DefaultWindows_Enforced_Kernel.xml' -Option 8 }
                
                Set-HVCIOptions -Strict -FilePath '.\Final_DefaultWindows_Enforced_Kernel.xml'
          
                ConvertFrom-CIPolicy '.\Final_DefaultWindows_Enforced_Kernel.xml' "$PolicyID.cip" | Out-Null
                CiTool.exe --update-policy "$PolicyID.cip" -json | Out-Null

                &$WritePink "Strict Kernel mode policy with no flighting root certs has been deployed in Enforced mode, please restart your system."

                if (!$Debug) {
                    Remove-Item -Path '.\Final_DefaultWindows_Enforced_Kernel.xml', ".\$PolicyID.cip" -Force
                } 
            }
        }

    }    
  
    <#
.SYNOPSIS
Creates Kernel only mode WDAC policy capable of protecting against BYOVD attacks category

.LINK
https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig

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

.PARAMETER SkipVersionCheck
Can be used with any parameter to bypass the online version check - only to be used in rare cases

#>
}
# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete