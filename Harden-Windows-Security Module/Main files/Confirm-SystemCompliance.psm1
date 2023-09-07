# Set the progress style
$PSStyle.Progress.Style = "$($PSStyle.Foreground.FromRGB(255,255,49))$($PSStyle.Blink)"

# To parse the ini file from the output of the "Secedit /export /cfg .\security_policy.inf"
function ConvertFrom-IniFile {
    [CmdletBinding()]
    Param ([string]$IniFile)
            
    # Don't prompt to continue if '-Debug' is specified.
    $DebugPreference = 'Continue'
          
    [hashtable]$IniObject = @{}
    [string]$SectionName = ''
    switch -regex -file $IniFile {
        '^\[(.+)\]$' {
            # Header of the section
            $SectionName = $matches[1]
            #Write-Debug "Section: $SectionName"
            $IniObject[$SectionName] = @{}
            continue
        }
        '^(.+?)\s*=\s*(.*)$' {
            # Name/value pair
            [string]$KeyName, [string]$KeyValue = $matches[1..2]
            #Write-Debug "Name: $KeyName"
            # Write-Debug "Value: $KeyValue"
            $IniObject[$SectionName][$KeyName] = $KeyValue
            continue
        }
        default {
            # Ignore blank lines or comments
            continue
        }
    }
    return [PSCustomObject]$IniObject
}

# Main function
function Confirm-SystemCompliance {   
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $false)]        
        [switch]$ExportToCSV,
        [parameter(Mandatory = $false)]        
        [switch]$ShowAsObjectsOnly,
        [parameter(Mandatory = $false)]        
        [switch]$DetailedDisplay        
    )
    begin {
        # Stop operation as soon as there is an error anywhere, unless explicitly specified otherwise
        $global:ErrorActionPreference = 'Stop'

        Write-Progress -Activity 'Starting' -Status 'Processing...' -PercentComplete 5   

        # Makes sure this cmdlet is invoked with Admin privileges
        if (![bool]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Error -Message 'Confirm-SystemCompliance cmdlet requires Administrator privileges.' -ErrorAction Stop
        }

        Write-Progress -Activity 'Checking for updates' -Status 'Processing...' -PercentComplete 10

        . "$psscriptroot\Functions.ps1"
           
        Write-Progress -Activity 'Gathering Security Policy Information' -Status 'Processing...' -PercentComplete 15

        # Get the security group policies
        Secedit /export /cfg .\security_policy.inf | Out-Null

        # Storing the output of the ini file parsing function
        [PSCustomObject]$SecurityPoliciesIni = ConvertFrom-IniFile -IniFile .\security_policy.inf
        
        Write-Progress -Activity 'Importing Registry CSV File' -Status 'Processing...' -PercentComplete 20
        
        # Import the CSV file
        [System.Object[]]$CSVResource = Import-Csv -Path "$psscriptroot\Resources\Registry resources.csv"
     
        # An object to hold all the initial registry items
        [System.Object[]]$AllRegistryItems = @()

        # Loop through each row in the CSV file
        foreach ($Row in $CSVResource) {
            $AllRegistryItems += [PSCustomObject]@{
                FriendlyName = $Row.FriendlyName
                category     = $Row.Category
                key          = $Row.Key                
                value        = $Row.Value
                name         = $Row.Name
                type         = $Row.Type                
                regPath      = "Registry::$($Row.Key)" # Build the registry path
                Method       = $Row.Origin
            }
        }

        # An object to store the FINAL results
        $FinalMegaObject = [PSCustomObject]@{} 

        # Function for processing each item in $AllRegistryItems for each category
        function Invoke-CategoryProcessing {
            param(
                [string]$CatName, [string]$Method
            )

            # an array to hold the output
            [System.Object[]]$output = @()
        
            foreach ($item in $AllRegistryItems | Where-Object { $_.category -eq $CatName } | Where-Object { $_.Method -eq $Method }) {
        
                # Initialize a flag to indicate if the key exists
                [bool]$keyExists = $false
            
                # Initialize a flag to indicate if the value exists and matches the type
                [bool]$valueMatches = $false
            
                # Try to get the registry key
                try {
                    $regKey = Get-Item -Path $item.regPath
                    # If no error is thrown, the key exists
                    $keyExists = $true
            
                    # Try to get the registry value and type
                    try {
                        $regValue = Get-ItemPropertyValue -Path $item.regPath -Name $item.name
                        # If no error is thrown, the value exists
            
                        # Check if the value matches the expected one
                        if ($regValue -eq $item.value) {
                            # If it matches, set the flag to true
                            $valueMatches = $true
                        }
                    }
                    catch {
                        # If an error is thrown, the value does not exist or is not accessible
                        # Do nothing, the flag remains false
                    }
                }
                catch {
                    # If an error is thrown, the key does not exist or is not accessible
                    # Do nothing, the flag remains false
                }
            
                # Create a custom object with the results for this row
                $output += [PSCustomObject]@{
                    # Category     = $item.category
                    # Key          = $item.key
                    #  Name         = $item.name
                    # KeyExists    = $keyExists
                    # ValueMatches = $valueMatches
                    # Type         = $item.type
                    #  Value        = $item.value
                    
                    FriendlyName = $item.FriendlyName
                    Compliant    = $valueMatches
                    Value        = $item.value  
                    Name         = $item.name                  
                    Category     = $CatName
                    Method       = $Method
                }
            }
            return $output
        }
    }

    process {
        
        #Region Microsoft-Defender-Category
        Write-Progress -Activity 'Validating Microsoft Defender Category' -Status 'Processing...' -PercentComplete 35

        # An array to store the nested custom objects, inside the main output object
        [System.Object[]]$NestedObjectArray = @()        
        [String]$CatName = 'Microsoft Defender'        
        
        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array
        $NestedObjectArray += [PSCustomObject](Invoke-CategoryProcessing -catname $CatName -Method 'Group Policy')       
     
        # For PowerShell Cmdlet
        $IndividualItemResult = $((Get-MpPreference).AllowSwitchToAsyncInspection)
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'AllowSwitchToAsyncInspection'            
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult 
            Name         = 'AllowSwitchToAsyncInspection'           
            Category     = $CatName
            Method       = 'Cmdlet'            
        }
    
        # For PowerShell Cmdlet
        $IndividualItemResult = $((Get-MpPreference).oobeEnableRtpAndSigUpdate)
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'oobeEnableRtpAndSigUpdate'            
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult 
            Name         = 'oobeEnableRtpAndSigUpdate'          
            Category     = $CatName
            Method       = 'Cmdlet'            
        }
    
        # For PowerShell Cmdlet
        $IndividualItemResult = $((Get-MpPreference).IntelTDTEnabled)
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'IntelTDTEnabled'
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult   
            Name         = 'IntelTDTEnabled'         
            Category     = $CatName
            Method       = 'Cmdlet'            
        }
    
        # For PowerShell Cmdlet
        $IndividualItemResult = $((Get-ProcessMitigation -System).aslr.ForceRelocateImages)
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Mandatory ASLR'            
            Compliant    = $IndividualItemResult -eq 'on' ? $True : $false
            Value        = $IndividualItemResult            
            Name         = 'Mandatory ASLR'
            Category     = $CatName
            Method       = 'Cmdlet'            
        }
    
        # For BCDEDIT NX value verification
        # IMPORTANT: bcdedit /enum requires an ELEVATED session.
        # Answer by mklement0: https://stackoverflow.com/a/50949849
        $BcdOutput = (bcdedit /enum) -join "`n" # collect bcdedit's output as a *single* string
    
        # Initialize the output list.
        $Entries = New-Object System.Collections.Generic.List[PSCustomObject]
    
        # Parse bcdedit's output.
    ($BcdOutput -split '(?m)^(.+\n-)-+\n' -ne '').ForEach({
                if ($_.EndsWith("`n-")) {
                    # entry header 
                    $Entries.Add([PSCustomObject] @{ Name = ($_ -split '\n')[0]; Properties = [ordered] @{} })
                }
                else {
                    # block of property-value lines
    ($_ -split '\n' -ne '').ForEach({
                            $propAndVal = $_ -split '\s+', 2 # split line into property name and value
                            if ($propAndVal[0] -ne '') {
                                # [start of] new property; initialize list of values
                                $currProp = $propAndVal[0]
                                $Entries[-1].Properties[$currProp] = New-Object Collections.Generic.List[string]
                            }
                            $Entries[-1].Properties[$currProp].Add($propAndVal[1]) # add the value
                        })
                }
            })
    
        # For PowerShell Cmdlet
        $IndividualItemResult = $(($Entries | Where-Object { $_.properties.identifier -eq '{current}' }).properties.nx)
        $NestedObjectArray += [PSCustomObject]@{            
            FriendlyName = (Get-Culture).name -eq 'en-US' ? 'BCDEDIT NX Value' : '(Not accurate on non-English system languages) - BCDEDIT NX Value'          
            Compliant    = $IndividualItemResult -eq 'AlwaysOn' ? $True : $false   
            Value        = $IndividualItemResult           
            Name         = (Get-Culture).name -eq 'en-US' ? 'BCDEDIT NX Value' : '(Not accurate on non-English system languages) - BCDEDIT NX Value'
            Category     = $CatName
            Method       = 'Cmdlet'             
        }
    
        # For PowerShell Cmdlet
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Smart App Control State'            
            Compliant    = 'N/A'
            Value        = $((Get-MpComputerStatus).SmartAppControlState)            
            Name         = 'Smart App Control State'
            Category     = $CatName
            Method       = 'Cmdlet'            
        }
    
        # For PowerShell Cmdlet
        try {
            $IndividualItemResult = $((Get-ScheduledTask -TaskPath '\MSFT Driver Block list update\' -TaskName 'MSFT Driver Block list update' -ErrorAction SilentlyContinue) ? $True : $false)
        } 
        catch {
            # suppress any possible terminating errors
        }
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Fast weekly Microsoft recommended driver block list update'            
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult            
            Name         = 'Fast weekly Microsoft recommended driver block list update'
            Category     = $CatName
            Method       = 'Cmdlet'           
        }
    
    
        [hashtable]$DefenderPlatformUpdatesChannels = @{
            0 = 'NotConfigured'
            2 = 'Beta'
            3 = 'Preview'
            4 = 'Staged'
            5 = 'Broad'
            6 = 'Delayed'
        }
        # For PowerShell Cmdlet
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Microsoft Defender Platform Updates Channel'            
            Compliant    = 'N/A'
            Value        = $($DefenderPlatformUpdatesChannels[[int](Get-MpPreference).PlatformUpdatesChannel])            
            Name         = 'Microsoft Defender Platform Updates Channel'
            Category     = $CatName
            Method       = 'Cmdlet'           
        }
    
    
        [hashtable]$DefenderEngineUpdatesChannels = @{
            0 = 'NotConfigured'
            2 = 'Beta'
            3 = 'Preview'
            4 = 'Staged'
            5 = 'Broad'
            6 = 'Delayed'
        }
        # For PowerShell Cmdlet
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Microsoft Defender Engine Updates Channel'            
            Compliant    = 'N/A'
            Value        = $($DefenderEngineUpdatesChannels[[int](Get-MpPreference).EngineUpdatesChannel])            
            Name         = 'Microsoft Defender Engine Updates Channel'
            Category     = $CatName
            Method       = 'Cmdlet'            
        }
    
        # For PowerShell Cmdlet
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Controlled Folder Access Exclusions'            
            Compliant    = 'N/A'
            Value        = [PSCustomObject]@{Count = $((Get-MpPreference).ControlledFolderAccessAllowedApplications.count); Programs = $((Get-MpPreference).ControlledFolderAccessAllowedApplications) }
            Name         = 'Controlled Folder Access Exclusions'
            Category     = $CatName
            Method       = 'Cmdlet'            
        } 
        
        # For PowerShell Cmdlet
        $IndividualItemResult = $((Get-MpPreference).DisableRestorePoint)
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Enable Restore Point scanning'
            Compliant    = ($IndividualItemResult -eq $False)
            Value        = ($IndividualItemResult -eq $False)   
            Name         = 'Enable Restore Point scanning'
            Category     = $CatName
            Method       = 'Cmdlet'            
        }

        # For PowerShell Cmdlet
        $IndividualItemResult = $((Get-MpPreference).PerformanceModeStatus)
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'PerformanceModeStatus'
            Compliant    = [bool]($IndividualItemResult -eq '0')
            Value        = $IndividualItemResult   
            Name         = 'PerformanceModeStatus'         
            Category     = $CatName
            Method       = 'Cmdlet'            
        }

        # For PowerShell Cmdlet
        $IndividualItemResult = $((Get-MpPreference).EnableConvertWarnToBlock)
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'EnableConvertWarnToBlock'
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult   
            Name         = 'EnableConvertWarnToBlock'         
            Category     = $CatName
            Method       = 'Cmdlet'            
        }
        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray
        #EndRegion Microsoft-Defender-Category
    
        #Region Attack-Surface-Reduction-Rules-Category
        Write-Progress -Activity 'Validating Attack Surface Reduction Rules Category' -Status 'Processing...' -PercentComplete 40
        [System.Object[]]$NestedObjectArray = @()
        [String]$CatName = 'ASR'

        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array
        $NestedObjectArray += [PSCustomObject](Invoke-CategoryProcessing -catname $CatName -Method 'Group Policy')
                
        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray
        #EndRegion Attack-Surface-Reduction-Rules-Category
    
        #Region Bitlocker-Category
        Write-Progress -Activity 'Validating Bitlocker Category' -Status 'Processing...' -PercentComplete 45
        [System.Object[]]$NestedObjectArray = @()
        [String]$CatName = 'Bitlocker'

        # This PowerShell script can be used to find out if the DMA Protection is ON \ OFF.
        # The Script will show this by emitting True \ False for On \ Off respectively.

        # bootDMAProtection check - checks for Kernel DMA Protection status in System information or msinfo32
        [string]$BootDMAProtectionCheck =
        @'
  namespace SystemInfo
    {
      using System;
      using System.Runtime.InteropServices;

      public static class NativeMethods
      {
        internal enum SYSTEM_DMA_GUARD_POLICY_INFORMATION : int
        {
            /// </summary>
            SystemDmaGuardPolicyInformation = 202
        }

        [DllImport("ntdll.dll")]
        internal static extern Int32 NtQuerySystemInformation(
          SYSTEM_DMA_GUARD_POLICY_INFORMATION SystemDmaGuardPolicyInformation,
          IntPtr SystemInformation,
          Int32 SystemInformationLength,
          out Int32 ReturnLength);

        public static byte BootDmaCheck() {
          Int32 result;
          Int32 SystemInformationLength = 1;
          IntPtr SystemInformation = Marshal.AllocHGlobal(SystemInformationLength);
          Int32 ReturnLength;

          result = NativeMethods.NtQuerySystemInformation(
                    NativeMethods.SYSTEM_DMA_GUARD_POLICY_INFORMATION.SystemDmaGuardPolicyInformation,
                    SystemInformation,
                    SystemInformationLength,
                    out ReturnLength);

          if (result == 0) {
            byte info = Marshal.ReadByte(SystemInformation, 0);
            return info;
          }

          return 0;
        }
      }
    }
'@
        Add-Type -TypeDefinition $BootDMAProtectionCheck
        # Returns true or false depending on whether Kernel DMA Protection is on or off
        [bool]$BootDMAProtection = ([SystemInfo.NativeMethods]::BootDmaCheck()) -ne 0    

        # Get the status of Bitlocker DMA protection 
        try {       
            [int]$BitlockerDMAProtectionStatus = Get-ItemPropertyValue -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\FVE' -Name 'DisableExternalDMAUnderLock' -ErrorAction SilentlyContinue
        } 
        catch {
            # -ErrorAction SilentlyContinue wouldn't suppress the error if the path exists but property doesn't, so using try-catch 
        }
        # Bitlocker DMA counter measure status
        # Returns true if only either Kernel DMA protection is on and Bitlocker DMA protection if off
        # or Kernel DMA protection is off and Bitlocker DMA protection is on
        [bool]$ItemState = ($bootDMAProtection -xor ($BitlockerDMAProtectionStatus -eq '1')) ? $True : $False

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'DMA protection'           
            Compliant    = $ItemState
            Value        = $ItemState            
            Name         = 'DMA protection'
            Category     = $CatName
            Method       = 'Group Policy'                
        }  


        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array
        $NestedObjectArray += [PSCustomObject](Invoke-CategoryProcessing -catname $CatName -Method 'Group Policy')

        # For PowerShell Cmdlet
        try {
            $IndividualItemResult = $($((Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Power -Name HibernateEnabled -ErrorAction SilentlyContinue).hibernateEnabled) -eq 1 ? $True : $False)
        } 
        catch {
            # suppress the errors if any
        }
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Hibernate enabled and set to full'            
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult           
            Name         = 'Hibernate enabled and set to full'
            Category     = $CatName
            Method       = 'Cmdlet'
        }

        # OS Drive encryption verifications
        if ((Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus -eq 'on') {                                 
            [System.Object[]]$KeyProtectors = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector.keyprotectortype
            # check if TPM+PIN and recovery password are being used with Bitlocker which are the safest settings
            if (($KeyProtectors -contains 'Tpmpin') -and ($KeyProtectors -contains 'RecoveryPassword')) {        
                $IndividualItemResult = $True
            }
            else {
                $IndividualItemResult = $false
            }
        }
        else {
            $IndividualItemResult = $false
        }
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Secure OS Drive encryption'            
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult           
            Name         = 'Secure OS Drive encryption'
            Category     = $CatName
            Method       = 'Cmdlet'
        }  

        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray
        #EndRegion Bitlocker-Category
    
        #Region TLS-Category
        Write-Progress -Activity 'Validating TLS Category' -Status 'Processing...' -PercentComplete 50
        [System.Object[]]$NestedObjectArray = @()
        [String]$CatName = 'TLS'
        
        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array
        $NestedObjectArray += [PSCustomObject](Invoke-CategoryProcessing -catname $CatName -Method 'Group Policy')
        
        # ECC Curves
        [System.Object[]]$ECCCurves = Get-TlsEccCurve
        [System.Object[]]$list = ('nistP521', 'curve25519', 'NistP384', 'NistP256')
        # Make sure both arrays are completely identical in terms of members and their exact position
        # If this variable is empty that means both arrays are completely identical
        $IndividualItemResult = Compare-Object $ECCCurves $list -SyncWindow 0

        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'ECC Curves and their positions'            
            Compliant    = [bool]($IndividualItemResult ? $false : $True)
            Value        = $list            
            Name         = 'ECC Curves and their positions'
            Category     = $CatName
            Method       = 'Cmdlet'
        }   

        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array
        $NestedObjectArray += [PSCustomObject](Invoke-CategoryProcessing -catname $CatName -Method 'Registry Keys')

        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray
        #EndRegion TLS-Category
    
        #Region LockScreen-Category
        Write-Progress -Activity 'Validating Lock Screen Category' -Status 'Processing...' -PercentComplete 55
        [System.Object[]]$NestedObjectArray = @()
        [String]$CatName = 'LockScreen'
        
        $NestedObjectArray += [PSCustomObject](Invoke-CategoryProcessing -catname $CatName -Method 'Group Policy')
    
        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs'] -eq '4,120') ? $True : $False   
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Machine inactivity limit'
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult   
            Name         = 'Machine inactivity limit'         
            Category     = $CatName
            Method       = 'Security Group Policy'
        }
    
        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array   
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD'] -eq '4,0') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Interactive logon: Do not require CTRL+ALT+DEL'            
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult  
            Name         = 'Interactive logon: Do not require CTRL+ALT+DEL'          
            Category     = $CatName
            Method       = 'Security Group Policy'
        }
    
        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array   
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\MaxDevicePasswordFailedAttempts'] -eq '4,5') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Interactive logon: Machine account lockout threshold'            
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult  
            Name         = 'Interactive logon: Machine account lockout threshold'          
            Category     = $CatName
            Method       = 'Security Group Policy'
        }
    
        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array   
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLockedUserId'] -eq '4,4') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Interactive logon: Display user information when the session is locked'             
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult    
            Name         = 'Interactive logon: Display user information when the session is locked'        
            Category     = $CatName
            Method       = 'Security Group Policy'
        }
    
        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array   
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayUserName'] -eq '4,1') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = "Interactive logon: Don't display username at sign-in"            
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult    
            Name         = "Interactive logon: Don't display username at sign-in"        
            Category     = $CatName
            Method       = 'Security Group Policy'
        }

        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array   
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'System Access'['LockoutBadCount'] -eq '5') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Account lockout threshold'           
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult 
            Name         = 'Account lockout threshold'         
            Category     = $CatName
            Method       = 'Security Group Policy'
        }

        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array   
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'System Access'['LockoutDuration'] -eq '1440') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Account lockout duration'            
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult
            Name         = 'Account lockout duration'            
            Category     = $CatName
            Method       = 'Security Group Policy'
        }

        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array   
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'System Access'['ResetLockoutCount'] -eq '1440') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Reset account lockout counter after'            
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult  
            Name         = 'Reset account lockout counter after'          
            Category     = $CatName
            Method       = 'Security Group Policy'
        }

        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array   
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName'] -eq '4,1') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = "Interactive logon: Don't display last signed-in"            
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult           
            Name         = "Interactive logon: Don't display last signed-in"
            Category     = $CatName
            Method       = 'Security Group Policy'
        }
    
        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray
        #EndRegion LockScreen-Category
    
        #Region User-Account-Control-Category
        Write-Progress -Activity 'Validating User Account Control Category' -Status 'Processing...' -PercentComplete 60
        [System.Object[]]$NestedObjectArray = @()
        [String]$CatName = 'UAC' 

        $NestedObjectArray += [PSCustomObject](Invoke-CategoryProcessing -catname $CatName -Method 'Group Policy')

        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin'] -eq '4,2') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'UAC: Behavior of the elevation prompt for administrators in Admin Approval Mode'            
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult      
            Name         = 'UAC: Behavior of the elevation prompt for administrators in Admin Approval Mode'      
            Category     = $CatName
            Method       = 'Security Group Policy'
        }
    
        
        # This particular policy can have 2 values and they are both acceptable depending on whichever user selects        
        [string]$ConsentPromptBehaviorUserValue = $SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser']
        # This option is automatically applied when UAC category is run
        if ($ConsentPromptBehaviorUserValue -eq '4,1') {        
            $ConsentPromptBehaviorUserCompliance = $true
            $IndividualItemResult = 'Prompt for credentials on the secure desktop'
        }
        # This option prompts for additional confirmation before it's applied
        elseif ($ConsentPromptBehaviorUserValue -eq '4,0') {
            $ConsentPromptBehaviorUserCompliance = $true
            $IndividualItemResult = 'Automatically deny elevation requests'
        }
        # If none of them is applied then return false for compliance and N/A for value
        else {
            $ConsentPromptBehaviorUserCompliance = $false
            $IndividualItemResult = 'N/A'
        }

        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'UAC: Behavior of the elevation prompt for standard users'            
            Compliant    = $ConsentPromptBehaviorUserCompliance
            Value        = $IndividualItemResult    
            Name         = 'UAC: Behavior of the elevation prompt for standard users'        
            Category     = $CatName
            Method       = 'Security Group Policy'
        }   

        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array   
        $IndividualItemResult = [bool]($($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures'] -eq '4,1') ? $True : $False)
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'UAC: Only elevate executables that are signed and validated'            
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult  
            Name         = 'UAC: Only elevate executables that are signed and validated'          
            Category     = $CatName
            Method       = 'Security Group Policy'
        }
                
        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray
        #EndRegion User-Account-Control-Category
    
        #Region Device-Guard-Category
        Write-Progress -Activity 'Validating Device Guard Category' -Status 'Processing...' -PercentComplete 65
        [System.Object[]]$NestedObjectArray = @()
        [String]$CatName = 'Device Guard'
 
        $NestedObjectArray += [PSCustomObject](Invoke-CategoryProcessing -catname $CatName -Method 'Group Policy')

        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray
        #EndRegion Device-Guard-Category
        
        #Region Windows-Firewall-Category
        Write-Progress -Activity 'Validating Windows Firewall Category' -Status 'Processing...' -PercentComplete 70
        [System.Object[]]$NestedObjectArray = @()
        [String]$CatName = 'Windows Firewall'
                  
        $NestedObjectArray += [PSCustomObject](Invoke-CategoryProcessing -catname $CatName -Method 'Group Policy')
    
        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray
        #EndRegion Windows-Firewall-Category

        #Region Optional-Windows-Features-Category
        Write-Progress -Activity 'Validating Optional Windows Features Category' -Status 'Processing...' -PercentComplete 75
        [System.Object[]]$NestedObjectArray = @()
        [String]$CatName = 'Optional Windows Features'
         
        # Windows PowerShell handling Windows optional features verifications
        [System.Object[]]$Results = @()
        $Results = powershell.exe {
            [bool]$PowerShell1 = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).State -eq 'Disabled'
            [bool]$PowerShell2 = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).State -eq 'Disabled'
            [string]$WorkFoldersClient = (Get-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client).state
            [string]$InternetPrintingClient = (Get-WindowsOptionalFeature -Online -FeatureName Printing-Foundation-Features).state
            [string]$WindowsMediaPlayer = (Get-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer).state
            [string]$MDAG = (Get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard).state
            [string]$WindowsSandbox = (Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM).state
            [string]$HyperV = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).state
            [string]$VMPlatform = (Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform).state
            [string]$WMIC = (Get-WindowsCapability -Online | Where-Object { $_.Name -like '*wmic*' }).state
            [string]$IEMode = (Get-WindowsCapability -Online | Where-Object { $_.Name -like '*Browser.InternetExplorer*' }).state
            [string]$LegacyNotepad = (Get-WindowsCapability -Online | Where-Object { $_.Name -like '*Microsoft.Windows.Notepad.System*' }).state
            # returning the output of the script block as an array
            Return $PowerShell1, $PowerShell2, $WorkFoldersClient, $InternetPrintingClient, $WindowsMediaPlayer, $MDAG, $WindowsSandbox, $HyperV, $VMPlatform, $WMIC, $IEMode, $LegacyNotepad
        } 
        # Verify PowerShell v2 is disabled
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'PowerShell v2 is disabled'            
            Compliant    = ($Results[0] -and $Results[1]) ? $True : $False
            Value        = ($Results[0] -and $Results[1]) ? $True : $False 
            Name         = 'PowerShell v2 is disabled'          
            Category     = $CatName
            Method       = 'Optional Windows Features'
        }

        # Verify Work folders is disabled
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Work Folders client is disabled'            
            Compliant    = [bool]($Results[2] -eq 'Disabled')
            Value        = [string]$Results[2]         
            Name         = 'Work Folders client is disabled'
            Category     = $CatName
            Method       = 'Optional Windows Features'
        }

        # Verify Internet Printing Client is disabled      
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Internet Printing Client is disabled'            
            Compliant    = [bool]($Results[3] -eq 'Disabled')
            Value        = [string]$Results[3]   
            Name         = 'Internet Printing Client is disabled'         
            Category     = $CatName
            Method       = 'Optional Windows Features'
        }

        # Verify the old Windows Media Player is disabled    
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Windows Media Player (legacy) is disabled'            
            Compliant    = [bool]($Results[4] -eq 'Disabled')
            Value        = [string]$Results[4]
            Name         = 'Windows Media Player (legacy) is disabled'          
            Category     = $CatName
            Method       = 'Optional Windows Features'
        }

        # Verify MDAG is enabled       
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Microsoft Defender Application Guard is enabled'            
            Compliant    = [bool]($Results[5] -eq 'Enabled')
            Value        = [string]$Results[5]
            Name         = 'Microsoft Defender Application Guard is enabled'           
            Category     = $CatName
            Method       = 'Optional Windows Features'
        }

        # Verify Windows Sandbox is enabled   
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Windows Sandbox is enabled'            
            Compliant    = [bool]($Results[6] -eq 'Enabled')
            Value        = [string]$Results[6]
            Name         = 'Windows Sandbox is enabled'           
            Category     = $CatName
            Method       = 'Optional Windows Features'
        }
        
        # Verify Hyper-V is enabled     
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Hyper-V is enabled'            
            Compliant    = [bool]($Results[7] -eq 'Enabled')
            Value        = [string]$Results[7]
            Name         = 'Hyper-V is enabled'           
            Category     = $CatName
            Method       = 'Optional Windows Features'
        }

        # Verify Virtual Machine Platform is enabled
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Virtual Machine Platform is enabled'            
            Compliant    = [bool]($Results[8] -eq 'Enabled')
            Value        = [string]$Results[8]
            Name         = 'Virtual Machine Platform is enabled'           
            Category     = $CatName
            Method       = 'Optional Windows Features'
        }

        # Verify WMIC is not present
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'WMIC is not present'            
            Compliant    = [bool]($Results[9] -eq 'NotPresent')
            Value        = [string]$Results[9] 
            Name         = 'WMIC is not present'          
            Category     = $CatName
            Method       = 'Optional Windows Features'
        }

        # Verify Internet Explorer mode functionality for Edge is not present    
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Internet Explorer mode functionality for Edge is not present'           
            Compliant    = [bool]($Results[10] -eq 'NotPresent')
            Value        = [string]$Results[10]    
            Name         = 'Internet Explorer mode functionality for Edge is not present'                   
            Category     = $CatName
            Method       = 'Optional Windows Features'
        }

        # Verify Legacy Notepad is not present        
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Legacy Notepad is not present'           
            Compliant    = [bool]($Results[11] -eq 'NotPresent')
            Value        = [string]$Results[11]  
            Name         = 'Legacy Notepad is not present'                   
            Category     = $CatName
            Method       = 'Optional Windows Features'
        }
    
        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray
        #EndRegion Optional-Windows-Features-Category

        #Region Windows-Networking-Category
        Write-Progress -Activity 'Validating Windows Networking Category' -Status 'Processing...' -PercentComplete 80
        [System.Object[]]$NestedObjectArray = @()
        [String]$CatName = 'Windows Networking'
        
        $NestedObjectArray += [PSCustomObject](Invoke-CategoryProcessing -catname $CatName -Method 'Group Policy')
        
        # Check network location of all connections to see if they are public
        $Condition = Get-NetConnectionProfile | ForEach-Object { $_.NetworkCategory -eq 'public' }
        [bool]$IndividualItemResult = -not ($condition -contains $false) ? $True : $false 
    
        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Network Location of all connections set to Public'            
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult
            Name         = 'Network Location of all connections set to Public'          
            Category     = $CatName
            Method       = 'Cmdlet'
        }
    
        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array
        try {
            $IndividualItemResult = [bool]((Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'EnableLMHOSTS' -ErrorAction SilentlyContinue) -eq '0')
        } 
        catch {
            # -ErrorAction SilentlyContinue wouldn't suppress the error if the path exists but property doesn't, so using try-catch 
        }
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Disable LMHOSTS lookup protocol on all network adapters'            
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult     
            Name         = 'Disable LMHOSTS lookup protocol on all network adapters'       
            Category     = $CatName
            Method       = 'Registry Key'
        }

        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array   
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'Registry Values'['MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine'] -eq '7,') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Network access: Remotely accessible registry paths'            
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult
            Name         = 'Network access: Remotely accessible registry paths'
            Category     = $CatName
            Method       = 'Security Group Policy'
        }

        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array   
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'Registry Values'['MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine'] -eq '7,') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Network access: Remotely accessible registry paths and subpaths'            
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult        
            Name         = 'Network access: Remotely accessible registry paths and subpaths'    
            Category     = $CatName
            Method       = 'Security Group Policy'
        }
    
        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray
        #EndRegion Windows-Networking-Category
        
        #Region Miscellaneous-Category
        Write-Progress -Activity 'Validating Miscellaneous Category' -Status 'Processing...' -PercentComplete 85
        [System.Object[]]$NestedObjectArray = @()
        [String]$CatName = 'Miscellaneous'
        
        $NestedObjectArray += [PSCustomObject](Invoke-CategoryProcessing -catname $CatName -Method 'Group Policy')
    
        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array
        $IndividualItemResult = [bool]((Get-SmbServerConfiguration).encryptdata)
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'SMB Encryption'           
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult
            Name         = 'SMB Encryption'
            Category     = $CatName
            Method       = 'Cmdlet'
        }
         
        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array
        $IndividualItemResult = [bool](((auditpol /get /subcategory:"Other Logon/Logoff Events" /r | ConvertFrom-Csv).'Inclusion Setting' -eq 'Success and Failure') ? $True : $False)
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = (Get-Culture).name -eq 'en-US' ? 'Audit policy for Other Logon/Logoff Events' : '(Not accurate on non-English system languages) - Audit policy for Other Logon/Logoff Events'            
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult
            Name         = (Get-Culture).name -eq 'en-US' ? 'Audit policy for Other Logon/Logoff Events' : '(Not accurate on non-English system languages) - Audit policy for Other Logon/Logoff Events'            
            Category     = $CatName
            Method       = 'Cmdlet'
        }            

        # Checking if all user accounts are part of the Hyper-V security Group 
        # Get all the enabled user accounts
        [string[]]$enabledUsers = (Get-LocalUser | Where-Object { $_.Enabled -eq 'True' }).Name | Sort-Object
        # Get the members of the Hyper-V Administrators security group using their SID
        [string[]]$groupMembers = (Get-LocalGroupMember -SID 'S-1-5-32-578').Name -replace "$($env:COMPUTERNAME)\\" | Sort-Object

        # Set the $MatchHyperVUsers variable to $True only if all enabled user accounts are part of the Hyper-V Security group, if one of them isn't part of the group then returns false
        [System.Object[]]$MatchHyperVUsers = @() # An array of bool values
        for ($i = 0; $i -lt $enabledUsers.Count; $i++) {
            $MatchHyperVUsers += ($enabledUsers[$i] -ceq $groupMembers[$i]) ? $True : $false
        }
        
        # Saving the results of the Hyper-V administrators members group to the array as an object
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'All users are part of the Hyper-V Administrators group'            
            Compliant    = [bool]($MatchHyperVUsers -notcontains $false)
            Value        = [bool]($MatchHyperVUsers -notcontains $false)  
            Name         = 'All users are part of the Hyper-V Administrators group'          
            Category     = $CatName
            Method       = 'Cmdlet'
        }
        
        $NestedObjectArray += [PSCustomObject](Invoke-CategoryProcessing -catname $CatName -Method 'Registry Keys')
    
        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray
        #EndRegion Miscellaneous-Category
    
        #Region Windows-Update-Category
        Write-Progress -Activity 'Validating Windows Update Category' -Status 'Processing...' -PercentComplete 90
        [System.Object[]]$NestedObjectArray = @()
        [String]$CatName = 'Windows Update'
        
        $NestedObjectArray += [PSCustomObject](Invoke-CategoryProcessing -catname $CatName -Method 'Group Policy')
    
        # Process the registry keys for this category based on the selected method and category name, then save the output Custom Object in the Array
        try {
            $IndividualItemResult = [bool]((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'RestartNotificationsAllowed2' -ErrorAction SilentlyContinue) -eq '1')
        } 
        catch {
            # -ErrorAction SilentlyContinue wouldn't suppress the error if the path exists but property doesn't, so using try-catch 
        }
        $NestedObjectArray += [PSCustomObject]@{
            FriendlyName = 'Enable restart notification for Windows update'            
            Compliant    = $IndividualItemResult
            Value        = $IndividualItemResult 
            Name         = 'Enable restart notification for Windows update'           
            Category     = $CatName
            Method       = 'Registry Key'
        }
    
        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray
        #EndRegion Windows-Update-Category
        
        #Region Edge-Category
        Write-Progress -Activity 'Validating Edge Browser Category' -Status 'Processing...' -PercentComplete 95
        [System.Object[]]$NestedObjectArray = @()
        [String]$CatName = 'Edge'  
        
        $NestedObjectArray += [PSCustomObject](Invoke-CategoryProcessing -catname $CatName -Method 'Registry Keys')
            
        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray
        #EndRegion Edge-Category
        
        #Region Non-Admin-Category
        Write-Progress -Activity 'Validating Non-Admin Category' -Status 'Processing...' -PercentComplete 100
        [System.Object[]]$NestedObjectArray = @()
        [String]$CatName = 'Non-Admin'
    
        $NestedObjectArray += [PSCustomObject](Invoke-CategoryProcessing -catname $CatName -Method 'Registry Keys')
    
        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray
        #EndRegion Non-Admin-Category
   
        if ($ExportToCSV) {
            # An array to store the content of each category
            $CsvOutPutFileContent = @()
            # Append the categories in $FinalMegaObject to the array using += operator
            $CsvOutPutFileContent += $FinalMegaObject.PSObject.Properties.Value
            # Convert the array to a CSV file and store it in the current working directory
            $CsvOutPutFileContent | ConvertTo-Csv | Out-File '.\Compliance Check Output.CSV' -Force
        }
        
        if ($ShowAsObjectsOnly) {
            # return the main object that contains multiple nested objects
            return $FinalMegaObject
        }
        else {   

            #Region Colors
            [scriptblock]$WritePlum = { Write-Output "$($PSStyle.Foreground.FromRGB(221,160,221))$($PSStyle.Reverse)$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WriteOrchid = { Write-Output "$($PSStyle.Foreground.FromRGB(218,112,214))$($PSStyle.Reverse)$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WriteFuchsia = { Write-Output "$($PSStyle.Foreground.FromRGB(255,0,255))$($PSStyle.Reverse)$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WriteMediumOrchid = { Write-Output "$($PSStyle.Foreground.FromRGB(186,85,211))$($PSStyle.Reverse)$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WriteMediumPurple = { Write-Output "$($PSStyle.Foreground.FromRGB(147,112,219))$($PSStyle.Reverse)$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WriteBlueViolet = { Write-Output "$($PSStyle.Foreground.FromRGB(138,43,226))$($PSStyle.Reverse)$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$AndroidGreen = { Write-Output "$($PSStyle.Foreground.FromRGB(176,191,26))$($PSStyle.Reverse)$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WritePink = { Write-Output "$($PSStyle.Foreground.FromRGB(255,192,203))$($PSStyle.Reverse)$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WriteHotPink = { Write-Output "$($PSStyle.Foreground.FromRGB(255,105,180))$($PSStyle.Reverse)$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WriteDeepPink = { Write-Output "$($PSStyle.Foreground.FromRGB(255,20,147))$($PSStyle.Reverse)$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WriteMintGreen = { Write-Output "$($PSStyle.Foreground.FromRGB(152,255,152))$($PSStyle.Reverse)$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WriteOrange = { Write-Output "$($PSStyle.Foreground.FromRGB(255,165,0))$($PSStyle.Reverse)$($args[0])$($PSStyle.Reset)" }            
            [scriptblock]$WriteSkyBlue = { Write-Output "$($PSStyle.Foreground.FromRGB(135,206,235))$($PSStyle.Reverse)$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$Daffodil = { Write-Output "$($PSStyle.Foreground.FromRGB(255,255,49))$($PSStyle.Reverse)$($args[0])$($PSStyle.Reset)" }

            [scriptblock]$WriteRainbow1 = { 
                $text = $args[0]
                $colors = @(
                    [System.Drawing.Color]::Pink,
                    [System.Drawing.Color]::HotPink,
                    [System.Drawing.Color]::SkyBlue,
                    [System.Drawing.Color]::Pink,
                    [System.Drawing.Color]::HotPink,
                    [System.Drawing.Color]::SkyBlue,
                    [System.Drawing.Color]::Pink
                )

                $output = ''
                for ($i = 0; $i -lt $text.Length; $i++) {
                    $color = $colors[$i % $colors.Length]
                    $output += "$($PSStyle.Foreground.FromRGB($color.R, $color.G, $color.B))$($text[$i])$($PSStyle.Reset)"
                }
                Write-Output $output
            }          
              
            [scriptblock]$WriteRainbow2 = { 
                $text = $args[0]
                $colors = @(
                    [System.Drawing.Color]::Pink,
                    [System.Drawing.Color]::HotPink,
                    [System.Drawing.Color]::SkyBlue,
                    [System.Drawing.Color]::HotPink,
                    [System.Drawing.Color]::SkyBlue,
                    [System.Drawing.Color]::LightSkyBlue,
                    [System.Drawing.Color]::Lavender,
                    [System.Drawing.Color]::LightGreen,
                    [System.Drawing.Color]::Coral,
                    [System.Drawing.Color]::Plum,
                    [System.Drawing.Color]::Gold
                )
              
                $output = ''
                for ($i = 0; $i -lt $text.Length; $i++) {
                    $color = $colors[$i % $colors.Length]
                    $output += "$($PSStyle.Foreground.FromRGB($color.R, $color.G, $color.B))$($text[$i])$($PSStyle.Reset)"
                }
                Write-Output $output
            }
            #Endregion Colors
    
            # Show all properties in list
            if ($DetailedDisplay) {

                # Setting the List Format Accent the same color as the category's title
                $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(221,160,221))"   
                & $WritePlum "`n-------------Microsoft Defender Category-------------"
                $FinalMegaObject.'Microsoft Defender' | Format-List -Property FriendlyName, @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(221,160,221))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                }, Value, Name, Category, Method
    
                # Setting the List Format Accent the same color as the category's title
                $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(218,112,214))"
                & $WriteOrchid "`n-------------Attack Surface Reduction Rules Category-------------"
                $FinalMegaObject.ASR | Format-List -Property FriendlyName, @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(218,112,214))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                }, Value, Name, Category, Method
    
                # Setting the List Format Accent the same color as the category's title
                $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(255,0,255))"
                & $WriteFuchsia "`n-------------Bitlocker Category-------------"
                $FinalMegaObject.Bitlocker | Format-List -Property FriendlyName, @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(255,0,255))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                }, Value, Name, Category, Method
    
                # Setting the List Format Accent the same color as the category's title
                $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(186,85,211))"
                & $WriteMediumOrchid "`n-------------TLS Category-------------"
                $FinalMegaObject.TLS | Format-List -Property FriendlyName, @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(186,85,211))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                }, Value, Name, Category, Method
    
                # Setting the List Format Accent the same color as the category's title
                $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(147,112,219))"
                & $WriteMediumPurple "`n-------------Lock Screen Category-------------"
                $FinalMegaObject.LockScreen | Format-List -Property FriendlyName, @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(147,112,219))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                }, Value, Name, Category, Method
    
                # Setting the List Format Accent the same color as the category's title
                $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(138,43,226))"
                & $WriteBlueViolet "`n-------------User Account Control Category-------------"
                $FinalMegaObject.UAC | Format-List -Property FriendlyName, @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(138,43,226))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                }, Value, Name, Category, Method
    
                # Setting the List Format Accent the same color as the category's title
                $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(176,191,26))"
                & $AndroidGreen "`n-------------Device Guard Category-------------"
                $FinalMegaObject.'Device Guard' | Format-List -Property FriendlyName, @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(176,191,26))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                }, Value, Name, Category, Method
    
                # Setting the List Format Accent the same color as the category's title
                $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(255,192,203))"
                & $WritePink "`n-------------Windows Firewall Category-------------"
                $FinalMegaObject.'Windows Firewall' | Format-List -Property FriendlyName, @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(255,192,203))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                }, Value, Name, Category, Method

                # Setting the List Format Accent the same color as the category's title
                $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(135,206,235))"
                & $WriteSkyBlue "`n-------------Optional Windows Features Category-------------"
                $FinalMegaObject.'Optional Windows Features' | Format-List -Property FriendlyName, @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(135,206,235))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                }, Value, Name, Category, Method
    
                # Setting the List Format Accent the same color as the category's title
                $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(255,105,180))"
                & $WriteHotPink "`n-------------Windows Networking Category-------------"
                $FinalMegaObject.'Windows Networking' | Format-List -Property FriendlyName, @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(255,105,180))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                }, Value, Name, Category, Method
    
                # Setting the List Format Accent the same color as the category's title
                $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(255,20,147))"
                & $WriteDeepPink "`n-------------Miscellaneous Category-------------"
                $FinalMegaObject.Miscellaneous | Format-List -Property FriendlyName, @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(255,20,147))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                }, Value, Name, Category, Method
    
                # Setting the List Format Accent the same color as the category's title
                $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(152,255,152))"
                & $WriteMintGreen "`n-------------Windows Update Category-------------"
                $FinalMegaObject.'Windows Update' | Format-List -Property FriendlyName, @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(152,255,152))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                }, Value, Name, Category, Method
    
                # Setting the List Format Accent the same color as the category's title
                $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(255,165,0))"
                & $WriteOrange "`n-------------Microsoft Edge Category-------------"
                $FinalMegaObject.Edge | Format-List -Property FriendlyName, @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(255,165,0))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                }, Value, Name, Category, Method
    
                # Setting the List Format Accent the same color as the category's title
                $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(255,255,49))"
                & $Daffodil "`n-------------Non-Admin Category-------------"
                $FinalMegaObject.'Non-Admin' | Format-List -Property FriendlyName, @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(255,255,49))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                }, Value, Name, Category, Method
            }

            # Show properties that matter in a table
            else {
                
                # Setting the Table header the same color as the category's title
                $PSStyle.Formatting.TableHeader = "$($PSStyle.Foreground.FromRGB(221,160,221))"                
                & $WritePlum "`n-------------Microsoft Defender Category-------------"
                $FinalMegaObject.'Microsoft Defender' | Format-Table -Property FriendlyName, 
                @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(221,160,221))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                } , Value -AutoSize
 
                # Setting the Table header the same color as the category's title
                $PSStyle.Formatting.TableHeader = "$($PSStyle.Foreground.FromRGB(218,112,214))"
                & $WriteOrchid "`n-------------Attack Surface Reduction Rules Category-------------"
                $FinalMegaObject.ASR | Format-Table -Property FriendlyName, 
                @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(218,112,214))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                } , Value -AutoSize 
        
                # Setting the Table header the same color as the category's title
                $PSStyle.Formatting.TableHeader = "$($PSStyle.Foreground.FromRGB(255,0,255))"
                & $WriteFuchsia "`n-------------Bitlocker Category-------------"
                $FinalMegaObject.Bitlocker | Format-Table -Property FriendlyName, 
                @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(255,0,255))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                } , Value -AutoSize 
        
                # Setting the Table header the same color as the category's title
                $PSStyle.Formatting.TableHeader = "$($PSStyle.Foreground.FromRGB(186,85,211))"
                & $WriteMediumOrchid "`n-------------TLS Category-------------"
                $FinalMegaObject.TLS | Format-Table -Property FriendlyName, 
                @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(186,85,211))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                } , Value -AutoSize 
        
                # Setting the Table header the same color as the category's title
                $PSStyle.Formatting.TableHeader = "$($PSStyle.Foreground.FromRGB(147,112,219))"
                & $WriteMediumPurple "`n-------------Lock Screen Category-------------"
                $FinalMegaObject.LockScreen | Format-Table -Property FriendlyName, 
                @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(147,112,219))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                } , Value -AutoSize 
        
                # Setting the Table header the same color as the category's title
                $PSStyle.Formatting.TableHeader = "$($PSStyle.Foreground.FromRGB(138,43,226))"
                & $WriteBlueViolet "`n-------------User Account Control Category-------------"
                $FinalMegaObject.UAC | Format-Table -Property FriendlyName, 
                @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(138,43,226))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                } , Value -AutoSize 
        
                # Setting the Table header the same color as the category's title
                $PSStyle.Formatting.TableHeader = "$($PSStyle.Foreground.FromRGB(176,191,26))"
                & $AndroidGreen "`n-------------Device Guard Category-------------"
                $FinalMegaObject.'Device Guard' | Format-Table -Property FriendlyName, 
                @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(176,191,26))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                } , Value -AutoSize 
        
                # Setting the Table header the same color as the category's title
                $PSStyle.Formatting.TableHeader = "$($PSStyle.Foreground.FromRGB(255,192,203))"
                & $WritePink "`n-------------Windows Firewall Category-------------"
                $FinalMegaObject.'Windows Firewall' | Format-Table -Property FriendlyName, 
                @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(255,192,203))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                } , Value -AutoSize 
    
                # Setting the Table header the same color as the category's title
                $PSStyle.Formatting.TableHeader = "$($PSStyle.Foreground.FromRGB(135,206,235))"
                & $WriteSkyBlue "`n-------------Optional Windows Features Category-------------"
                $FinalMegaObject.'Optional Windows Features' | Format-Table -Property FriendlyName, 
                @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(135,206,235))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                } , Value -AutoSize 
        
                # Setting the Table header the same color as the category's title
                $PSStyle.Formatting.TableHeader = "$($PSStyle.Foreground.FromRGB(255,105,180))"
                & $WriteHotPink "`n-------------Windows Networking Category-------------"
                $FinalMegaObject.'Windows Networking' | Format-Table -Property FriendlyName, 
                @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(255,105,180))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                } , Value -AutoSize 
        
                # Setting the Table header the same color as the category's title
                $PSStyle.Formatting.TableHeader = "$($PSStyle.Foreground.FromRGB(255,20,147))"
                & $WriteDeepPink "`n-------------Miscellaneous Category-------------"
                $FinalMegaObject.Miscellaneous | Format-Table -Property FriendlyName, 
                @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(255,20,147))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                } , Value -AutoSize 
        
                # Setting the Table header the same color as the category's title
                $PSStyle.Formatting.TableHeader = "$($PSStyle.Foreground.FromRGB(152,255,152))"
                & $WriteMintGreen "`n-------------Windows Update Category-------------"
                $FinalMegaObject.'Windows Update' | Format-Table -Property FriendlyName, 
                @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(152,255,152))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                } , Value -AutoSize 
        
                # Setting the Table header the same color as the category's title
                $PSStyle.Formatting.TableHeader = "$($PSStyle.Foreground.FromRGB(255,165,0))"
                & $WriteOrange "`n-------------Microsoft Edge Category-------------"
                $FinalMegaObject.Edge | Format-Table -Property FriendlyName, 
                @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(255,165,0))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                } , Value -AutoSize 
        
                # Setting the Table header the same color as the category's title
                $PSStyle.Formatting.TableHeader = "$($PSStyle.Foreground.FromRGB(255,255,49))"
                & $Daffodil "`n-------------Non-Admin Category-------------"
                $FinalMegaObject.'Non-Admin' | Format-Table -Property FriendlyName, 
                @{
                    Label      = 'Compliant'
                    Expression = 
                    { switch ($_.Compliant) {
                            { $_ -eq $true } { $color = "$($PSStyle.Foreground.FromRGB(255,255,49))"; break } # Use PSStyle to set the color
                            { $_ -eq $false } { $color = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break } # Use PSStyle to set the color
                            { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break } # Use PSStyle to set the color
                        }
                        "$color$($_.Compliant)$($PSStyle.Reset)" # Use PSStyle to reset the color
                    }
                  
                } , Value -AutoSize                
            }
            
            # Counting the number of $True Compliant values in the Final Output Object
            [int]$TotalTrueCompliantValuesInOutPut = ($FinalMegaObject.'Microsoft Defender' | Where-Object { $_.Compliant -eq $True }).Count + # 49 - 4x(N/A) = 45
            [int]($FinalMegaObject.ASR | Where-Object { $_.Compliant -eq $True }).Count + # 17
            [int]($FinalMegaObject.Bitlocker | Where-Object { $_.Compliant -eq $True }).Count + # 23
            [int]($FinalMegaObject.TLS | Where-Object { $_.Compliant -eq $True }).Count + # 21
            [int]($FinalMegaObject.LockScreen | Where-Object { $_.Compliant -eq $True }).Count + # 16
            [int]($FinalMegaObject.UAC | Where-Object { $_.Compliant -eq $True }).Count + # 4
            [int]($FinalMegaObject.'Device Guard' | Where-Object { $_.Compliant -eq $True }).Count + # 8
            [int]($FinalMegaObject.'Windows Firewall' | Where-Object { $_.Compliant -eq $True }).Count + # 19
            [int]($FinalMegaObject.'Optional Windows Features' | Where-Object { $_.Compliant -eq $True }).Count + # 11
            [int]($FinalMegaObject.'Windows Networking' | Where-Object { $_.Compliant -eq $True }).Count + # 9
            [int]($FinalMegaObject.Miscellaneous | Where-Object { $_.Compliant -eq $True }).Count + # 18
            [int]($FinalMegaObject.'Windows Update' | Where-Object { $_.Compliant -eq $True }).Count + # 14
            [int]($FinalMegaObject.Edge | Where-Object { $_.Compliant -eq $True }).Count + # 16
            [int]($FinalMegaObject.'Non-Admin' | Where-Object { $_.Compliant -eq $True }).Count # 11


            #Region ASCII-Arts
            [string]$WhenValue1To20 = @'
                OH
                
                N
                　   O
                　　　 O
                　　　　 o
                　　　　　o
                　　　　　 o
                　　　　　o
                　　　　 。
                　　　 。
                　　　.
                　　　.
                　　　 .
                　　　　.
                
'@
                         
                
            [string]$WhenValue21To40 = @'

‎‏‏‎‏‏‎⣿⣿⣷⡁⢆⠈⠕⢕⢂⢕⢂⢕⢂⢔⢂⢕⢄⠂⣂⠂⠆⢂⢕⢂⢕⢂⢕⢂⢕⢂
‎‏‏‎‏‏‎⣿⣿⣿⡷⠊⡢⡹⣦⡑⢂⢕⢂⢕⢂⢕⢂⠕⠔⠌⠝⠛⠶⠶⢶⣦⣄⢂⢕⢂⢕
‎‏‏‎‏‏‎⣿⣿⠏⣠⣾⣦⡐⢌⢿⣷⣦⣅⡑⠕⠡⠐⢿⠿⣛⠟⠛⠛⠛⠛⠡⢷⡈⢂⢕⢂
‎‏‏‎‏‏‎⠟⣡⣾⣿⣿⣿⣿⣦⣑⠝⢿⣿⣿⣿⣿⣿⡵⢁⣤⣶⣶⣿⢿⢿⢿⡟⢻⣤⢑⢂
‎‏‏‎‏‏‎⣾⣿⣿⡿⢟⣛⣻⣿⣿⣿⣦⣬⣙⣻⣿⣿⣷⣿⣿⢟⢝⢕⢕⢕⢕⢽⣿⣿⣷⣔
‎‏‏‎‏‏‎⣿⣿⠵⠚⠉⢀⣀⣀⣈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣗⢕⢕⢕⢕⢕⢕⣽⣿⣿⣿⣿
‎‏‏‎‏‏‎⢷⣂⣠⣴⣾⡿⡿⡻⡻⣿⣿⣴⣿⣿⣿⣿⣿⣿⣷⣵⣵⣵⣷⣿⣿⣿⣿⣿⣿⡿
‎‏‏‎‏‏‎⢌⠻⣿⡿⡫⡪⡪⡪⡪⣺⣿⣿⣿⣿⣿⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃
‎‏‏‎‏‏‎⠣⡁⠹⡪⡪⡪⡪⣪⣾⣿⣿⣿⣿⠋⠐⢉⢍⢄⢌⠻⣿⣿⣿⣿⣿⣿⣿⣿⠏⠈
‎‏‏‎‏‏‎⡣⡘⢄⠙⣾⣾⣾⣿⣿⣿⣿⣿⣿⡀⢐⢕⢕⢕⢕⢕⡘⣿⣿⣿⣿⣿⣿⠏⠠⠈
‎‏‏‎‏‏‎⠌⢊⢂⢣⠹⣿⣿⣿⣿⣿⣿⣿⣿⣧⢐⢕⢕⢕⢕⢕⢅⣿⣿⣿⣿⡿⢋⢜⠠⠈
‎‏‏‎‏‏‎⠄⠁⠕⢝⡢⠈⠻⣿⣿⣿⣿⣿⣿⣿⣷⣕⣑⣑⣑⣵⣿⣿⣿⡿⢋⢔⢕⣿⠠⠈
‎‏‏‎‏‏‎⠨⡂⡀⢑⢕⡅⠂⠄⠉⠛⠻⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢋⢔⢕⢕⣿⣿⠠⠈
‎‏‏‎‏‏‎⠄⠪⣂⠁⢕⠆⠄⠂⠄⠁⡀⠂⡀⠄⢈⠉⢍⢛⢛⢛⢋⢔⢕⢕⢕⣽⣿⣿⠠⠈

'@
         
                
            [string]$WhenValue41To60 = @'
  
            ⣿⡟⠙⠛⠋⠩⠭⣉⡛⢛⠫⠭⠄⠒⠄⠄⠄⠈⠉⠛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            ⣿⡇⠄⠄⠄⠄⣠⠖⠋⣀⡤⠄⠒⠄⠄⠄⠄⠄⠄⠄⠄⠄⣈⡭⠭⠄⠄⠄⠉⠙
            ⣿⡇⠄⠄⢀⣞⣡⠴⠚⠁⠄⠄⢀⠠⠄⠄⠄⠄⠄⠄⠄⠉⠄⠄⠄⠄⠄⠄⠄⠄
            ⣿⡇⠄⡴⠁⡜⣵⢗⢀⠄⢠⡔⠁⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄
            ⣿⡇⡜⠄⡜⠄⠄⠄⠉⣠⠋⠠⠄⢀⡄⠄⠄⣠⣆⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸
            ⣿⠸⠄⡼⠄⠄⠄⠄⢰⠁⠄⠄⠄⠈⣀⣠⣬⣭⣛⠄⠁⠄⡄⠄⠄⠄⠄⠄⢀⣿
            ⣏⠄⢀⠁⠄⠄⠄⠄⠇⢀⣠⣴⣶⣿⣿⣿⣿⣿⣿⡇⠄⠄⡇⠄⠄⠄⠄⢀⣾⣿
            ⣿⣸⠈⠄⠄⠰⠾⠴⢾⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⢁⣾⢀⠁⠄⠄⠄⢠⢸⣿⣿
            ⣿⣿⣆⠄⠆⠄⣦⣶⣦⣌⣿⣿⣿⣿⣷⣋⣀⣈⠙⠛⡛⠌⠄⠄⠄⠄⢸⢸⣿⣿
            ⣿⣿⣿⠄⠄⠄⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⠈⠄⠄⠄⠄⠄⠈⢸⣿⣿
            ⣿⣿⣿⠄⠄⠄⠘⣿⣿⣿⡆⢀⣈⣉⢉⣿⣿⣯⣄⡄⠄⠄⠄⠄⠄⠄⠄⠈⣿⣿
            ⣿⣿⡟⡜⠄⠄⠄⠄⠙⠿⣿⣧⣽⣍⣾⣿⠿⠛⠁⠄⠄⠄⠄⠄⠄⠄⠄⠃⢿⣿
            ⣿⡿⠰⠄⠄⠄⠄⠄⠄⠄⠄⠈⠉⠩⠔⠒⠉⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠐⠘⣿
            ⣿⠃⠃⠄⠄⠄⠄⠄⠄⣀⢀⠄⠄⡀⡀⢀⣤⣴⣤⣤⣀⣀⠄⠄⠄⠄⠄⠄⠁⢹

'@
                
                
                
            [string]$WhenValue61To80 = @'
                
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⡷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⡿⠋⠈⠻⣮⣳⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣾⡿⠋⠀⠀⠀⠀⠙⣿⣿⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣿⡿⠟⠛⠉⠀⠀⠀⠀⠀⠀⠀⠈⠛⠛⠿⠿⣿⣷⣶⣤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣾⡿⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠻⠿⣿⣶⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⣀⣠⣤⣤⣀⡀⠀⠀⣀⣴⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⣿⣷⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣄⠀⠀
                ⢀⣤⣾⡿⠟⠛⠛⢿⣿⣶⣾⣿⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⣿⣷⣦⣀⣀⣤⣶⣿⡿⠿⢿⣿⡀⠀
                ⣿⣿⠏⠀⢰⡆⠀⠀⠉⢿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⢿⡿⠟⠋⠁⠀⠀⢸⣿⠇⠀
                ⣿⡟⠀⣀⠈⣀⡀⠒⠃⠀⠙⣿⡆⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠇⠀
                ⣿⡇⠀⠛⢠⡋⢙⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀
                ⣿⣧⠀⠀⠀⠓⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⠋⠀⠀⢸⣧⣤⣤⣶⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⡿⠀⠀
                ⣿⣿⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠻⣷⣶⣶⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⠁⠀⠀
                ⠈⠛⠻⠿⢿⣿⣷⣶⣦⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⡏⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠻⠿⢿⣿⣷⣶⣦⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣿⡄⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠙⠛⠻⠿⢿⣿⣷⣶⣦⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⡄⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠛⠿⠿⣿⣷⣶⣶⣤⣤⣀⡀⠀⠀⠀⢀⣴⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⡿⣄
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠛⠿⠿⣿⣷⣶⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣹
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠀⠀⠀⠀⠀⠀⢸⣧
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣆⠀⠀⠀⠀⠀⠀⢀⣀⣠⣤⣶⣾⣿⣿⣿⣿⣤⣄⣀⡀⠀⠀⠀⣿
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⢿⣻⣷⣶⣾⣿⣿⡿⢯⣛⣛⡋⠁⠀⠀⠉⠙⠛⠛⠿⣿⣿⡷⣶⣿
                
'@
                
                
            [string]$WhenValue81To88 = @'
                
                ⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠔⠶⠒⠉⠈⠸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠪⣦⢄⣀⡠⠁⠀⠀⠀⠀⠀⠀⠀⢀⣀⣠⣤⣤⣤⣤⣤⣄⣀⣀⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠈⠉⠀⠀⠀⣰⣶⣶⣦⠶⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠉⠉⢷⡔⠒⠚⢽⠃⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣰⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⢅⢰⣾⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⣀⡴⠞⠛⠉⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣧⠀⠀⠀⠀⠀
                ⠀⣀⣀⣤⣤⡞⠋⠀⠀⠀⢠⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⡇⠀⠀⠀⠀
                ⢸⡏⠉⣴⠏⠀⠀⠀⠀⠀⢸⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀
                ⠈⣧⢰⠏⠀⠀⠀⠀⠀⠀⢸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠰⠯⠥⠠⠒⠄⠀⠀⠀⠀⠀⠀⢠⠀⣿⠀⠀⠀⠀
                ⠀⠈⣿⠀⠀⠀⠀⠀⠀⠀⠈⡧⢀⢻⠿⠀⠲⡟⣞⠀⠀⠀⠀⠈⠀⠁⠀⠀⠀⠀⠀⢀⠆⣰⠇⠀⠀⠀⠀
                ⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⣧⡀⠃⠀⠀⠀⠱⣼⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⣂⡴⠋⠀⣀⡀⠀⠀
                ⠀⠀⢹⡄⠀⠀⠀⠀⠀⠀⠀⠹⣜⢄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠒⠒⠿⡻⢦⣄⣰⠏⣿⠀⠀
                ⠀⠀⠀⢿⡢⡀⠀⠀⠀⠀⠀⠀⠙⠳⢮⣥⣤⣤⠶⠖⠒⠛⠓⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⢌⢻⣴⠏⠀⠀
                ⠀⠀⠀⠀⠻⣮⣒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⣤⣀⣀⣀⣤⡴⠖⠛⢻⡆⠀⠀⠀⠀⠀⠀⢣⢻⡄⠀⠀
                ⠀⠀⠀⠀⠀⠀⠉⠛⠒⠶⠶⡶⢶⠛⠛⠁⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⠞⠁⠀⠀⠀⠀⠀⠀⠈⢜⢧⣄⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠃⠇⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠉⢻⠀⠀⠀⠀⠀⠀⠀⢀⣀⠀⠀⠉⠈⣷
                ⠀⠀⠀⠀⠀⠀⠀⣼⠟⠷⣿⣸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠲⠶⢶⣶⠶⠶⢛⣻⠏⠙⠛⠛⠛⠁
                ⠀⠀⠀⠀⠀⠀⠀⠈⠷⣤⣀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠉⠛⠓⠚⠋⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⣟⡂⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢹⡟⡟⢻⡟⠛⢻⡄⠀⠀⣸⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⡄⠀⠀⠀⠈⠷⠧⠾⠀⠀⠀⠻⣦⡴⠏⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠁⠀⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                
'@
                
                
            [string]$WhenValueAbove88 = @'
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⢠⣶⣶⣶⣦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⠟⠛⢿⣶⡄⠀⢀⣀⣤⣤⣦⣤⡀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⢠⣿⠋⠀⠀⠈⠙⠻⢿⣶⣶⣶⣶⣶⣶⣶⣿⠟⠀⠀⠀⠀⠹⣿⡿⠟⠋⠉⠁⠈⢻⣷⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⣼⡧⠀⠀⠀⠀⠀⠀⠀⠉⠁⠀⠀⠀⠀⣾⡏⠀⠀⢠⣾⢶⣶⣽⣷⣄⡀⠀⠀⠀⠈⣿⡆⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⢸⣧⣾⠟⠉⠉⠙⢿⣿⠿⠿⠿⣿⣇⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⢸⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣷⣄⣀⣠⣼⣿⠀⠀⠀⠀⣸⣿⣦⡀⠀⠈⣿⡄⠀⠀⠀
                ⠀⠀⠀⠀⠀⢠⣾⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠉⠻⣷⣤⣤⣶⣿⣧⣿⠃⠀⣰⣿⠁⠀⠀⠀
                ⠀⠀⠀⠀⠀⣾⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠹⣿⣀⠀⠀⣀⣴⣿⣧⠀⠀⠀⠀
                ⠀⠀⠀⠀⢸⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⠿⠿⠛⠉⢸⣿⠀⠀⠀⠀
                ⢀⣠⣤⣤⣼⣿⣤⣄⠀⠀⠀⡶⠟⠻⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣶⣶⡄⠀⠀⠀⠀⢀⣀⣿⣄⣀⠀⠀
                ⠀⠉⠉⠉⢹⣿⣩⣿⠿⠿⣶⡄⠀⠀⠀⠀⠀⠀⠀⢀⣤⠶⣤⡀⠀⠀⠀⠀⠀⠿⡿⠃⠀⠀⠀⠘⠛⠛⣿⠋⠉⠙⠃
                ⠀⠀⠀⣤⣼⣿⣿⡇⠀⠀⠸⣿⠀⠀⠀⠀⠀⠀⠀⠘⠿⣤⡼⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣼⣿⣀⠀⠀⠀
                ⠀⠀⣾⡏⠀⠈⠙⢧⠀⠀⠀⢿⣧⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⠟⠙⠛⠓⠀
                ⠀⠀⠹⣷⡀⠀⠀⠀⠀⠀⠀⠈⠉⠙⠻⣷⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⣶⣿⣯⡀⠀⠀⠀⠀
                ⠀⠀⠀⠈⠻⣷⣄⠀⠀⠀⢀⣴⠿⠿⠗⠈⢻⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣾⠟⠋⠉⠛⠷⠄⠀⠀
                ⠀⠀⠀⠀⠀⢸⡏⠀⠀⠀⢿⣇⠀⢀⣠⡄⢘⣿⣶⣶⣤⣤⣤⣤⣀⣤⣤⣤⣤⣶⣶⡿⠿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠘⣿⡄⠀⠀⠈⠛⠛⠛⠋⠁⣼⡟⠈⠻⣿⣿⣿⣿⡿⠛⠛⢿⣿⣿⣿⣡⣾⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠙⢿⣦⣄⣀⣀⣀⣀⣴⣾⣿⡁⠀⠀⠀⡉⣉⠁⠀⠀⣠⣾⠟⠉⠉⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠛⠛⠛⠛⠉⠀⠹⣿⣶⣤⣤⣷⣿⣧⣴⣾⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠻⢦⣭⡽⣯⣡⡴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                
'@
            #Endregion ASCII-Arts

            # Total number of Compliant values not equal to N/A 
            [int]$TotalNumberOfTrueCompliantValues = 232
                  
            switch ($True) {
                    ($TotalTrueCompliantValuesInOutPut -in 1..40) { & $WriteRainbow2 "$WhenValue1To20`nYour compliance score is $TotalTrueCompliantValuesInOutPut out of $TotalNumberOfTrueCompliantValues!" }                    
                    ($TotalTrueCompliantValuesInOutPut -in 41..80) { & $WriteRainbow1 "$WhenValue21To40`nYour compliance score is $TotalTrueCompliantValuesInOutPut out of $TotalNumberOfTrueCompliantValues!" }
                    ($TotalTrueCompliantValuesInOutPut -in 81..120) { & $WriteRainbow1 "$WhenValue41To60`nYour compliance score is $TotalTrueCompliantValuesInOutPut out of $TotalNumberOfTrueCompliantValues!" }
                    ($TotalTrueCompliantValuesInOutPut -in 121..160) { & $WriteRainbow2 "$WhenValue61To80`nYour compliance score is $TotalTrueCompliantValuesInOutPut out of $TotalNumberOfTrueCompliantValues!" }
                    ($TotalTrueCompliantValuesInOutPut -in 161..200) { & $WriteRainbow1 "$WhenValue81To88`nYour compliance score is $TotalTrueCompliantValuesInOutPut out of $TotalNumberOfTrueCompliantValues!" }
                    ($TotalTrueCompliantValuesInOutPut -gt 200) { & $WriteRainbow2 "$WhenValueAbove88`nYour compliance score is $TotalTrueCompliantValuesInOutPut out of $TotalNumberOfTrueCompliantValues!" }
            } 
        }
    
    } # End of Process Block

    end {
        # Clean up
        Remove-Item -Path '.\security_policy.inf' -Force
    }

    <#
.SYNOPSIS
Checks the compliance of a system with the Harden Windows Security script guidelines

.LINK
https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden%E2%80%90Windows%E2%80%90Security%E2%80%90Module

.DESCRIPTION
Checks the compliance of a system with the Harden Windows Security script. Checks the applied Group policies, registry keys and PowerShell cmdlets used by the hardening script.

.COMPONENT
Gpresult, Secedit, PowerShell, Registry

.FUNCTIONALITY
Uses Gpresult and Secedit to first export the effective Group policies and Security policies, then goes through them and checks them against the Harden Windows Security's guidelines.

.EXAMPLE
($result.Microsoft Defender | Where-Object {$_.name -eq 'Controlled Folder Access Exclusions'}).value.programs

# Do this to get the Controlled Folder Access Programs list when using ShowAsObjectsOnly optional parameter to output an object

.EXAMPLE
$result.Microsoft Defender

# Do this to only see the result for the Microsoft Defender category when using ShowAsObjectsOnly optional parameter to output an object

.PARAMETER ExportToCSV
Export the output to a CSV file in the current working directory

.PARAMETER ShowAsObjectsOnly
Returns a nested object instead of writing strings on the PowerShell console, it can be assigned to a variable

.PARAMETER DetailedDisplay
Shows the output on the PowerShell console with more details and in the list format instead of table format

#>    

}

# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
