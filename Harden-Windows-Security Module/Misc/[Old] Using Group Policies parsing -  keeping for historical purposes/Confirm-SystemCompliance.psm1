# To parse the ini file from the output of the "secedit /export /cfg c:\\security_policy.inf"
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

# Main function that also parses the output of "gpresult /Scope Computer /x GPResult.xml"
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

        Write-Progress -Activity 'Starting' -Status 'Processing...' -PercentComplete 5

        # Make sure the latest version of the module is installed and if not, automatically update it, clean up any old versions
        function Update-self {
            [version]$CurrentVersion = (Test-modulemanifest "$psscriptroot\Harden-Windows-Security-Module.psd1" -ErrorAction Stop).Version

            try {
                [version]$LatestVersion = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/version.txt'
            }
            catch {
                Write-Error -Message "Couldn't verify if the latest version of the module is installed, please check your Internet connection." -ErrorAction Stop
            }

            if ($CurrentVersion -lt $LatestVersion) {
                Write-Output "$($PSStyle.Foreground.FromRGB(255,105,180))The currently installed module's version is $CurrentVersion while the latest version is $LatestVersion - Auto Updating the module... 💓$($PSStyle.Reset)"
                Remove-Module -Name 'Harden-Windows-Security-Module' -Force
                # Do this if the module was installed properly using Install-moodule cmdlet
                try {
                    Uninstall-Module -Name 'Harden-Windows-Security-Module' -AllVersions -Force -ErrorAction Stop
                    Install-Module -Name 'Harden-Windows-Security-Module' -RequiredVersion $LatestVersion -Force -ErrorAction Stop
                    Import-Module -Name 'Harden-Windows-Security-Module' -RequiredVersion $LatestVersion -Force -Global -ErrorAction Stop
                }
                # Do this if module files/folder was just copied to Documents folder and not properly installed - Should rarely happen
                catch {
                    Install-Module -Name 'Harden-Windows-Security-Module' -RequiredVersion $LatestVersion -Force -ErrorAction Stop
                    Import-Module -Name 'Harden-Windows-Security-Module' -RequiredVersion $LatestVersion -Force -Global -ErrorAction Stop
                }
                # Make sure the old version isn't run after update
                Write-Output "$($PSStyle.Foreground.FromRGB(152,255,152))Update successful, please run the Confirm-SystemCompliance cmdlet again.$($PSStyle.Reset)"
                break
                return
            }
        }

        # Make sure this cmdlet is invoked with Admin privileges
        if (![bool]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Error -Message 'Confirm-SystemCompliance cmdlet requires Administrator privileges.' -ErrorAction Stop
        }

        Write-Progress -Activity 'Checking for updates' -Status 'Processing...' -PercentComplete 10

        # Self update the module
        Update-self -ErrorAction Stop

        # Stop operation as soon as there is an error anywhere, unless explicitly specified otherwise
        $ErrorActionPreference = 'SilentlyContinue'

        Write-Progress -Activity 'Gathering Security Policy Information' -Status 'Processing...' -PercentComplete 15

        Secedit /export /cfg .\security_policy.inf | Out-Null
        # Storing the output of the ini file parsing function
        [PSCustomObject]$SecurityPoliciesIni = ConvertFrom-IniFile -IniFile .\security_policy.inf

        Write-Progress -Activity 'Downloading Registry CSV File from GitHub or Azure DevOps' -Status 'Processing...' -PercentComplete 20

        # Download Registry CSV file from GitHub or Azure DevOps
        try {
            Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Payload/Registry.csv' -OutFile '.\Registry.csv' -ErrorAction Stop
        }
        catch {
            Write-Host 'Using Azure DevOps...' -ForegroundColor Yellow
            Invoke-WebRequest -Uri 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/Payload/Registry.csv' -OutFile '.\Registry.csv' -ErrorAction Stop
        }
        # Import the registry.csv file as CSV
        [PSCustomObject]$CSVFileContent = Import-Csv -Path '.\Registry.csv'

        Write-Progress -Activity 'Downloading Group-Policies.json file from GitHub' -Status 'Processing...' -PercentComplete 25

        # Download Group-Policies.json file from GitHub
        try {
            Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Payload/Group-Policies.json' -OutFile ".\Group-Policies.json" -ErrorAction Stop
        }
        catch {
            Write-Error -Message "Group-Policies.json file couldn't be downloaded, exitting..."
        }
        # Hash table to store Hardening Script's Policy Categories and Names
        # Importing it from the JSON file as hashtable
        [System.Collections.Hashtable]$HashPol = Get-Content -Path '.\Group-Policies.json' -ErrorAction Stop | ConvertFrom-Json -Depth 100 -AsHashtable -ErrorAction Stop

        Write-Progress -Activity 'Gathering Group Policy Information' -Status 'Processing...' -PercentComplete 30

        Gpresult /Scope Computer /x .\GPResult.xml /f
        # Load the xml file into a variable
        [System.Xml.XmlDocument]$GroupPolicyXmlContent = Get-Content -Path .\GPResult.xml -ErrorAction Stop


        # An array to store each Group Policy "<q6:Policy>" element as a separate object
        [System.Array]$PoliciesOutput = @()
        # Use dot notation to access the Group Policy elements
        $GroupPolicyXmlContent.Rsop.ComputerResults.ExtensionData.Extension.Policy | Where-Object { $null -ne $_.name } | ForEach-Object {
            # All the sub-elements of the "<q6:Policy>" that we need to verify
            $PoliciesOutput += [PSCustomObject]@{
                Name                 = $_.Name
                State                = $_.State
                Category             = $_.Category
                DropDownListName     = $_.DropDownList.Name
                DropDownListState    = $_.DropDownList.State
                DropDownListValue    = $_.DropDownList.Value.Name
                CheckboxName         = $_.Checkbox.Name
                CheckboxState        = $_.Checkbox.State
                Numeric              = $_.Numeric
                NumericName          = $_.Numeric.Name
                NumericState         = $_.Numeric.State
                NumericValue         = $_.Numeric.Value
                ListBox              = $_.ListBox
                ListBoxName          = $_.ListBox.Name
                ListBoxState         = $_.ListBox.State
                ListBoxExplicitValue = $_.ListBox.ExplicitValue
                ListBoxAdditive      = $_.ListBox.Additive
                ListBoxValue         = $_.ListBox.Value
                MultiTextName        = $_.MultiText.Name
                MultiTextState       = $_.MultiText.State
                MultiTextValue       = $_.MultiText.Value
                EditTextName         = $_.EditText.Name
                EditTextState        = $_.EditText.State
                EditTextValue        = $_.EditText.Value
            }
        }


        # An array to store Group Policy Firewall settings as an object
        [System.Array]$FirewallPoliciesOutput = @()
        # Use dot notation to access the Group Policy elements - sometimes the type is q4 or q3 or q7, so using wildcard for the number
        [System.Xml.XmlLinkedNode]$FirewallGroupPolicySettings = $GroupPolicyXmlContent.Rsop.ComputerResults.ExtensionData.Extension | Where-Object { $_.type -like 'q*:WindowsFirewallSettings' }

        $FirewallPoliciesOutput += [PSCustomObject]@{

            GlobalSettingsPolicyVersion      = $FirewallGroupPolicySettings.GlobalSettings.PolicyVersion.Value
            # Domain profile policies
            DomainDefaultInboundAction       = $FirewallGroupPolicySettings.DomainProfile.DefaultInboundAction.value
            DomainDefaultOutboundAction      = $FirewallGroupPolicySettings.DomainProfile.DefaultOutboundAction.value
            DomainDisableNotifications       = $FirewallGroupPolicySettings.DomainProfile.DisableNotifications.value
            DomainDoNotAllowExceptions       = $FirewallGroupPolicySettings.DomainProfile.DoNotAllowExceptions.value
            DomainEnableFirewall             = $FirewallGroupPolicySettings.DomainProfile.EnableFirewall.value
            DomainLogFilePath                = $FirewallGroupPolicySettings.DomainProfile.LogFilePath.value
            DomainLogFileSize                = $FirewallGroupPolicySettings.DomainProfile.LogFileSize.value
            DomainLogDroppedPackets          = $FirewallGroupPolicySettings.DomainProfile.LogDroppedPackets.value
            DomainLogSuccessfulConnections   = $FirewallGroupPolicySettings.DomainProfile.LogSuccessfulConnections.value
            # Public profile policies
            PublicAllowLocalIPsecPolicyMerge = $FirewallGroupPolicySettings.PublicProfile.AllowLocalIPsecPolicyMerge.value
            PublicAllowLocalPolicyMerge      = $FirewallGroupPolicySettings.PublicProfile.AllowLocalPolicyMerge.value
            PublicDefaultInboundAction       = $FirewallGroupPolicySettings.PublicProfile.DefaultInboundAction.value
            PublicDefaultOutboundAction      = $FirewallGroupPolicySettings.PublicProfile.DefaultOutboundAction.value
            PublicDisableNotifications       = $FirewallGroupPolicySettings.PublicProfile.DisableNotifications.value
            PublicDoNotAllowExceptions       = $FirewallGroupPolicySettings.PublicProfile.DoNotAllowExceptions.value
            PublicEnableFirewall             = $FirewallGroupPolicySettings.PublicProfile.EnableFirewall.value
            PublicLogFilePath                = $FirewallGroupPolicySettings.PublicProfile.LogFilePath.value
            PublicLogFileSize                = $FirewallGroupPolicySettings.PublicProfile.LogFileSize.value
            PublicLogDroppedPackets          = $FirewallGroupPolicySettings.PublicProfile.LogDroppedPackets.value
            PublicLogSuccessfulConnections   = $FirewallGroupPolicySettings.PublicProfile.LogSuccessfulConnections.value
            # Private profile policies
            PrivateDefaultInboundAction      = $FirewallGroupPolicySettings.PrivateProfile.DefaultInboundAction.value
            PrivateDefaultOutboundAction     = $FirewallGroupPolicySettings.PrivateProfile.DefaultOutboundAction.value
            PrivateDisableNotifications      = $FirewallGroupPolicySettings.PrivateProfile.DisableNotifications.value
            PrivateEnableFirewall            = $FirewallGroupPolicySettings.PrivateProfile.EnableFirewall.value
            PrivateLogFilePath               = $FirewallGroupPolicySettings.PrivateProfile.LogFilePath.value
            PrivateLogFileSize               = $FirewallGroupPolicySettings.PrivateProfile.LogFileSize.value
            PrivateLogDroppedPackets         = $FirewallGroupPolicySettings.PrivateProfile.LogDroppedPackets.value
            PrivateLogSuccessfulConnections  = $FirewallGroupPolicySettings.PrivateProfile.LogSuccessfulConnections.value
        }


        # An array to store each Group Policy "<q6:RegistrySetting>" element as a separate object
        [System.Array]$RegistriesOutput = @()
        # Use dot notation to access the Policy element
        $GroupPolicyXmlContent.Rsop.ComputerResults.ExtensionData.Extension.RegistrySetting | Where-Object { $null -ne $_.Value.Name } | ForEach-Object {

            $RegistriesOutput += [PSCustomObject]@{
                KeyPath = $_.KeyPath
                Name    = $_.Value.Name
                Number  = $_.Value.Number
            }
        }


        # An object to store the FINAL results
        $FinalMegaObject = [PSCustomObject]@{}

        # Hash table to store Hardening Script's Registry Policy Categories and Names
        # They are still Group Policies but instead of being in "<q6:Policy>" element they are in "<q6:RegistrySetting>"
        [System.Collections.Hashtable]$HashReg = @{
            # Device Guard
            'Device Guard' = @{
                1 = @{
                    KeyPath = 'Software\Policies\Microsoft\Windows\System'
                    Name    = 'RunAsPPL'
                }
            }
        }
    }

    process {

        #Region Microsoft-Defender-Category
        Write-Progress -Activity 'Validating Microsoft Defender Category' -Status 'Processing...' -PercentComplete 35
        # An array to store the nested custom objects (Results of the foreach loop), inside the main output object
        [System.Array]$NestedObjectArray = @()
        [String]$CatName = 'Microsoft Defender'
        # Loop through each nested hash table inside the main Policies hash table and check the item state using a switch statement
        foreach ($Key in $HashPol[$CatName].Keys) {
            # Get the correct object from the PoliciesOutput Object that contains all the group policies in the xml file
            $Item = $PoliciesOutput | Where-object { $_.Name -eq $HashPol[$CatName][$Key].Name -and $_.Category -eq $HashPol[$CatName][$Key].Cat }
            switch ($Key) {
                1 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.DropDownListState -eq 'NotConfigured') ? $True : $False  # It's actually Enabled but Gpresult shows NotConfigured!
                }
                2 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                3 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.DropDownListState -eq 'Enabled' `
                            -and $Item.DropDownListValue -eq 'Advanced MAPS') ? $True : $False
                }
                4 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.DropDownListName -eq 'Send file samples when further analysis is required' `
                            -and $Item.DropDownListState -eq 'Enabled' `
                            -and $Item.DropDownListValue -eq 'Send all samples'
                    ) ? $True : $False
                }
                5 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.DropDownListName -eq 'Configure the guard my folders feature' `
                            -and $Item.DropDownListState -eq 'NotConfigured' ` # It's actually Enabled but Gpresult shows NotConfigured!
                    ) ? $True : $False
                }
                6 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.DropDownListState -eq 'NotConfigured' # It's actually Enabled but Gpresult shows NotConfigured!
                    ) ? $True : $False
                }
                7 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.NumericName -eq 'Specify the extended cloud check time in seconds' `
                            -and $Item.NumericState -eq 'Enabled' `
                            -and $Item.NumericValue -eq '50'
                    ) ? $True : $False
                }
                8 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                9 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.DropDownListName -eq 'Select cloud blocking level' `
                            -and $Item.DropDownListState -eq 'Enabled' `
                            -and $Item.DropDownListValue -eq 'Zero tolerance blocking level'
                    ) ? $True : $False
                }
                10 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.NumericName -eq 'Configure removal of items from Quarantine folder' `
                            -and $Item.NumericState -eq 'Enabled' `
                            -and $Item.NumericValue -eq '3'
                    ) ? $True : $False
                }
                11 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.NumericName -eq 'Define the maximum size of downloaded files and attachments to be scanned' `
                            -and $Item.NumericState -eq 'Enabled' `
                            -and $Item.NumericValue -eq '10000000'
                    ) ? $True : $False
                }
                12 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                13 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                14 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                15 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                16 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.NumericName -eq 'Specify the maximum depth to scan archive files' `
                            -and $Item.NumericState -eq 'Enabled' `
                            -and $Item.NumericValue -eq '4294967295'
                    ) ? $True : $False
                }
                17 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                18 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                19 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                20 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                21 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                22 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.NumericName -eq 'Define the number of days before spyware security intelligence is considered out of date' `
                            -and $Item.NumericState -eq 'Enabled' `
                            -and $Item.NumericValue -eq '2'
                    ) ? $True : $False
                }
                23 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.NumericName -eq 'Define the number of days before virus security intelligence is considered out of date' `
                            -and $Item.NumericState -eq 'Enabled' `
                            -and $Item.NumericValue -eq '2'
                    ) ? $True : $False
                }
                24 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.NumericName -eq 'Specify the interval to check for security intelligence updates' `
                            -and $Item.NumericState -eq 'Enabled' `
                            -and $Item.NumericValue -eq '3'
                    ) ? $True : $False
                }
                25 {
                    # ListBox 1
                    $1index = $Item.ListBoxValue.element.Name.IndexOf("4")
                    # Write-Host "$1index" -ForegroundColor Yellow
                    $1ListData = $Item.ListBoxValue.element.Data[$1index]
                    # Write-Host "$1ListData" -ForegroundColor Yellow

                    # ListBox 2
                    $2index = $Item.ListBoxValue.element.Name.IndexOf("2")
                    # Write-Host "$2index" -ForegroundColor Yellow
                    $2ListData = $Item.ListBoxValue.element.Data[$2index]
                    # Write-Host "$2ListData" -ForegroundColor Yellow

                    # ListBox 3
                    $3index = $Item.ListBoxValue.element.Name.IndexOf("1")
                    # Write-Host "$3index" -ForegroundColor Yellow
                    $3ListData = $Item.ListBoxValue.element.Data[$3index]
                    # Write-Host "$3ListData" -ForegroundColor Yellow

                    # ListBox 4
                    $4index = $Item.ListBoxValue.element.Name.IndexOf("5")
                    # Write-Host "$4index" -ForegroundColor Yellow
                    $4ListData = $Item.ListBoxValue.element.Data[$4index]
                    # Write-Host "$4ListData" -ForegroundColor Yellow

                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.ListBoxName -eq 'Specify threat alert levels at which default action should not be taken when detected' `
                            -and $Item.ListBoxState -eq 'Enabled' `
                            -and $Item.ListBoxExplicitValue -eq 'true' `
                            -and $Item.ListBoxAdditive -eq 'true' `
                            -and $1ListData -eq '3' `
                            -and $2ListData -eq '2' `
                            -and $3ListData -eq '2' `
                            -and $4ListData -eq '3' `
                    ) ? $True : $False
                }
                26 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                27 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                28 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                29 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
            }

            # Create a custom object with 5 properties to store them as nested objects inside the main output object
            $NestedObjectArray += [PSCustomObject]@{
                Name      = $HashPol[$CatName][$Key].Name
                Value     = $ItemState
                Compliant = $ItemState
                Category  = $CatName
                Method    = 'Group Policy'
            }
        }

        # For PowerShell Cmdlet
        $IndividualItemResult = $((Get-MpPreference).AllowSwitchToAsyncInspection)
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'AllowSwitchToAsyncInspection'
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Cmdlet'
        }

        # For PowerShell Cmdlet
        $IndividualItemResult = $((Get-MpPreference).oobeEnableRtpAndSigUpdate)
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'oobeEnableRtpAndSigUpdate'
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Cmdlet'
        }

        # For PowerShell Cmdlet
        $IndividualItemResult = $((Get-MpPreference).IntelTDTEnabled)
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'IntelTDTEnabled'
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Cmdlet'
        }

        # For PowerShell Cmdlet
        $IndividualItemResult = $((Get-ProcessMitigation -System -ErrorAction Stop).aslr.ForceRelocateImages)
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'Mandatory ASLR'
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult -eq 'on' ? $True : $false
            Category  = $CatName
            Method    = 'Cmdlet'
        }

        # For BCDEDIT NX value verification
        # IMPORTANT: bcdedit /enum requires an ELEVATED session.
        # Answer by mklement0: https://stackoverflow.com/a/50949849
        $bcdOutput = (bcdedit /enum) -join "`n" # collect bcdedit's output as a *single* string

        # Initialize the output list.
        $entries = New-Object System.Collections.Generic.List[PSCustomObject] -ErrorAction Stop

        # Parse bcdedit's output.
    ($bcdOutput -split '(?m)^(.+\n-)-+\n' -ne '').ForEach({
                if ($_.EndsWith("`n-")) {
                    # entry header
                    $entries.Add([PSCustomObject] @{ Name = ($_ -split '\n')[0]; Properties = [ordered] @{} })
                }
                else {
                    # block of property-value lines
    ($_ -split '\n' -ne '').ForEach({
                            $propAndVal = $_ -split '\s+', 2 # split line into property name and value
                            if ($propAndVal[0] -ne '') {
                                # [start of] new property; initialize list of values
                                $currProp = $propAndVal[0]
                                $entries[-1].Properties[$currProp] = New-Object Collections.Generic.List[string] -ErrorAction Stop
                            }
                            $entries[-1].Properties[$currProp].Add($propAndVal[1]) # add the value
                        })
                }
            })

        # For PowerShell Cmdlet
        $IndividualItemResult = $(($entries | Where-Object { $_.properties.identifier -eq "{current}" }).properties.nx)
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'BCDEDIT NX Value'
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult -eq 'AlwaysOn' ? $True : $false
            Category  = $CatName
            Method    = 'Cmdlet'
        }

        # For PowerShell Cmdlet
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'Smart App Control State'
            Value     = $((Get-MpComputerStatus).SmartAppControlState)
            Compliant = 'N/A'
            Category  = $CatName
            Method    = 'Cmdlet'
        }

        # For PowerShell Cmdlet
        $IndividualItemResult = $((Get-ScheduledTask -TaskPath "\MSFT Driver Block list update\" -TaskName "MSFT Driver Block list update" -ErrorAction SilentlyContinue) ? $True : $false)
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'Fast weekly Microsoft recommended driver block list update'
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Cmdlet'
        }


        $DefenderPlatformUpdatesChannels = @{
            0 = 'NotConfigured'
            2 = 'Beta'
            3 = 'Preview'
            4 = 'Staged'
            5 = 'Broad'
            6 = 'Delayed'
        }
        # For PowerShell Cmdlet
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'Microsoft Defender Platform Updates Channel'
            Value     = $($DefenderPlatformUpdatesChannels[[int](get-mppreference).PlatformUpdatesChannel])
            Compliant = 'N/A'
            Category  = $CatName
            Method    = 'Cmdlet'
        }


        $DefenderEngineUpdatesChannels = @{
            0 = 'NotConfigured'
            2 = 'Beta'
            3 = 'Preview'
            4 = 'Staged'
            5 = 'Broad'
            6 = 'Delayed'
        }
        # For PowerShell Cmdlet
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'Microsoft Defender Engine Updates Channel'
            Value     = $($DefenderEngineUpdatesChannels[[int](get-mppreference).EngineUpdatesChannel])
            Compliant = 'N/A'
            Category  = $CatName
            Method    = 'Cmdlet'
        }

        # For PowerShell Cmdlet
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'Controlled Folder Access Exclusions'
            Value     = [PSCustomObject]@{Count = $((Get-MpPreference).ControlledFolderAccessAllowedApplications.count); Programs = $((Get-MpPreference).ControlledFolderAccessAllowedApplications) }
            Compliant = 'N/A'
            Category  = $CatName
            Method    = 'Cmdlet'
        }
        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray -ErrorAction Stop
        #EndRegion Microsoft-Defender-Category

        #Region Attack-Surface-Reduction-Rules-Category
        Write-Progress -Activity 'Validating Attack Surface Reduction Rules Category' -Status 'Processing...' -PercentComplete 40
        [System.Array]$NestedObjectArray = @()
        [String]$CatName = 'ASR'
        # Loop through each nested hash table inside the main Policies hash table and check the item state using a switch statement
        foreach ($Key in $HashPol[$CatName].Keys) {
            $Item = $PoliciesOutput | Where-object { $_.Name -eq $HashPol[$CatName][$Key].Name -and $_.Category -eq $HashPol[$CatName][$Key].Cat }
            switch ($Key) {
                1 {
                    $1index = $Item.ListBoxValue.element.Name.IndexOf('92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B')
                    $1ListData = $Item.ListBoxValue.element.Data[$1index]

                    $2index = $Item.ListBoxValue.element.Name.IndexOf('e6db77e5-3df2-4cf1-b95a-636979351e5b')
                    $2ListData = $Item.ListBoxValue.element.Data[$2index]

                    $3index = $Item.ListBoxValue.element.Name.IndexOf('d1e49aac-8f56-4280-b9ba-993a6d77406c')
                    $3ListData = $Item.ListBoxValue.element.Data[$3index]

                    $4index = $Item.ListBoxValue.element.Name.IndexOf('3b576869-a4ec-4529-8536-b80a7769e899')
                    $4ListData = $Item.ListBoxValue.element.Data[$4index]

                    $5index = $Item.ListBoxValue.element.Name.IndexOf('be9ba2d9-53ea-4cdc-84e5-9b1eeee46550')
                    $5ListData = $Item.ListBoxValue.element.Data[$5index]

                    $6index = $Item.ListBoxValue.element.Name.IndexOf('75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84')
                    $6ListData = $Item.ListBoxValue.element.Data[$6index]

                    $7index = $Item.ListBoxValue.element.Name.IndexOf('56a863a9-875e-4185-98a7-b882c64b5ce5')
                    $7ListData = $Item.ListBoxValue.element.Data[$7index]

                    $8index = $Item.ListBoxValue.element.Name.IndexOf('01443614-cd74-433a-b99e-2ecdc07bfc25')
                    $8ListData = $Item.ListBoxValue.element.Data[$8index]

                    $9index = $Item.ListBoxValue.element.Name.IndexOf('b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4')
                    $9ListData = $Item.ListBoxValue.element.Data[$9index]

                    $10index = $Item.ListBoxValue.element.Name.IndexOf('d4f940ab-401b-4efc-aadc-ad5f3c50688a')
                    $10ListData = $Item.ListBoxValue.element.Data[$10index]

                    $11index = $Item.ListBoxValue.element.Name.IndexOf('5beb7efe-fd9a-4556-801d-275e5ffc04cc')
                    $11ListData = $Item.ListBoxValue.element.Data[$11index]

                    $12index = $Item.ListBoxValue.element.Name.IndexOf('c1db55ab-c21a-4637-bb3f-a12568109d35')
                    $12ListData = $Item.ListBoxValue.element.Data[$12index]

                    $13index = $Item.ListBoxValue.element.Name.IndexOf('9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2')
                    $13ListData = $Item.ListBoxValue.element.Data[$13index]

                    $14index = $Item.ListBoxValue.element.Name.IndexOf('7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c')
                    $14ListData = $Item.ListBoxValue.element.Data[$14index]

                    $15index = $Item.ListBoxValue.element.Name.IndexOf('26190899-1602-49e8-8b27-eb1d0a1ce869')
                    $15ListData = $Item.ListBoxValue.element.Data[$15index]

                    $16index = $Item.ListBoxValue.element.Name.IndexOf('d3e037e1-3eb8-44c8-a917-57927947596d')
                    $16ListData = $Item.ListBoxValue.element.Data[$16index]

                    # Use ternary operator instead of if-else statements
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.ListBoxName -eq 'Set the state for each ASR rule:' `
                            -and $Item.ListBoxState -eq 'Enabled' `
                            -and $Item.ListBoxExplicitValue -eq 'true' `
                            -and $Item.ListBoxAdditive -eq 'true' `
                            -and $1ListData -eq 1 `
                            -and $2ListData -eq 1 `
                            -and $3ListData -eq 1 `
                            -and $4ListData -eq 1 `
                            -and $5ListData -eq 1 `
                            -and $6ListData -eq 1 `
                            -and $7ListData -eq 1 `
                            -and $8ListData -eq 1 `
                            -and $9ListData -eq 1 `
                            -and $10ListData -eq 1 `
                            -and $11ListData -eq 1 `
                            -and $12ListData -eq 1 `
                            -and $13ListData -eq 1 `
                            -and $14ListData -eq 1 `
                            -and $15ListData -eq 1 `
                            -and $16ListData -eq 1 `
                    ) ? $True : $False
                }
            }
            # Create a custom object with 5 properties to store them as nested objects inside the main output object
            $NestedObjectArray += [PSCustomObject]@{
                Name      = $HashPol[$CatName][$Key].Name
                Value     = $ItemState
                Compliant = $ItemState
                Category  = $CatName
                Method    = 'Group Policy'
            }
        }
        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray -ErrorAction Stop
        #EndRegion Attack-Surface-Reduction-Rules-Category

        #Region Bitlocker-Category
        Write-Progress -Activity 'Validating Bitlocker Category' -Status 'Processing...' -PercentComplete 45
        [System.Array]$NestedObjectArray = @()
        [String]$CatName = 'Bitlocker'


        # This PowerShell script can be used to find out if the DMA Protection is ON \ OFF.
        # The Script will show this by emitting True \ False for On \ Off respectively.

        # bootDMAProtection check - checks for Kernel DMA Protection status in System information or msinfo32
        [string]$BootDMAProtectionCheck =
        @"
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
"@
        Add-Type -TypeDefinition $BootDMAProtectionCheck
        # returns true or false depending on whether Kernel DMA Protection is on or off
        [bool]$BootDMAProtection = ([SystemInfo.NativeMethods]::BootDmaCheck()) -ne 0



        # Loop through each nested hash table inside the main Policies hash table and check the item state using a switch statement
        foreach ($Key in $HashPol[$CatName].Keys) {
            $Item = $PoliciesOutput | Where-object { $_.Name -eq $HashPol[$CatName][$Key].Name -and $_.Category -eq $HashPol[$CatName][$Key].Cat }
            switch ($Key) {
                1 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                2 {
                    $1index = $Item.DropDownListName.IndexOf('Configure TPM startup:')
                    $1DropDownState = $Item.DropDownListState[$1index]
                    $1DropDownValue = $Item.DropDownListValue[$1index]

                    $2index = $Item.DropDownListName.IndexOf('Configure TPM startup PIN:')
                    $2DropDownState = $Item.DropDownListState[$2index]
                    $2DropDownValue = $Item.DropDownListValue[$2index]

                    $3index = $Item.DropDownListName.IndexOf('Configure TPM startup key:')
                    $3DropDownState = $Item.DropDownListState[$3index]
                    $3DropDownValue = $Item.DropDownListValue[$3index]

                    $4index = $Item.DropDownListName.IndexOf('Configure TPM startup key and PIN:')
                    $4DropDownState = $Item.DropDownListState[$4index]
                    $4DropDownValue = $Item.DropDownListValue[$4index]


                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.CheckboxName -eq 'Allow BitLocker without a compatible TPM (requires a password or a startup key on a USB flash drive)' `
                            -and $Item.CheckboxState -eq 'Disabled' `
                            -and $1DropDownState -eq 'Enabled' `
                            -and $1DropDownValue -eq 'Allow TPM' `
                            -and $2DropDownState -eq 'Enabled' `
                            -and $2DropDownValue -eq 'Allow startup PIN with TPM' `
                            -and $3DropDownState -eq 'Enabled' `
                            -and $3DropDownValue -eq 'Allow startup key with TPM' `
                            -and $4DropDownState -eq 'Enabled' `
                            -and $4DropDownValue -eq 'Allow startup key and PIN with TPM' `
                    ) ? $True : $False
                }
                3 {
                    $1index = $Item.DropDownListName.IndexOf("Select the encryption method for operating system drives:")
                    $1DropDownState = $Item.DropDownListState[$1index]
                    $1DropDownValue = $Item.DropDownListValue[$1index]

                    $2index = $Item.DropDownListName.IndexOf("Select the encryption method for fixed data drives:")
                    $2DropDownState = $Item.DropDownListState[$2index]
                    $2DropDownValue = $Item.DropDownListValue[$2index]

                    $3index = $Item.DropDownListName.IndexOf("Select the encryption method for removable data drives:")
                    $3DropDownState = $Item.DropDownListState[$3index]
                    $3DropDownValue = $Item.DropDownListValue[$3index]


                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $1DropDownState -eq 'Enabled' `
                            -and $1DropDownValue -eq 'XTS-AES 256-bit' `
                            -and $2DropDownState -eq 'Enabled' `
                            -and $2DropDownValue -eq 'XTS-AES 256-bit' `
                            -and $3DropDownState -eq 'Enabled' `
                            -and $3DropDownValue -eq 'XTS-AES 256-bit'
                    ) ? $True : $False
                }
                4 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.DropDownListName -eq 'Select the encryption type:' `
                            -and $Item.DropDownListState -eq 'NotConfigured' # It's actually set to "Full Encryption" but Gpresult shows NotConfigured!
                    ) ? $True : $False
                }
                5 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.NumericName -eq 'Minimum characters:' `
                            -and $Item.NumericState -eq 'Enabled' `
                            -and $Item.NumericValue -eq '10'
                    ) ? $True : $False
                }
                6 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.DropDownListName -eq 'Select the encryption type:' `
                            -and $Item.DropDownListState -eq 'NotConfigured' # NotConfigured actually means "Full Encryption" but Gpresult reports it NotConfigured
                    ) ? $True : $False
                }
                7 {
                    [bool]$ItemState = ($Item.State -eq 'Disabled') ? $True : $False
                }
                8 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.DropDownListName -eq 'Select the encryption type:' `
                            -and $Item.DropDownListState -eq 'NotConfigured' # It's actually set to "Full Encryption" but Gpresult shows NotConfigured!
                    ) ? $True : $False
                }
                9 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                10 {
                    [bool]$ItemState = ($Item.State -eq 'Disabled') ? $True : $False
                }
                11 {
                    [bool]$ItemState = ($Item.State -eq 'Disabled') ? $True : $False
                }
                12 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                13 {
                    # Bitlocker DMA counter measure status
                    # Returns true if only either Kernel DMA protection is on and Bitlocker DMA protection if off
                    # or Kernel DMA protection is off and Bitlocker DMA protection is on
                    [bool]$ItemState = ($bootDMAProtection -xor ($Item.State -eq 'Enabled')) ? $True : $False
                }
            }

            # Create a custom object with 5 properties to store them as nested objects inside the main output object
            $NestedObjectArray += [PSCustomObject]@{
                Name      = $HashPol[$CatName][$Key].Name
                Value     = $ItemState
                Compliant = $ItemState
                Category  = $CatName
                Method    = 'Group Policy'
            }
        }

        # For PowerShell Cmdlet
        $IndividualItemResult = $($((Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Power -name HibernateEnabled).hibernateEnabled) -eq 1 ? $True : $False)
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'Hibernate enabled and set to full'
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Cmdlet'
        }
        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray -ErrorAction Stop
        #EndRegion Bitlocker-Category

        #Region TLS-Category
        Write-Progress -Activity 'Validating TLS Category' -Status 'Processing...' -PercentComplete 50
        [System.Array]$NestedObjectArray = @()
        [String]$CatName = 'TLS'
        # Loop through each nested hash table inside the main Policies hash table and check the item state using a switch statement
        foreach ($Key in $HashPol[$CatName].Keys) {
            $Item = $PoliciesOutput | Where-object { $_.Name -eq $HashPol[$CatName][$Key].Name -and $_.Category -eq $HashPol[$CatName][$Key].Cat }
            switch ($Key) {
                1 {
                    # Write-Host "$($Item.MultiTextValue.string)" -ForegroundColor Yellow
                    # Make sure the content and their exact order is present in Group Policy
                    [System.Array]$ExpectedOrderAndContent = @('nistP521', 'curve25519', 'NistP384', 'NistP256')

                    # Loop through the array and compare each element with the expected value
                    foreach ($i in 0..3) {
                        # Use a ternary operator to set the result to false and break the loop if the element does not match
                        $ItemStateAux = $Item.MultiTextValue.string[$i] -eq $ExpectedOrderAndContent[$i] ? $True :  $false
                    }
                    # Write-Host "$ItemStateAux" -ForegroundColor Red


                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.MultiTextName -eq 'ECC Curve Order:' `
                            -and $Item.MultiTextState -eq 'Enabled' `
                            -and $ItemStateAux -eq $True
                    ) ? $True : $False
                }
                2 {

                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.EditTextName -eq 'SSL Cipher Suites' `
                            -and $Item.EditTextState -eq 'Enabled' `
                            -and $Item.EditTextValue -eq 'TLS_CHACHA20_POLY1305_SHA256,TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256' # Checks the exact values and order
                    ) ? $True : $False
                }
            }
            # Create a custom object with 5 properties to store them as nested objects inside the main output object
            $NestedObjectArray += [PSCustomObject]@{
                Name      = $HashPol[$CatName][$Key].Name
                Value     = $ItemState
                Compliant = $ItemState
                Category  = $CatName
                Method    = 'Group Policy'
            }
        }


        $MatchRegistryKeys = @() # initialize the variable to false - an array that is going to hold only bool values
        foreach ($Item in $CSVFileContent) {
            if ($Item.category -eq 'TLS' -and $Item.Action -eq 'AddOrModify') {
                $path = $Item.Path
                $key = $Item.Key
                $value = $Item.value

                $regValue = Get-ItemPropertyValue -Path $path -Name $key
                # Store only boolean values in the $MatchRegistryKeys
                $MatchRegistryKeys += [bool]($regValue -eq $value)
                <#
            Testing the key's value type

    Reg Type      PS Type
    --------      -------
    REG_DWORD     System.Int32
    REG_SZ        System.String
    REG_QWORD     System.Int64
    REG_BINARY    System.Byte[]
    REG_MULTI_SZ  System.String[]
    REG_EXPAND_SZ System.String

             (Get-ItemPropertyValue -Path $path -Name $key).GetType().name -eq $type
            (Get-ItemPropertyValue -Path $path -Name $key) -is [System.Int32]

    #>
            }
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        # Make sure the boolean array doesn't contain any $false values
        $IndividualItemResult = ($MatchRegistryKeys -notcontains $false)
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'Registry Keys All correct'
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Registry Keys'
        }

        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray -ErrorAction Stop
        #EndRegion TLS-Category

        #Region LockScreen-Category
        Write-Progress -Activity 'Validating Lock Screen Category' -Status 'Processing...' -PercentComplete 55
        [System.Array]$NestedObjectArray = @()
        [String]$CatName = 'LockScreen'
        # Loop through each nested hash table inside the main Policies hash table and check the item state using a switch statement
        foreach ($Key in $HashPol[$CatName].Keys) {
            $Item = $PoliciesOutput | Where-object { $_.Name -eq $HashPol[$CatName][$Key].Name -and $_.Category -eq $HashPol[$CatName][$Key].Cat }
            switch ($Key) {
                1 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                2 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                3 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.NumericName -eq 'PIN Expiration' `
                            -and $Item.NumericState -eq 'Enabled' `
                            -and $Item.NumericValue -eq '180'
                    ) ? $True : $False
                }
                4 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.NumericName -eq 'PIN History' `
                            -and $Item.NumericState -eq 'Enabled' `
                            -and $Item.NumericValue -eq '3'
                    ) ? $True : $False
                }
                5 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                6 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.EditTextName -eq 'Exclude the following credential providers:' `
                            -and $Item.EditTextState -eq 'Enabled' `
                            -and $item.EditTextValue -eq '{60b78e88-ead8-445c-9cfd-0b87f74ea6cd},{F8A0B131-5F68-486c-8040-7E8FC3C85BB6},{8FD7E19C-3BF7-489B-A72C-846AB3678C96},{1ee7337f-85ac-45e2-a23c-37c753209769},{1b283861-754f-4022-ad47-a5eaaa618894}' ) ? $True : $False
                }
                7 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.EditTextName -eq 'Assign the following credential provider as the default credential provider:' `
                            -and $Item.EditTextState -eq 'Enabled' `
                            -and $item.EditTextValue -eq '{D6886603-9D2F-4EB2-B667-1971041FA96B}' ) ? $True : $False
                }
            }
            # Create a custom object with 5 properties to store them as nested objects inside the main output object
            $NestedObjectArray += [PSCustomObject]@{
                Name      = $HashPol[$CatName][$Key].Name
                Value     = $ItemState
                Compliant = $ItemState
                Category  = $CatName
                Method    = 'Group Policy'
            }
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs'] -eq '4,120') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'Machine inactivity limit'
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Security Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD'] -eq '4,0') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'Interactive logon: Do not require CTRL+ALT+DEL'
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Security Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\MaxDevicePasswordFailedAttempts'] -eq '4,5') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'Interactive logon: Machine account lockout threshold'
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Security Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLockedUserId'] -eq '4,4') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'Interactive logon: Display user information when the session is locked'
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Security Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayUserName'] -eq '4,1') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Interactive logon: Don't display username at sign-in"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Security Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'System Access'['LockoutBadCount'] -eq '5') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Account lockout threshold"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Security Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'System Access'['LockoutDuration'] -eq '1440') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Account lockout duration"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Security Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'System Access'['ResetLockoutCount'] -eq '1440') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Reset account lockout counter after"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Security Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName'] -eq '4,1') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Interactive logon: Don't display last signed-in"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Security Group Policy'
        }

        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray -ErrorAction Stop
        #EndRegion LockScreen-Category

        #Region User-Account-Control-Category
        Write-Progress -Activity 'Validating User Account Control Category' -Status 'Processing...' -PercentComplete 60
        [System.Array]$NestedObjectArray = @()
        [String]$CatName = "UAC"
        # Loop through each nested hash table inside the main Policies hash table and check the item state using a switch statement
        foreach ($Key in $HashPol[$CatName].Keys) {
            $Item = $PoliciesOutput | Where-object { $_.Name -eq $HashPol[$CatName][$Key].Name -and $_.Category -eq $HashPol[$CatName][$Key].Cat }
            switch ($Key) {
                1 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
            }

            # Create a custom object with 5 properties to store them as nested objects inside the main output object
            $NestedObjectArray += [PSCustomObject]@{
                Name      = $HashPol[$CatName][$Key].Name
                Value     = $ItemState
                Compliant = $ItemState
                Category  = $CatName
                Method    = 'Group Policy'
            }
        }


        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin'] -eq '4,2') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "UAC: Behavior of the elevation prompt for administrators in Admin Approval Mode"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Security Group Policy'
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

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "UAC: Behavior of the elevation prompt for standard users"
            Value     = $IndividualItemResult
            Compliant = $ConsentPromptBehaviorUserCompliance
            Category  = $CatName
            Method    = 'Security Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]($($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures'] -eq '4,1') ? $True : $False)
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'UAC: Only elevate executables that are signed and validated'
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Security Group Policy'
        }

        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray -ErrorAction Stop
        #EndRegion User-Account-Control-Category

        #Region Device-Guard-Category
        Write-Progress -Activity 'Validating Device Guard Category' -Status 'Processing...' -PercentComplete 65
        [System.Array]$NestedObjectArray = @()
        [String]$CatName = "Device Guard"
        # Loop through each nested hash table inside the main Policies hash table and check the item state using a switch statement
        foreach ($Key in $HashPol[$CatName].Keys) {
            $Item = $PoliciesOutput | Where-object { $_.Name -eq $HashPol[$CatName][$Key].Name -and $_.Category -eq $HashPol[$CatName][$Key].Cat }
            switch ($Key) {
                1 {
                    # Write-Host "$($Item.DropDownListName)" -ForegroundColor Yellow
                    # DropDown 1
                    $1index = $Item.DropDownListName.IndexOf("Select Platform Security Level:")
                    #Write-Host "$1index" -ForegroundColor Yellow

                    $1DropDownState = $Item.DropDownListState[$1index]
                    #Write-Host "$1DropDownState" -ForegroundColor Yellow

                    $1DropDownValue = $Item.DropDownListValue[$1index]
                    #Write-Host "$1DropDownValue" -ForegroundColor Yellow

                    # DropDown 2
                    $2index = $Item.DropDownListName.IndexOf("Virtualization Based Protection of Code Integrity:")
                    # Write-Host "$2index" -ForegroundColor Yellow

                    $2DropDownState = $Item.DropDownListState[$2index]
                    # Write-Host "$2DropDownState" -ForegroundColor Yellow

                    $2DropDownValue = $Item.DropDownListValue[$2index]
                    # Write-Host "$2DropDownValue" -ForegroundColor Yellow

                    # DropDown 3
                    $3index = $Item.DropDownListName.IndexOf("Credential Guard Configuration:")
                    # Write-Host "$3index" -ForegroundColor Yellow

                    $3DropDownState = $Item.DropDownListState[$3index]
                    # Write-Host "$3DropDownState" -ForegroundColor Yellow

                    $3DropDownValue = $Item.DropDownListValue[$3index]
                    # Write-Host "$3DropDownValue" -ForegroundColor Yellow

                    # DropDown 4
                    $4index = $Item.DropDownListName.IndexOf("Secure Launch Configuration:")
                    # Write-Host "$4index" -ForegroundColor Yellow

                    $4DropDownState = $Item.DropDownListState[$4index]
                    # Write-Host "$4DropDownState" -ForegroundColor Yellow

                    $4DropDownValue = $Item.DropDownListValue[$4index]
                    # Write-Host "$4DropDownValue" -ForegroundColor Yellow

                    # DropDown 5
                    $5index = $Item.DropDownListName.IndexOf("Kernel-mode Hardware-enforced Stack Protection:")
                    # Write-Host "$5index" -ForegroundColor Yellow

                    $5DropDownState = $Item.DropDownListState[$5index]
                    # Write-Host "$5DropDownState" -ForegroundColor Yellow

                    $5DropDownValue = $Item.DropDownListValue[$5index]
                    # Write-Host "$5DropDownValue" -ForegroundColor Yellow


                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $1DropDownState -eq 'Enabled' `
                            -and $1DropDownValue -eq 'Secure Boot' `
                            -and $2DropDownState -eq 'Enabled' `
                            -and $2DropDownValue -eq 'Enabled with UEFI lock' `
                            -and $Item.CheckboxName -eq 'Require UEFI Memory Attributes Table' `
                            -and $Item.CheckboxState -eq 'Disabled' `
                            -and $3DropDownState -eq 'Enabled' `
                            -and $3DropDownValue -eq 'Enabled with UEFI lock' `
                            -and $4DropDownState -eq 'Enabled' `
                            -and $4DropDownValue -eq 'Enabled' `
                            -and $5DropDownState -eq 'Enabled' `
                            -and $5DropDownValue -eq 'Enabled in enforcement mode'
                    ) ? $True : $False
                }
            }
            # Create a custom object with 5 properties to store them as nested objects inside the main output object
            $NestedObjectArray += [PSCustomObject]@{
                Name      = $HashPol[$CatName][$Key].Name
                Value     = $ItemState
                Compliant = $ItemState
                Category  = $CatName
                Method    = 'Group Policy'
            }
        }


        # Loop through each nested hash table inside the main Registeries hash table and check the item state using a switch statement
        foreach ($Key in $HashReg[$CatName].Keys) {
            # Get the correct object from the RegistriesOutput Object that contains all the group policies in the xml file
            $Item = $RegistriesOutput | Where-object { $_.Name -eq $HashReg[$CatName][$Key].Name -and $_.KeyPath -eq $HashReg[$CatName][$Key].KeyPath }
            switch ($Key) {
                1 {
                    [bool]$ItemState = ($Item.Number -eq '1') ? $True : $False
                }
            }
            # Create a custom object with 5 properties to store them as nested objects inside the main output object
            $NestedObjectArray += [PSCustomObject]@{
                Name      = $HashReg[$CatName][$Key].Name
                Value     = $ItemState
                Compliant = $ItemState
                Category  = $CatName
                Method    = 'Group Policy'
            }
        }
        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray -ErrorAction Stop
        #EndRegion Device-Guard-Category

        #Region Windows-Firewall-Category
        Write-Progress -Activity 'Validating Windows Firewall Category' -Status 'Processing...' -PercentComplete 70
        [System.Array]$NestedObjectArray = @()
        [String]$CatName = 'Windows Firewall'


        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Domain Profile Default Inbound Action"
            Value     = $FirewallPoliciesOutput.DomainDefaultInboundAction
            Compliant = [bool]($FirewallPoliciesOutput.DomainDefaultInboundAction -eq $True ? $True : $False)
            Category  = $CatName
            Method    = 'Firewall Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Domain Profile Default Outbound Action"
            Value     = $FirewallPoliciesOutput.DomainDefaultOutboundAction
            Compliant = [bool]($FirewallPoliciesOutput.DomainDefaultOutboundAction -eq $true ? $True : $False)
            Category  = $CatName
            Method    = 'Firewall Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Domain Profile Do Not Allow Exceptions"
            Value     = $FirewallPoliciesOutput.DomainDoNotAllowExceptions
            Compliant = [bool]($FirewallPoliciesOutput.DomainDoNotAllowExceptions -eq $true ? $True : $False)
            Category  = $CatName
            Method    = 'Firewall Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Domain Profile Firewall Enabled"
            Value     = $FirewallPoliciesOutput.DomainEnableFirewall
            Compliant = [bool]($FirewallPoliciesOutput.DomainEnableFirewall -eq $true ? $True : $False)
            Category  = $CatName
            Method    = 'Firewall Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Domain Profile Log File Path"
            Value     = $FirewallPoliciesOutput.DomainLogFilePath
            Compliant = [bool]($FirewallPoliciesOutput.DomainLogFilePath -eq '%systemroot%\system32\logfiles\firewall\domainfirewall.log' ? $True : $False)
            Category  = $CatName
            Method    = 'Firewall Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Domain Profile Log File Size"
            Value     = $FirewallPoliciesOutput.DomainLogFileSize
            Compliant = [bool]($FirewallPoliciesOutput.DomainLogFileSize -eq '32767' ? $True : $False)
            Category  = $CatName
            Method    = 'Firewall Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Domain Profile Log Dropped Packets"
            Value     = $FirewallPoliciesOutput.DomainLogDroppedPackets
            Compliant = [bool]($FirewallPoliciesOutput.DomainLogDroppedPackets -eq $true ? $True : $False)
            Category  = $CatName
            Method    = 'Firewall Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Domain Profile Log Successful Connections"
            Value     = $FirewallPoliciesOutput.DomainLogSuccessfulConnections
            Compliant = [bool]($FirewallPoliciesOutput.DomainLogSuccessfulConnections -eq $true ? $True : $False)
            Category  = $CatName
            Method    = 'Firewall Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Public Profile Disable Notifications"
            Value     = $FirewallPoliciesOutput.PublicDisableNotifications
            Compliant = [bool]($FirewallPoliciesOutput.PublicDisableNotifications -eq $false ? $True : $False)
            Category  = $CatName
            Method    = 'Firewall Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Public Profile Enable Firewall"
            Value     = $FirewallPoliciesOutput.PublicEnableFirewall
            Compliant = [bool]($FirewallPoliciesOutput.PublicEnableFirewall -eq $true ? $True : $False)
            Category  = $CatName
            Method    = 'Firewall Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Public Profile Log File Path"
            Value     = $FirewallPoliciesOutput.PublicLogFilePath
            Compliant = [bool]($FirewallPoliciesOutput.PublicLogFilePath -eq '%systemroot%\system32\logfiles\firewall\publicfirewall.log' ? $True : $False)
            Category  = $CatName
            Method    = 'Firewall Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Public Profile Log File Size"
            Value     = $FirewallPoliciesOutput.PublicLogFileSize
            Compliant = [bool]($FirewallPoliciesOutput.PublicLogFileSize -eq '32767' ? $True : $False)
            Category  = $CatName
            Method    = 'Firewall Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Public Profile Log Dropped Packets"
            Value     = $FirewallPoliciesOutput.PublicLogDroppedPackets
            Compliant = [bool]($FirewallPoliciesOutput.PublicLogDroppedPackets -eq $true ? $True : $False)
            Category  = $CatName
            Method    = 'Firewall Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Private Profile Disable Notifications"
            Value     = $FirewallPoliciesOutput.PrivateDisableNotifications
            Compliant = [bool]($FirewallPoliciesOutput.PrivateDisableNotifications -eq $false ? $True : $False)
            Category  = $CatName
            Method    = 'Firewall Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Private Profile Enable Firewall"
            Value     = $FirewallPoliciesOutput.PrivateEnableFirewall
            Compliant = [bool]($FirewallPoliciesOutput.PrivateEnableFirewall -eq $true ? $True : $False)
            Category  = $CatName
            Method    = 'Firewall Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Private Profile Log File Path"
            Value     = $FirewallPoliciesOutput.PrivateLogFilePath
            Compliant = [bool]($FirewallPoliciesOutput.PrivateLogFilePath -eq '%systemroot%\system32\logfiles\firewall\privatefirewall.log' ? $True : $False)
            Category  = $CatName
            Method    = 'Firewall Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Private Profile Log File Size"
            Value     = $FirewallPoliciesOutput.PrivateLogFileSize
            Compliant = [bool]($FirewallPoliciesOutput.PrivateLogFileSize -eq '32767' ? $True : $False)
            Category  = $CatName
            Method    = 'Firewall Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Private Profile Log Dropped Packets"
            Value     = $FirewallPoliciesOutput.PrivateLogDroppedPackets
            Compliant = [bool]($FirewallPoliciesOutput.PrivateLogDroppedPackets -eq $true ? $True : $False)
            Category  = $CatName
            Method    = 'Firewall Group Policy'
        }

        # Disables Multicast DNS (mDNS) UDP-in Firewall Rules for all 3 Firewall profiles - disables only 3 rules
        $RulesToDisable = get-NetFirewallRule -ErrorAction Stop |
        Where-Object { $_.RuleGroup -eq "@%SystemRoot%\system32\firewallapi.dll,-37302" -and $_.Direction -eq "inbound" }
        # Check if the number of detected rules that need to be disabled match the number of rules with the same criteria that are disabled
        $RulesTarget = $RulesToDisable | Where-Object { $_.Enabled -eq 'False' }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool](($RulesTarget.count -eq $RulesToDisable.Count) ? $True : $false)
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Firewall rules disabled for Multicast DNS (mDNS) UDP-in"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Firewall Group Policy'
        }

        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray -ErrorAction Stop
        #EndRegion Windows-Firewall-Category

        #Region Optional-Windows-Features-Category
        Write-Progress -Activity 'Validating Optional Windows Features Category' -Status 'Processing...' -PercentComplete 75
        [System.Array]$NestedObjectArray = @()
        [String]$CatName = 'Optional Windows Features'

        # Disable PowerShell v2 (needs 2 commands)
        [bool]$IndividualItemResult = ((get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction Stop).state -eq 'disabled') `
            -and [bool]((get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop).state -eq 'disabled') ? $True : $false

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "PowerShell v2 is disabled"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Optional Windows Features'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]((get-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client -ErrorAction Stop).state -eq 'disabled')
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Work Folders client is disabled"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Optional Windows Features'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]((get-WindowsOptionalFeature -Online -FeatureName Printing-Foundation-Features -ErrorAction Stop).state -eq 'disabled')
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Internet Printing Client is disabled"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Optional Windows Features'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]((get-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer -ErrorAction Stop).state -eq 'disabled')
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Windows Media Player (legacy) is disabled"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Optional Windows Features'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]((get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard -ErrorAction Stop).state -eq 'enabled')
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Microsoft Defender Application Guard is enabled"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Optional Windows Features'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]((get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -ErrorAction Stop).state -eq 'enabled')
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Windows Sandbox is enabled"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Optional Windows Features'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]((get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -ErrorAction Stop).state -eq 'enabled')
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Hyper-V is enabled"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Optional Windows Features'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]((get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -ErrorAction Stop).state -eq 'enabled')
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Virtual Machine Platform is enabled"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Optional Windows Features'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]((Get-WindowsCapability -Online -ErrorAction Stop | Where-Object { $_.Name -like '*wmic*' }).state -eq 'NotPresent')
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "WMIC is not present"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Optional Windows Features'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]((Get-WindowsCapability -Online -ErrorAction Stop | Where-Object { $_.Name -like '*Browser.InternetExplorer*' }).state -eq 'NotPresent')
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Internet Explorer mode functionality for Edge is not present"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Optional Windows Features'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]((Get-WindowsCapability -Online -ErrorAction Stop | Where-Object { $_.Name -like '*Microsoft.Windows.Notepad.System*' }).state -eq 'NotPresent')
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Legacy Notepad is not present"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Optional Windows Features'
        }

        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray -ErrorAction Stop
        #EndRegion Optional-Windows-Features-Category

        #Region Windows-Networking-Category
        Write-Progress -Activity 'Validating Windows Networking Category' -Status 'Processing...' -PercentComplete 80
        [System.Array]$NestedObjectArray = @()
        [String]$CatName = "Windows Networking"
        # Loop through each nested hash table inside the main Policies hash table and check the item state using a switch statement
        foreach ($Key in $HashPol[$CatName].Keys) {
            $Item = $PoliciesOutput | Where-object { $_.Name -eq $HashPol[$CatName][$Key].Name -and $_.Category -eq $HashPol[$CatName][$Key].Cat }
            switch ($Key) {
                1 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                2 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                3 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.DropDownListName -eq 'Configure NetBIOS options:' `
                            -and $Item.DropDownListState -eq 'Enabled' `
                            -and $Item.DropDownListValue -eq 'Disable NetBIOS name resolution'
                    ) ? $True : $False
                }
                4 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                5 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
            }
            # Create a custom object with 5 properties to store them as nested objects inside the main output object
            $NestedObjectArray += [PSCustomObject]@{
                Name      = $HashPol[$CatName][$Key].Name
                Value     = $ItemState
                Compliant = $ItemState
                Category  = $CatName
                Method    = 'Group Policy'
            }
        }


        # Check network location of all connections to see if they are public
        $Condition = Get-NetConnectionProfile -ErrorAction Stop | ForEach-Object { $_.NetworkCategory -eq 'public' }
        [bool]$IndividualItemResult = -not ($condition -contains $false) ? $True : $false

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Network Location of all connections set to Public"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Cmdlet'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "EnableLMHOSTS") -eq '0')
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Disable LMHOSTS lookup protocol on all network adapters"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = "Registry Key"
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'Registry Values'['MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine'] -eq '7,') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'Network access: Remotely accessible registry paths'
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Security Group Policy'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]$($SecurityPoliciesIni.'Registry Values'['MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine'] -eq '7,') ? $True : $False
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'Network access: Remotely accessible registry paths and subpaths'
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Security Group Policy'
        }

        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray -ErrorAction Stop
        #EndRegion Windows-Networking-Category

        #Region Miscellaneous-Category
        Write-Progress -Activity 'Validating Miscellaneous Category' -Status 'Processing...' -PercentComplete 85
        [System.Array]$NestedObjectArray = @()
        [String]$CatName = "Miscellaneous"
        # Loop through each nested hash table inside the main Policies hash table and check the item state using a switch statement
        foreach ($Key in $HashPol[$CatName].Keys) {
            $Item = $PoliciesOutput | Where-object { $_.Name -eq $HashPol[$CatName][$Key].Name -and $_.Category -eq $HashPol[$CatName][$Key].Cat }
            switch ($Key) {
                1 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.DropDownListState -eq 'Enabled' `
                            -and $Item.DropDownListValue -eq 'Send optional diagnostic data'
                    ) ? $True : $False
                }
                2 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                3 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                4 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                5 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                6 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.DropDownListName -eq 'Choose the boot-start drivers that can be initialized:' `
                            -and $Item.DropDownListState -eq 'Enabled' `
                            -and $Item.DropDownListValue -eq 'Good only'
                    ) ? $True : $False
                }
                7 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                8 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                9 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.DropDownListName -eq 'RPC Runtime Unauthenticated Client Restriction to Apply:' `
                            -and $Item.DropDownListState -eq 'Enabled' `
                            -and $Item.DropDownListValue -eq 'Authenticated without exceptions'
                    ) ? $True : $False
                }
                10 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $Item.DropDownListName -eq 'Mitigation Options' `
                            -and $Item.DropDownListState -eq 'Enabled' `
                            -and $Item.DropDownListValue -eq 'Block untrusted fonts and log events'
                    ) ? $True : $False
                }
            }
            # Create a custom object with 5 properties to store them as nested objects inside the main output object
            $NestedObjectArray += [PSCustomObject]@{
                Name      = $HashPol[$CatName][$Key].Name
                Value     = $ItemState
                Compliant = $ItemState
                Category  = $CatName
                Method    = 'Group Policy'
            }
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]((Get-SmbServerConfiguration -ErrorAction Stop).encryptdata)
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "SMB Encryption"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Cmdlet'
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool](((auditpol /get /subcategory:"Other Logon/Logoff Events" /r | ConvertFrom-Csv -ErrorAction Stop).'Inclusion Setting' -eq 'Success and Failure') ? $True : $False)
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Audit policy for Other Logon/Logoff Events"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Cmdlet'
        }


        # Checking if all user accounts are part of the Hyper-V security Group
        # Get all the enabled user accounts
        [string[]]$enabledUsers = (Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled -eq 'True' }).Name | Sort-Object
        # Get the members of the Hyper-V Administrators security group using their SID
        [string[]]$groupMembers = (Get-LocalGroupMember -SID 'S-1-5-32-578' -ErrorAction Stop).Name -replace "$($env:COMPUTERNAME)\\" | Sort-Object

        # Set the $MatchHyperVUsers variable to $True only if all enabled user accounts are part of the Hyper-V Security group, if one of them isn't part of the group then returns false
        [bool]$MatchHyperVUsers = $false # initialize the $MatchHyperVUsers variable to false
        for ($i = 0; $i -lt $enabledUsers.Count; $i++) {
            $MatchHyperVUsers = ($enabledUsers[$i] -ceq $groupMembers[$i]) ? $True : $false
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "All users are part of the Hyper-V Administrators group"
            Value     = $MatchHyperVUsers
            Compliant = $MatchHyperVUsers
            Category  = $CatName
            Method    = 'Cmdlet'
        }


        $MatchRegistryKeys = @() # initialize the variable to false - an array that is going to hold only bool values
        foreach ($Item in $CSVFileContent) {
            if ($Item.category -eq 'Miscellaneous' -and $Item.Action -eq 'AddOrModify') {
                $path = $Item.Path
                $key = $Item.Key
                $value = $Item.value

                $regValue = Get-ItemPropertyValue -Path $path -Name $key
                # Store only boolean values in the $MatchRegistryKeys
                $MatchRegistryKeys += [bool]($regValue -eq $value)
            }
        }
        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]($MatchRegistryKeys -notcontains $false)
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'Registry Keys All correct'
            # Make sure the boolean array doesn't contain any $false values
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Registry Keys'
        }

        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray -ErrorAction Stop
        #EndRegion Miscellaneous-Category

        #Region Windows-Update-Category
        Write-Progress -Activity 'Validating Windows Update Category' -Status 'Processing...' -PercentComplete 90
        [System.Array]$NestedObjectArray = @()
        [String]$CatName = 'Windows Update'
        # Loop through each nested hash table inside the main Policies hash table and check the item state using a switch statement
        foreach ($Key in $HashPol[$CatName].Keys) {
            $Item = $PoliciesOutput | Where-object { $_.Name -eq $HashPol[$CatName][$Key].Name -and $_.Category -eq $HashPol[$CatName][$Key].Cat }
            switch ($Key) {
                1 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                2 {
                    [bool]$ItemState = ($Item.State -eq 'Enabled') ? $True : $False
                }
                3 {
                    # 2 Check boxes with the same name exists, but both of their States and Values are the same that's why this works
                    $1index = $Item.DropDownListName.IndexOf("Deadline (days):")
                    $1DropDownState = $Item.DropDownListState[$1index]
                    $1DropDownValue = $Item.DropDownListValue[$1index]

                    $2index = $Item.DropDownListName.IndexOf("Grace period (days):")
                    $2DropDownState = $Item.DropDownListState[$2index]
                    $2DropDownValue = $Item.DropDownListValue[$2index]


                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $1DropDownState -eq 'Enabled' `
                            -and $1DropDownValue -eq '0' `
                            -and $2DropDownState -eq 'Enabled' `
                            -and $2DropDownValue -eq '1' `
                            -and $Item.CheckboxName -eq "Don't auto-restart until end of grace period" `
                            -and $Item.CheckboxState -eq 'Disabled'
                    ) ? $True : $False
                }
                4 {
                    # 2 Check boxes with the same name exists, but both of their States and Values are the same that's why this works
                    $1index = $Item.DropDownListName.IndexOf('Configure automatic updating:')
                    $1DropDownState = $Item.DropDownListState[$1index]
                    $1DropDownValue = $Item.DropDownListValue[$1index]

                    $2index = $Item.CheckboxName.IndexOf('Install during automatic maintenance')
                    $2CheckBoxState = $Item.CheckboxState[$2index]

                    $3index = $Item.DropDownListName.IndexOf('Scheduled install day: ') # Has an extra space in the xml!
                    $3DropDownState = $Item.DropDownListState[$3index]
                    $3DropDownValue = $Item.DropDownListValue[$3index]

                    $4index = $Item.DropDownListName.IndexOf('Scheduled install time:')
                    $4DropDownState = $Item.DropDownListState[$4index]
                    $4DropDownValue = $Item.DropDownListValue[$4index]

                    $5index = $Item.CheckboxName.IndexOf('Every week')
                    $5CheckBoxState = $Item.CheckboxState[$5index]

                    $6index = $Item.CheckboxName.IndexOf('First week of the month')
                    $6CheckBoxState = $Item.CheckboxState[$6index]

                    $7index = $Item.CheckboxName.IndexOf('Second week of the month')
                    $7CheckBoxState = $Item.CheckboxState[$7index]

                    $8index = $Item.CheckboxName.IndexOf('Third week of the month')
                    $8CheckBoxState = $Item.CheckboxState[$8index]

                    $9index = $Item.CheckboxName.IndexOf('Fourth week of the month')
                    $9CheckBoxState = $Item.CheckboxState[$9index]

                    $10index = $Item.CheckboxName.IndexOf('Install updates for other Microsoft products')
                    $10CheckBoxState = $Item.CheckboxState[$10index]


                    [bool]$ItemState = ($Item.State -eq 'Enabled' `
                            -and $1DropDownState -eq 'Enabled' `
                            -and $1DropDownValue -eq '4 - Auto download and schedule the install' `
                            -and $2CheckBoxState -eq 'Enabled' `
                            -and $3DropDownState -eq 'Enabled' `
                            -and $3DropDownValue -eq '0 - Every day' `
                            -and $4DropDownState -eq 'Enabled' `
                            -and $4DropDownValue -eq 'Automatic' `
                            -and $5CheckBoxState -eq 'Disabled' `
                            -and $6CheckBoxState -eq 'Disabled' `
                            -and $7CheckBoxState -eq 'Disabled' `
                            -and $8CheckBoxState -eq 'Disabled' `
                            -and $9CheckBoxState -eq 'Disabled' `
                            -and $10CheckBoxState -eq 'Enabled' `
                    ) ? $True : $False
                }

            }
            # Create a custom object with 5 properties to store them as nested objects inside the main output object
            $NestedObjectArray += [PSCustomObject]@{
                Name      = $HashPol[$CatName][$Key].Name
                Value     = $ItemState
                Compliant = $ItemState
                Category  = $CatName
                Method    = 'Group Policy'
            }
        }

        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        $IndividualItemResult = [bool]((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "RestartNotificationsAllowed2") -eq '1')
        $NestedObjectArray += [PSCustomObject]@{
            Name      = "Enable restart notification for Windows update"
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = "Registry Key"
        }

        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray -ErrorAction Stop
        #EndRegion Windows-Update-Category

        #Region Edge-Category
        Write-Progress -Activity 'Validating Edge Browser Category' -Status 'Processing...' -PercentComplete 95
        [System.Array]$NestedObjectArray = @()
        [String]$CatName = "Edge"
        $MatchRegistryKeys = @() # initialize the variable to false - an array that is going to hold only bool values
        foreach ($Item in $CSVFileContent) {
            if ($Item.category -eq 'Edge' -and $Item.Action -eq 'AddOrModify') {
                $path = $Item.Path
                $key = $Item.Key
                $value = $Item.value

                $regValue = Get-ItemPropertyValue -Path $path -Name $key
                # Store only boolean values in the $MatchRegistryKeys
                $MatchRegistryKeys += [bool]($regValue -eq $value)

            }
        }
        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        # Make sure the boolean array doesn't contain any $false values
        $IndividualItemResult = [bool]($MatchRegistryKeys -notcontains $false)
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'Registry Keys All correct'
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Registry Keys'
        }

        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray -ErrorAction Stop
        #EndRegion Edge-Category

        #Region Non-Admin-Category
        Write-Progress -Activity 'Validating Non-Admin Category' -Status 'Processing...' -PercentComplete 100
        [System.Array]$NestedObjectArray = @()
        [String]$CatName = 'Non-Admin'

        $MatchRegistryKeys = @() # initialize the variable to false - an array that is going to hold only bool values
        foreach ($Item in $CSVFileContent) {
            if ($Item.category -eq 'NonAdmin' -and $Item.Action -eq 'AddOrModify') {
                $path = $Item.Path
                $key = $Item.Key
                $value = $Item.value

                $regValue = Get-ItemPropertyValue -Path $path -Name $key
                # Store only boolean values in the $MatchRegistryKeys
                $MatchRegistryKeys += [bool]($regValue -eq $value)

            }
        }
        # Create a custom object with 5 properties to store them as nested objects inside the main output object
        # Make sure the boolean array doesn't contain any $false values
        $IndividualItemResult = ($MatchRegistryKeys -notcontains $false)
        $NestedObjectArray += [PSCustomObject]@{
            Name      = 'Registry Keys All correct'
            Value     = $IndividualItemResult
            Compliant = $IndividualItemResult
            Category  = $CatName
            Method    = 'Registry Keys'
        }

        # Add the array of custom objects as a property to the $FinalMegaObject object outside the loop
        Add-Member -InputObject $FinalMegaObject -MemberType NoteProperty -Name $CatName -Value $NestedObjectArray -ErrorAction Stop
        #EndRegion Non-Admin-Category

        if ($ExportToCSV) {

            # An array to store the content of each category
            $CsvOutPutFileContent = @()
            $CsvOutPutFileContent += $FinalMegaObject.'Microsoft Defender'
            $CsvOutPutFileContent += $FinalMegaObject.ASR
            $CsvOutPutFileContent += $FinalMegaObject.Bitlocker
            $CsvOutPutFileContent += $FinalMegaObject.TLS
            $CsvOutPutFileContent += $FinalMegaObject.LockScreen
            $CsvOutPutFileContent += $FinalMegaObject.UAC
            $CsvOutPutFileContent += $FinalMegaObject.'Device Guard'
            $CsvOutPutFileContent += $FinalMegaObject.'Windows Firewall'
            $CsvOutPutFileContent += $FinalMegaObject.'Optional Windows Features'
            $CsvOutPutFileContent += $FinalMegaObject.'Windows Networking'
            $CsvOutPutFileContent += $FinalMegaObject.Miscellaneous
            $CsvOutPutFileContent += $FinalMegaObject.'Windows Update'
            $CsvOutPutFileContent += $FinalMegaObject.Edge
            $CsvOutPutFileContent += $FinalMegaObject.'Non-Admin'
            # Convert the array to CSV and store it in the Output.CSV file in the current working directory
            $CsvOutPutFileContent | ConvertTo-Csv -ErrorAction Stop | Out-File '.\Output.CSV' -Force -ErrorAction Stop
        }

        if ($ShowAsObjectsOnly) {
            # return the main object that contains multiple nested objects
            return $FinalMegaObject
        }
        else {

            #Region Colors
            [scriptblock]$WritePlum = { Write-Output "$($PSStyle.Foreground.FromRGB(221,160,221))$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WriteOrchid = { Write-Output "$($PSStyle.Foreground.FromRGB(218,112,214))$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WriteFuchsia = { Write-Output "$($PSStyle.Foreground.FromRGB(255,0,255))$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WriteMediumOrchid = { Write-Output "$($PSStyle.Foreground.FromRGB(186,85,211))$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WriteMediumPurple = { Write-Output "$($PSStyle.Foreground.FromRGB(147,112,219))$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WriteBlueViolet = { Write-Output "$($PSStyle.Foreground.FromRGB(138,43,226))$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WriteDarkViolet = { Write-Output "$($PSStyle.Foreground.FromRGB(148,0,211))$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WritePink = { Write-Output "$($PSStyle.Foreground.FromRGB(255,192,203))$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WriteHotPink = { Write-Output "$($PSStyle.Foreground.FromRGB(255,105,180))$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WriteDeepPink = { Write-Output "$($PSStyle.Foreground.FromRGB(255,20,147))$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WriteMintGreen = { Write-Output "$($PSStyle.Foreground.FromRGB(152,255,152))$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WriteOrange = { Write-Output "$($PSStyle.Foreground.FromRGB(255,165,0))$($args[0])$($PSStyle.Reset)" }
            [scriptblock]$WriteSkyBlue = { Write-Output "$($PSStyle.Foreground.FromRGB(135,206,235))$($args[0])$($PSStyle.Reset)" }

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

                $output = ""
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

                $output = ""
                for ($i = 0; $i -lt $text.Length; $i++) {
                    $color = $colors[$i % $colors.Length]
                    $output += "$($PSStyle.Foreground.FromRGB($color.R, $color.G, $color.B))$($text[$i])$($PSStyle.Reset)"
                }
                Write-Output $output
            }
            #Endregion Colors

            # Show all properties in list
            if ($DetailedDisplay) {
                & $WritePlum "`n-------------Microsoft Defender Category-------------"
                $FinalMegaObject.'Microsoft Defender' | Format-list * -ErrorAction Stop

                & $WriteOrchid "`n-------------Attack Surface Reduction Rules Category-------------"
                $FinalMegaObject.ASR | Format-list * -ErrorAction Stop

                & $WriteFuchsia "`n-------------Bitlocker Category-------------"
                $FinalMegaObject.Bitlocker | Format-list * -ErrorAction Stop

                & $WriteMediumOrchid "`n-------------TLS Category-------------"
                $FinalMegaObject.TLS | Format-list * -ErrorAction Stop

                & $WriteMediumPurple "`n-------------Lock Screen Category-------------"
                $FinalMegaObject.LockScreen | Format-list * -ErrorAction Stop

                & $WriteBlueViolet "`n-------------User Account Control Category-------------"
                $FinalMegaObject.UAC | Format-list * -ErrorAction Stop

                & $WriteDarkViolet "`n-------------Device Guard Category-------------"
                $FinalMegaObject.'Device Guard' | Format-list * -ErrorAction Stop

                & $WritePink "`n-------------Windows Firewall Category-------------"
                $FinalMegaObject.'Windows Firewall' | Format-list * -ErrorAction Stop

                & $WriteSkyBlue "`n-------------Optional Windows Features Category-------------"
                $FinalMegaObject.'Optional Windows Features' | Format-list * -ErrorAction Stop

                & $WriteHotPink "`n-------------Windows Networking Category-------------"
                $FinalMegaObject.'Windows Networking' | Format-list * -ErrorAction Stop

                & $WriteDeepPink "`n-------------Miscellaneous Category-------------"
                $FinalMegaObject.Miscellaneous | Format-list * -ErrorAction Stop

                & $WriteMintGreen "`n-------------Windows Update Category-------------"
                $FinalMegaObject.'Windows Update' | Format-list * -ErrorAction Stop

                & $WriteOrange "`n-------------Microsoft Edge Category-------------"
                $FinalMegaObject.Edge | Format-list * -ErrorAction Stop

                & $WriteSkyBlue "`n-------------Non-Admin Category-------------"
                $FinalMegaObject.'Non-Admin' | Format-list * -ErrorAction Stop
            }

            # Show properties that matter in a table
            else {

                & $WritePlum "`n-------------Microsoft Defender Category-------------"
                $FinalMegaObject.'Microsoft Defender' | Format-Table -AutoSize -Property Name, Compliant, Value -ErrorAction Stop

                & $WriteOrchid "`n-------------Attack Surface Reduction Rules Category-------------"
                $FinalMegaObject.ASR | Format-Table -AutoSize -Property Name, Compliant, Value -ErrorAction Stop

                & $WriteFuchsia "`n-------------Bitlocker Category-------------"
                $FinalMegaObject.Bitlocker | Format-Table -AutoSize -Property Name, Compliant, Value -ErrorAction Stop

                & $WriteMediumOrchid "`n-------------TLS Category-------------"
                $FinalMegaObject.TLS | Format-Table -AutoSize -Property Name, Compliant, Value -ErrorAction Stop

                & $WriteMediumPurple "`n-------------Lock Screen Category-------------"
                $FinalMegaObject.LockScreen | Format-Table -AutoSize -Property Name, Compliant, Value -ErrorAction Stop

                & $WriteBlueViolet "`n-------------User Account Control Category-------------"
                $FinalMegaObject.UAC | Format-Table -AutoSize -Property Name, Compliant, Value -ErrorAction Stop

                & $WriteDarkViolet "`n-------------Device Guard Category-------------"
                $FinalMegaObject.'Device Guard' | Format-Table -AutoSize -Property Name, Compliant, Value -ErrorAction Stop

                & $WritePink "`n-------------Windows Firewall Category-------------"
                $FinalMegaObject.'Windows Firewall' | Format-Table -AutoSize -Property Name, Compliant, Value -ErrorAction Stop

                & $WriteSkyBlue "`n-------------Optional Windows Features Category-------------"
                $FinalMegaObject.'Optional Windows Features' | Format-Table -AutoSize -Property Name, Compliant, Value -ErrorAction Stop

                & $WriteHotPink "`n-------------Windows Networking Category-------------"
                $FinalMegaObject.'Windows Networking' | Format-Table -AutoSize -Property Name, Compliant, Value -ErrorAction Stop

                & $WriteDeepPink "`n-------------Miscellaneous Category-------------"
                $FinalMegaObject.Miscellaneous | Format-Table -AutoSize -Property Name, Compliant, Value -ErrorAction Stop

                & $WriteMintGreen "`n-------------Windows Update Category-------------"
                $FinalMegaObject.'Windows Update' | Format-Table -AutoSize -Property Name, Compliant, Value -ErrorAction Stop

                & $WriteOrange "`n-------------Microsoft Edge Category-------------"
                $FinalMegaObject.Edge | Format-Table -AutoSize -Property Name, Compliant, Value -ErrorAction Stop

                & $WriteSkyBlue "`n-------------Non-Admin Category-------------"
                $FinalMegaObject.'Non-Admin' | Format-Table -AutoSize -Property Name, Compliant, Value -ErrorAction Stop
            }

            # Counting the number of $True Compliant values in the Final Output Object
            [int]$TotalTrueValuesInOutPut = ($FinalMegaObject.'Microsoft Defender' | Where-Object { $_.Compliant -eq $True }).value.Count + `
                [int]($FinalMegaObject.ASR | Where-Object { $_.Compliant -eq $True }).value.Count + `
                [int]($FinalMegaObject.Bitlocker | Where-Object { $_.Compliant -eq $True }).value.Count + `
                [int]($FinalMegaObject.TLS | Where-Object { $_.Compliant -eq $True }).value.Count + `
                [int]($FinalMegaObject.LockScreen | Where-Object { $_.Compliant -eq $True }).value.Count + `
                [int]($FinalMegaObject.UAC | Where-Object { $_.Compliant -eq $True }).value.Count + `
                [int]($FinalMegaObject.'Device Guard' | Where-Object { $_.Compliant -eq $True }).value.Count + `
                [int]($FinalMegaObject.'Windows Firewall' | Where-Object { $_.Compliant -eq $True }).value.Count + `
                [int]($FinalMegaObject.'Optional Windows Features' | Where-Object { $_.Compliant -eq $True }).value.Count + `
                [int]($FinalMegaObject.'Windows Networking' | Where-Object { $_.Compliant -eq $True }).value.Count + `
                [int]($FinalMegaObject.Miscellaneous | Where-Object { $_.Compliant -eq $True }).value.Count + `
                [int]($FinalMegaObject.'Windows Update' | Where-Object { $_.Compliant -eq $True }).value.Count + `
                [int]($FinalMegaObject.Edge | Where-Object { $_.Compliant -eq $True }).value.Count + `
                [int]($FinalMegaObject.'Non-Admin' | Where-Object { $_.Compliant -eq $True }).value.Count


            #Region ASCII-Arts
            [string]$WhenValue1To20 = @"
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

"@


            [string]$WhenValue21To40 = @"

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

"@


            [string]$WhenValue41To60 = @"

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

"@



            [string]$WhenValue61To80 = @"

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

"@


            [string]$WhenValue81To88 = @"

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

"@


            [string]$WhenValueAbove88 = @"
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

"@
            #Endregion ASCII-Arts

            # Total number of Compliant values not equal to N/A
            [int]$TotalNumberOfTrueCompliantValues = 135

            switch ($True) {
                    ($TotalTrueValuesInOutPut -in 1..20) { & $WriteRainbow2 "$WhenValue1To20`nYour compliance score is $TotalTrueValuesInOutPut out of $TotalNumberOfTrueCompliantValues!" }
                    ($TotalTrueValuesInOutPut -in 21..40) { & $WriteRainbow1 "$WhenValue21To40`nYour compliance score is $TotalTrueValuesInOutPut out of $TotalNumberOfTrueCompliantValues!" }
                    ($TotalTrueValuesInOutPut -in 41..60) { & $WriteRainbow1 "$WhenValue41To60`nYour compliance score is $TotalTrueValuesInOutPut out of $TotalNumberOfTrueCompliantValues!" }
                    ($TotalTrueValuesInOutPut -in 61..80) { & $WriteRainbow2 "$WhenValue61To80`nYour compliance score is $TotalTrueValuesInOutPut out of $TotalNumberOfTrueCompliantValues!" }
                    ($TotalTrueValuesInOutPut -in 81..100) { & $WriteRainbow1 "$WhenValue81To88`nYour compliance score is $TotalTrueValuesInOutPut out of $TotalNumberOfTrueCompliantValues!" }
                    ($TotalTrueValuesInOutPut -gt 100) { & $WriteRainbow2 "$WhenValueAbove88`nYour compliance score is $TotalTrueValuesInOutPut out of $TotalNumberOfTrueCompliantValues!" }
            }
        }

    } # End of Process Block

    end {
        # Clean up
        Remove-Item -Path '.\security_policy.inf' -Force -ErrorAction Stop
        Remove-Item -Path '.\Registry.csv' -Force -ErrorAction Stop
        Remove-Item -Path '.\Group-Policies.json' -Force -ErrorAction Stop
        Remove-Item -Path '.\GPResult.xml' -Force -ErrorAction Stop
    }

    <#
.SYNOPSIS
Checks the compliance of a system with the Harden Windows Security script guidelines

.LINK
https://github.com/HotCakeX/Harden-Windows-Security

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
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete
