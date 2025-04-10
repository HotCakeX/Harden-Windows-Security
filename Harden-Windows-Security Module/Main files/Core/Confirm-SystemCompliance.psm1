function Confirm-SystemCompliance {
    [CmdletBinding()]
    param (
        [ArgumentCompleter({
                param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)
                $Existing = $CommandAst.FindAll(
                    {
                        $Args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    },
                    $false
                ).Value
                foreach ($Item in [Enum]::GetNames([HardenWindowsSecurity.ComplianceCategories])) {
                    if ($Item -notin $Existing) { $Item }
                }
            })]
        [ValidateScript({
                if ($_ -notin [Enum]::GetNames([HardenWindowsSecurity.ComplianceCategories])) { throw "Invalid Category Name: $_" }
                $true # Return true if everything is okay
            })]
        [System.String[]]$Categories,
        [parameter(Mandatory = $false)][Switch]$ExportToCSV,
        [parameter(Mandatory = $false)][Switch]$ShowAsObjectsOnly,
        [parameter(Mandatory = $false)][Switch]$DetailedDisplay,
        [parameter(Mandatory = $false)][Switch]$Offline
    )
    begin {
        $script:ErrorActionPreference = 'Stop'
        if (![System.Environment]::IsPrivilegedProcess) {
            Throw [System.Security.AccessControl.PrivilegeNotHeldException] 'Administrator'
        }
        try { LoadHardenWindowsSecurityNecessaryDLLsInternal } catch { Write-Verbose ([HardenWindowsSecurity.GlobalVars]::ReRunText); ReRunTheModuleAgain $MyInvocation.Statement }
        [HardenWindowsSecurity.Initializer]::Initialize($VerbosePreference)
        if (-NOT $Offline) {
            [HardenWindowsSecurity.Logger]::LogMessage('Checking for updates...', [HardenWindowsSecurity.LogTypeIntel]::Information)
            Update-HardenWindowsSecurity -InvocationStatement $MyInvocation.Statement
        }
        if ((Get-CimInstance -ClassName Win32_OperatingSystem -Verbose:$false).OperatingSystemSKU -in '101', '100') {
            Write-Warning -Message 'The Windows Home edition has been detected, many features are unavailable in this edition.'
        }
        #Region Colors
        [System.Collections.Hashtable]$global:ColorsMap = @{
            Plum         = @{ Code = '221', '160', '221'; ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(221,160,221))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" } }
            Orchid       = @{ Code = '218', '112', '214'; ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(218,112,214))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" } }
            Fuchsia      = @{ Code = '255', '0', '255'; ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(255,0,255))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" } }
            MediumOrchid = @{ Code = '186', '85', '211'; ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(186,85,211))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" } }
            MediumPurple = @{ Code = '147', '112', '219'; ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(147,112,219))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" } }
            BlueViolet   = @{ Code = '138', '43', '226'; ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(138,43,226))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" } }
            AndroidGreen = @{ Code = '176', '191', '26'; ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(176,191,26))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" } }
            Pink         = @{ Code = '255', '192', '203'; ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(255,192,203))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" } }
            HotPink      = @{ Code = '255', '105', '180'; ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(255,105,180))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" } }
            DeepPink     = @{ Code = '255', '20', '147'; ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(255,20,147))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" } }
            MintGreen    = @{ Code = '152', '255', '152'; ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(152,255,152))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" } }
            Orange       = @{ Code = '255', '165', '0'; ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(255,165,0))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" } }
            SkyBlue      = @{ Code = '135', '206', '235'; ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(135,206,235))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" } }
            Daffodil     = @{ Code = '255', '255', '49'; ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(255,255,49))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" } }
        }
        Class Colorsx : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $Colorsx = @($global:ColorsMap.Keys)
                return [System.String[]]$Colorsx
            }
        }
        [System.Drawing.Color[]]$Global:Colors = @([System.Drawing.Color]::SkyBlue, [System.Drawing.Color]::Pink, [System.Drawing.Color]::HotPink, [System.Drawing.Color]::Lavender, [System.Drawing.Color]::LightGreen, [System.Drawing.Color]::Coral, [System.Drawing.Color]::Plum, [System.Drawing.Color]::Gold)
        [System.Management.Automation.ScriptBlock]$WriteRainbow = {
            Param([System.String]$Text)
            $StringBuilder = [System.Text.StringBuilder]::new()
            for ($i = 0; $i -lt $Text.Length; $i++) {
                $Color = $Global:Colors[$i % $Global:Colors.Length]
                [System.Void]$StringBuilder.Append("$($PSStyle.Foreground.FromRGB($Color.R, $Color.G, $Color.B))$($Text[$i])$($PSStyle.Reset)")
            }
            Write-Output -InputObject $StringBuilder.ToString()
        }
        #Endregion Colors
    }
    process {
        try {
            Write-Progress -Activity 'Performing Compliance Check...' -Status 'Running' -PercentComplete 50
            [HardenWindowsSecurity.InvokeConfirmation]::Invoke($Categories)
            if ($ExportToCSV) {
                # Create an empty list to store the results based on the category order by sorting the concurrent hashtable
                $AllOrderedResults = [System.Collections.Generic.List[HardenWindowsSecurity.IndividualResult]]::new()

                $AllOrderedResults = foreach ($Key in [Enum]::GetNames([HardenWindowsSecurity.ComplianceCategories])) {
                    if (([HardenWindowsSecurity.GlobalVars]::FinalMegaObject).ContainsKey($Key)) {
                        foreach ($Item in ([HardenWindowsSecurity.GlobalVars]::FinalMegaObject)[$Key].GetEnumerator()) {
                            $Item
                        }
                    }
                }
                $AllOrderedResults | ConvertTo-Csv | Out-File -FilePath ".\Compliance Check Output $(Get-Date -Format "MM-dd-yyyy 'at' HH-mm-ss").CSV" -Force
            }
            function Set-CategoryFormat {
                [CmdletBinding()]
                param (
                    [ValidateSet([Colorsx])][Parameter(Mandatory)][System.String]$ColorInput,
                    [Parameter(Mandatory)][System.String]$CategoryName,
                    [Parameter(Mandatory)][System.String]$DisplayName,
                    [Parameter(Mandatory)][System.Collections.Hashtable]$ColorMap,
                    [AllowNull()][Parameter(Mandatory)][System.String[]]$Categories,
                    [ValidateSet('List', 'Table')][Parameter(Mandatory)][System.String]$Type
                )
                # If user selected specific categories and the current function call's category name is not included in them, return from this function
                if (($null -ne $Categories) -and ($CategoryName -notin $Categories)) { Return }

                # Assign the array of color codes to a variable for easier/shorter assignments
                [System.Int32[]]$RGBs = $ColorMap[$ColorInput]['Code']

                &$ColorMap[$ColorInput]['ScriptBlock'] "`n-------------$DisplayName Category-------------"

                Switch ($Type) {
                    'List' {
                        # Setting the List Format Accent the same color as the category's title
                        $PSStyle.Formatting.FormatAccent = $($PSStyle.Foreground.FromRGB($RGBs[0], $RGBs[1], $RGBs[2]))
                        ([HardenWindowsSecurity.GlobalVars]::FinalMegaObject).([Enum]::Parse([HardenWindowsSecurity.ComplianceCategories], $CategoryName, $true)) | Format-List -Property FriendlyName, @{
                            Label      = 'Compliant'
                            Expression =
                            { switch ($_.Compliant) {
                                    { $_ -eq $true } { $SwitchColor = $($PSStyle.Foreground.FromRGB($RGBs[0], $RGBs[1], $RGBs[2])); break }
                                    { $_ -eq $false } { $SwitchColor = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break }
                                }
                                "$SwitchColor$($_.Compliant)$($PSStyle.Reset)"
                            }
                        }, Value, Name, Category, Method
                    }
                    'Table' {
                        # Setting the Table header the same color as the category's title
                        $PSStyle.Formatting.TableHeader = $($PSStyle.Foreground.FromRGB($RGBs[0], $RGBs[1], $RGBs[2]))
                        ([HardenWindowsSecurity.GlobalVars]::FinalMegaObject).([Enum]::Parse([HardenWindowsSecurity.ComplianceCategories], $CategoryName, $true)) | Format-Table -Property FriendlyName,
                        @{
                            Label      = 'Compliant'
                            Expression =
                            { switch ($_.Compliant) {
                                    { $_ -eq $true } { $SwitchColor = $($PSStyle.Foreground.FromRGB($RGBs[0], $RGBs[1], $RGBs[2])); break }
                                    { $_ -eq $false } { $SwitchColor = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break }
                                }
                                "$SwitchColor$($_.Compliant)$($PSStyle.Reset)"
                            }
                        }, Value -AutoSize
                    }
                }
            }

            if ($ShowAsObjectsOnly) {
                return ([HardenWindowsSecurity.GlobalVars]::FinalMegaObject)
            }
            else {
                Set-CategoryFormat -ColorInput Plum -CategoryName 'MicrosoftDefender' -DisplayName 'Microsoft Defender' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput Orchid -CategoryName 'AttackSurfaceReductionRules' -DisplayName 'Attack Surface Reduction Rules' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput Fuchsia -CategoryName 'BitLockerSettings' -DisplayName 'Bitlocker Category' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput MediumOrchid -CategoryName 'TLSSecurity' -DisplayName 'TLS' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput MediumPurple -CategoryName 'LockScreen' -DisplayName 'Lock Screen' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput BlueViolet -CategoryName 'UserAccountControl' -DisplayName 'User Account Control' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput AndroidGreen -CategoryName 'DeviceGuard' -DisplayName 'Device Guard' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput Pink -CategoryName 'WindowsFirewall' -DisplayName 'Windows Firewall' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput SkyBlue -CategoryName 'OptionalWindowsFeatures' -DisplayName 'Optional Windows Features' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput HotPink -CategoryName 'WindowsNetworking' -DisplayName 'Windows Networking' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput DeepPink -CategoryName 'MiscellaneousConfigurations' -DisplayName 'Miscellaneous' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput MintGreen -CategoryName 'WindowsUpdateConfigurations' -DisplayName 'Windows Update' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput Orange -CategoryName 'EdgeBrowserConfigurations' -DisplayName 'Microsoft Edge' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput Daffodil -CategoryName 'NonAdminCommands' -DisplayName 'Non-Admin' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')

                # Counting the number of $True Compliant values in the Final Output Object
                [System.UInt32]$TotalTrueCompliantValuesInOutPut = 0
                foreach ($Category in [Enum]::GetNames([HardenWindowsSecurity.ComplianceCategories])) {
                    $TotalTrueCompliantValuesInOutPut += (([HardenWindowsSecurity.GlobalVars]::FinalMegaObject).([Enum]::Parse([HardenWindowsSecurity.ComplianceCategories], $Category, $true))).Where({ $_.Compliant -eq $True }).Count
                }

                # Only display the overall score if the user has not specified any categories
                if (!$Categories) {
                    & $WriteRainbow "`nYour compliance score is $TotalTrueCompliantValuesInOutPut out of $([HardenWindowsSecurity.GlobalVars]::TotalNumberOfTrueCompliantValues)!"
                }
            }
        }
        finally {
            Write-Progress -Activity 'Compliance checks have been completed' -Status 'Completed' -Completed
            [HardenWindowsSecurity.ControlledFolderAccessHandler]::Reset()
            [HardenWindowsSecurity.Miscellaneous]::CleanUp()
        }
    }
    <#
.SYNOPSIS
    Checks the compliance of a system according to the Harden Windows Security repository's guidelines.
    Use the GUI for much better experience: Protect-WindowsSecurity -GUI
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden%E2%80%90Windows%E2%80%90Security%E2%80%90Module
.DESCRIPTION
    Checks the compliance of a system according to the Harden Windows Security repository's guidelines.
.EXAMPLE
    $Result = Confirm-SystemCompliance -ShowAsObjectsOnly
    $Result['MicrosoftDefender']

    Do this to only see the result for the Microsoft Defender category when using ShowAsObjectsOnly optional parameter to output an object
.EXAMPLE
    Confirm-SystemCompliance -Categories MicrosoftDefender, MiscellaneousConfigurations

    Do this to only check the compliance for the Microsoft Defender and Miscellaneous Configurations categories
.PARAMETER ExportToCSV
    Export the output to a CSV file in the current working directory
.PARAMETER ShowAsObjectsOnly
    Returns a nested object instead of writing strings on the PowerShell console, it can be assigned to a variable
.PARAMETER DetailedDisplay
    Shows the output on the PowerShell console with more details and in the list format instead of table format
.PARAMETER Categories
    Specify the categories to check compliance for. If not specified, all categories will be checked
.PARAMETER Offline
    Skips the online update check
.INPUTS
    System.Management.Automation.SwitchParameter
    System.String[]
.OUTPUTS
    System.String
    System.Collections.Concurrent.ConcurrentDictionary[System.String, HardenWindowsSecurity.IndividualResult[]]
#>
}