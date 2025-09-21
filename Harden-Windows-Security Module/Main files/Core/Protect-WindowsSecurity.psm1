function Protect-WindowsSecurity {
    [CmdletBinding(DefaultParameterSetName = 'Online Mode')]
    param (
        [parameter(Mandatory = $false, ParameterSetName = 'GUI')][Switch]$GUI,

        [parameter(Mandatory = $false, ParameterSetName = 'Online Mode')]
        [parameter(Mandatory = $false, ParameterSetName = 'Offline Mode')]
        [ArgumentCompleter({
                param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)
                $Existing = $CommandAst.FindAll(
                    {
                        $Args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    },
                    $false
                ).Value
                ([HardenWindowsSecurity.GlobalVars]::HardeningCategorieX) | ForEach-Object -Process {
                    if ($_ -notin $Existing) {
                        $_
                    }
                }
            })]
        [ValidateScript({
                if ($_ -notin ([HardenWindowsSecurity.GlobalVars]::HardeningCategorieX)) { throw "Invalid Category Name: $_" }
                $true
            })]
        [System.String[]]$Categories,

        [parameter(Mandatory = $false, ParameterSetName = 'Online Mode')]
        [parameter(Mandatory = $false, ParameterSetName = 'Offline Mode')]
        [Switch]$Log,

        [Switch]$Offline
    )
    dynamicparam {
        $ParamDictionary = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()
        [System.Management.Automation.ScriptBlock]$DynParamCreatorSubCategories = {
            param([System.String]$Name)
            $ParamAttrib1 = [System.Management.Automation.ParameterAttribute]@{
                Mandatory        = $false
                ParameterSetName = 'Online Mode'
            }
            $ParamAttrib2 = [System.Management.Automation.ParameterAttribute]@{
                Mandatory        = $false
                ParameterSetName = 'Offline Mode'
            }
            $ParamDictionary.Add($Name, [System.Management.Automation.RuntimeDefinedParameter]::new(
                    $Name,
                    [Switch],
                    [System.Management.Automation.ParameterAttribute[]]@($ParamAttrib1, $ParamAttrib2) # Add both attributes to the parameter
                ))
        }
        if ('MicrosoftSecurityBaselines' -in $PSBoundParameters['Categories']) {
            Invoke-Command -ScriptBlock $DynParamCreatorSubCategories -ArgumentList 'SecBaselines_NoOverrides'
        }
        if ('MicrosoftDefender' -in $PSBoundParameters['Categories']) {
            'MSFTDefender_SAC', 'MSFTDefender_NoDiagData', 'MSFTDefender_NoScheduledTask', 'MSFTDefender_BetaChannels' | ForEach-Object -Process { Invoke-Command -ScriptBlock $DynParamCreatorSubCategories -ArgumentList $_ }
        }
        if ('DeviceGuard' -in $PSBoundParameters['Categories']) {
            Invoke-Command -ScriptBlock $DynParamCreatorSubCategories -ArgumentList 'DeviceGuard_MandatoryVBS'
        }
        if ('LockScreen' -in $PSBoundParameters['Categories']) {
            'LockScreen_NoLastSignedIn', 'LockScreen_CtrlAltDel' | ForEach-Object -Process { Invoke-Command -ScriptBlock $DynParamCreatorSubCategories -ArgumentList $_ }
        }
        if ('UserAccountControl' -in $PSBoundParameters['Categories']) {
            'UAC_NoFastSwitching', 'UAC_OnlyElevateSigned' | ForEach-Object -Process { Invoke-Command -ScriptBlock $DynParamCreatorSubCategories -ArgumentList $_ }
        }
        if ('WindowsNetworking' -in $PSBoundParameters['Categories']) {
            Invoke-Command -ScriptBlock $DynParamCreatorSubCategories -ArgumentList 'WindowsNetworking_BlockNTLM'
        }
        if ('MiscellaneousConfigurations' -in $PSBoundParameters['Categories']) {
            'Miscellaneous_WindowsProtectedPrint', 'MiscellaneousConfigurations_LongPathSupport', 'MiscellaneousConfigurations_StrongKeyProtection' , 'MiscellaneousConfigurations_ReducedTelemetry' | ForEach-Object -Process { Invoke-Command -ScriptBlock $DynParamCreatorSubCategories -ArgumentList $_ }
        }
        if ('CountryIPBlocking' -in $PSBoundParameters['Categories']) {
            Invoke-Command -ScriptBlock $DynParamCreatorSubCategories -ArgumentList 'CountryIPBlocking_OFAC'
        }
        if ('DownloadsDefenseMeasures' -in $PSBoundParameters['Categories']) {
            Invoke-Command -ScriptBlock $DynParamCreatorSubCategories -ArgumentList 'DangerousScriptHostsBlocking'
        }
        if ($PSBoundParameters.Offline.IsPresent) {
            [scriptblock]$ArgumentCompleterZipFilePathsPicker = {
                Add-Type -AssemblyName 'PresentationFramework'
                [Microsoft.Win32.OpenFileDialog]$Dialog = [Microsoft.Win32.OpenFileDialog]::new()
                $Dialog.Filter = 'Zip files (*.zip)|*.zip'
                $Dialog.Title = 'Select the Zip file'
                $Result = $Dialog.ShowDialog()
                if ($Result -eq $true) {
                    return "`'$($Dialog.FileName)`'"
                }
            }
            $PathToLGPO_AttributesCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            [System.Management.Automation.ParameterAttribute]$PathToLGPO_MandatoryAttrib = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $PathToLGPO_MandatoryAttrib.Mandatory = $true
            $PathToLGPO_AttributesCollection.Add($PathToLGPO_MandatoryAttrib)

            [System.Management.Automation.ParameterAttribute]$PathToLGPO_ParamSetAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $PathToLGPO_ParamSetAttribute.ParameterSetName = 'Offline Mode'
            $PathToLGPO_AttributesCollection.Add($PathToLGPO_ParamSetAttribute)

            [System.Management.Automation.ValidateScriptAttribute]$PathToLGPO_ValidateScriptAttrib = New-Object -TypeName System.Management.Automation.ValidateScriptAttribute( {
                    if (-not ([HardenWindowsSecurity.SneakAndPeek]::Search('LGPO_*/LGPO.exe', $_))) {
                        throw 'The selected Zip file does not contain the LGPO.exe which is required for the Protect-WindowsSecurity function to work properly'
                    }
                    $true
                })
            $PathToLGPO_AttributesCollection.Add($PathToLGPO_ValidateScriptAttrib)

            [System.Management.Automation.ArgumentCompleterAttribute]$PathToLGPO_ArgumentCompleterAttrib = New-Object -TypeName System.Management.Automation.ArgumentCompleterAttribute($ArgumentCompleterZipFilePathsPicker)
            $PathToLGPO_AttributesCollection.Add($PathToLGPO_ArgumentCompleterAttrib)

            [System.Management.Automation.RuntimeDefinedParameter]$PathToLGPO = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('PathToLGPO', [System.IO.FileInfo], $PathToLGPO_AttributesCollection)

            $ParamDictionary.Add('PathToLGPO', $PathToLGPO)

            $PathToMSFT365AppsSecurityBaselines_AttributesCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

            [System.Management.Automation.ParameterAttribute]$PathToMSFT365AppsSecurityBaselines_MandatoryAttrib = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $PathToMSFT365AppsSecurityBaselines_MandatoryAttrib.Mandatory = $true
            $PathToMSFT365AppsSecurityBaselines_AttributesCollection.Add($PathToMSFT365AppsSecurityBaselines_MandatoryAttrib)

            [System.Management.Automation.ParameterAttribute]$PathToMSFT365AppsSecurityBaselinesParamSetAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $PathToMSFT365AppsSecurityBaselinesParamSetAttribute.ParameterSetName = 'Offline Mode'
            $PathToMSFT365AppsSecurityBaselines_AttributesCollection.Add($PathToMSFT365AppsSecurityBaselinesParamSetAttribute)

            [System.Management.Automation.ValidateScriptAttribute]$PathToMSFT365AppsSecurityBaselines_ValidateScriptAttrib = New-Object -TypeName System.Management.Automation.ValidateScriptAttribute( {
                    if (-not ([HardenWindowsSecurity.SneakAndPeek]::Search('Microsoft 365 Apps for Enterprise*/Scripts/Baseline-LocalInstall.ps1', $_))) {
                        throw 'The selected Zip file does not contain the Microsoft 365 Apps for Enterprise Security Baselines Baseline-LocalInstall.ps1 which is required for the Protect-WindowsSecurity function to work properly'
                    }
                    $true
                })
            $PathToMSFT365AppsSecurityBaselines_AttributesCollection.Add($PathToMSFT365AppsSecurityBaselines_ValidateScriptAttrib)

            [System.Management.Automation.ArgumentCompleterAttribute]$PathToMSFT365AppsSecurityBaselines_ArgumentCompleterAttrib = New-Object -TypeName System.Management.Automation.ArgumentCompleterAttribute($ArgumentCompleterZipFilePathsPicker)
            $PathToMSFT365AppsSecurityBaselines_AttributesCollection.Add($PathToMSFT365AppsSecurityBaselines_ArgumentCompleterAttrib)

            [System.Management.Automation.RuntimeDefinedParameter]$PathToMSFT365AppsSecurityBaselines = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('PathToMSFT365AppsSecurityBaselines', [System.IO.FileInfo], $PathToMSFT365AppsSecurityBaselines_AttributesCollection)

            $ParamDictionary.Add('PathToMSFT365AppsSecurityBaselines', $PathToMSFT365AppsSecurityBaselines)

            $PathToMSFTSecurityBaselines_AttributesCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

            [System.Management.Automation.ParameterAttribute]$PathToMSFTSecurityBaselines_MandatoryAttrib = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $PathToMSFTSecurityBaselines_MandatoryAttrib.Mandatory = $true
            $PathToMSFTSecurityBaselines_AttributesCollection.Add($PathToMSFTSecurityBaselines_MandatoryAttrib)

            [System.Management.Automation.ParameterAttribute]$PathToMSFTSecurityBaselines_ParamSetAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $PathToMSFTSecurityBaselines_ParamSetAttribute.ParameterSetName = 'Offline Mode'
            $PathToMSFTSecurityBaselines_AttributesCollection.Add($PathToMSFTSecurityBaselines_ParamSetAttribute)

            [System.Management.Automation.ValidateScriptAttribute]$PathToMSFTSecurityBaselines_ValidateScriptAttrib = New-Object -TypeName System.Management.Automation.ValidateScriptAttribute( {
                    if (-not ([HardenWindowsSecurity.SneakAndPeek]::Search('Windows*Security Baseline/Scripts/Baseline-LocalInstall.ps1', $_))) {
                        throw 'The selected Zip file does not contain the Microsoft Security Baselines Baseline-LocalInstall.ps1 which is required for the Protect-WindowsSecurity function to work properly'
                    }
                    $true
                })
            $PathToMSFTSecurityBaselines_AttributesCollection.Add($PathToMSFTSecurityBaselines_ValidateScriptAttrib)

            [System.Management.Automation.ArgumentCompleterAttribute]$PathToMSFTSecurityBaselines_ArgumentCompleterAttrib = New-Object -TypeName System.Management.Automation.ArgumentCompleterAttribute($ArgumentCompleterZipFilePathsPicker)
            $PathToMSFTSecurityBaselines_AttributesCollection.Add($PathToMSFTSecurityBaselines_ArgumentCompleterAttrib)

            [System.Management.Automation.RuntimeDefinedParameter]$PathToMSFTSecurityBaselines = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('PathToMSFTSecurityBaselines', [System.IO.FileInfo], $PathToMSFTSecurityBaselines_AttributesCollection)

            $ParamDictionary.Add('PathToMSFTSecurityBaselines', $PathToMSFTSecurityBaselines)
        }

        if ($PSBoundParameters.Log.IsPresent) {

            $LogPath_AttributesCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

            [System.Management.Automation.ScriptBlock]$ArgumentCompleterLogFilePathPicker = {
                Add-Type -AssemblyName 'PresentationFramework'
                [Microsoft.Win32.SaveFileDialog]$Dialog = [Microsoft.Win32.SaveFileDialog]::new()
                $Dialog.InitialDirectory = [System.Environment]::GetFolderPath('Desktop')
                $Dialog.Filter = 'Text files (*.txt)|*.txt'
                $Dialog.Title = 'Choose where to save the log file'
                $Result = $Dialog.ShowDialog()
                if ($Result -eq $true) {
                    return "`'$($Dialog.FileName)`'"
                }
            }

            [System.Management.Automation.ArgumentCompleterAttribute]$LogPath_ArgumentCompleterAttrib = New-Object -TypeName System.Management.Automation.ArgumentCompleterAttribute($ArgumentCompleterLogFilePathPicker)
            $LogPath_AttributesCollection.Add($LogPath_ArgumentCompleterAttrib)

            [System.Management.Automation.ParameterAttribute]$LogPath_MandatoryAttrib = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $LogPath_MandatoryAttrib.Mandatory = $true
            $LogPath_AttributesCollection.Add($LogPath_MandatoryAttrib)

            [System.Management.Automation.ParameterAttribute]$LogPath_ParamSetAttribute1 = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $LogPath_ParamSetAttribute1.ParameterSetName = 'Offline Mode'
            $LogPath_AttributesCollection.Add($LogPath_ParamSetAttribute1)

            [System.Management.Automation.ParameterAttribute]$LogPath_ParamSetAttribute2 = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $LogPath_ParamSetAttribute2.ParameterSetName = 'Online Mode'
            $LogPath_AttributesCollection.Add($LogPath_ParamSetAttribute2)

            [System.Management.Automation.RuntimeDefinedParameter]$LogPath = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('LogPath', [System.IO.FileInfo], $LogPath_AttributesCollection)

            $ParamDictionary.Add('LogPath', $LogPath)
        }
        if (-not $PSBoundParameters.GUI.IsPresent) {
            return $ParamDictionary
        }
    }
    begin {
        Write-Warning -Message "This module is deprecated.`nPlease use the new Harden System Security App, available on Microsoft Store: https://apps.microsoft.com/detail/9P7GGFL7DX57`nGitHub Document: https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security"
        try { LoadHardenWindowsSecurityNecessaryDLLsInternal } catch { Write-Verbose ([HardenWindowsSecurity.GlobalVars]::ReRunText); ReRunTheModuleAgain -C $MyInvocation.Statement }
        $script:ErrorActionPreference = 'Stop'
        [HardenWindowsSecurity.Initializer]::Initialize($VerbosePreference)
        [bool]$ErrorsOccurred = $false

        ('SecBaselines_NoOverrides', 'MSFTDefender_SAC', 'MSFTDefender_NoDiagData', 'MSFTDefender_NoScheduledTask',
        'MSFTDefender_BetaChannels', 'LockScreen_CtrlAltDel', 'LockScreen_NoLastSignedIn', 'UAC_NoFastSwitching',
        'UAC_OnlyElevateSigned', 'WindowsNetworking_BlockNTLM', 'Miscellaneous_WindowsProtectedPrint', 'CountryIPBlocking_OFAC',
        'PathToLGPO', 'PathToMSFT365AppsSecurityBaselines', 'PathToMSFTSecurityBaselines', 'DangerousScriptHostsBlocking',
        'MiscellaneousConfigurations_LongPathSupport', 'DeviceGuard_MandatoryVBS', 'MiscellaneousConfigurations_StrongKeyProtection', 'MiscellaneousConfigurations_ReducedTelemetry') | ForEach-Object -Process {
            New-Variable -Name $_ -Value $($PSBoundParameters[$_]) -Force
        }
        New-Variable -Name 'LogPath' -Value $($PSBoundParameters['LogPath'] ?? (Join-Path -Path $(Get-Location).Path -ChildPath "Log-Protect-WindowsSecurity-$(Get-Date -Format 'yyyy-MM-dd HH-mm-ss').txt")) -Force

        ([HardenWindowsSecurity.GlobalVars]::Offline) = $PSBoundParameters['Offline'] ? $true : $false

        [System.String]$CurrentExecutionPolicy = Get-ExecutionPolicy -Scope 'Process'
        Set-ExecutionPolicy -ExecutionPolicy 'Unrestricted' -Scope 'Process' -Force

        try { [System.String]$CurrentPowerShellTitle = $Host.UI.RawUI.WindowTitle }
        catch { [System.String]$CurrentPowerShellTitle = $null }

        [HardenWindowsSecurity.ChangePSConsoleTitle]::Set('❤️‍🔥Harden Windows Security❤️‍🔥')

        if ([System.Environment]::IsPrivilegedProcess) {
            [HardenWindowsSecurity.Miscellaneous]::RequirementsCheck()
            [HardenWindowsSecurity.ControlledFolderAccessHandler]::Start($true, $false)
        }
        if ($PSBoundParameters.GUI.IsPresent) {
            [HardenWindowsSecurity.GUIHandOff]::Boot()
            return
        }
    }
    process {
        try {
            if ($PSBoundParameters.GUI.IsPresent) { return }

            . "$([HardenWindowsSecurity.GlobalVars]::Path)\Shared\HardeningFunctions.ps1"

            if ($Log) {
                [HardenWindowsSecurity.Logger]::LogFilePathCLI = $LogPath
                [System.Diagnostics.Stopwatch]$StopWatch = [Diagnostics.Stopwatch]::StartNew()
            }

            [HardenWindowsSecurity.ChangePSConsoleTitle]::Set('⏬ Downloading')

            if (!([HardenWindowsSecurity.GlobalVars]::Offline)) {
                [HardenWindowsSecurity.Logger]::LogMessage('Downloading the required files', [HardenWindowsSecurity.LogTypeIntel]::Information)
                Write-Progress -Activity 'Downloading the required files' -Status 'Downloading' -PercentComplete 20
            }
            [HardenWindowsSecurity.AsyncDownloader]::PrepDownloadedFiles("$PathToLGPO", "$PathToMSFTSecurityBaselines", "$PathToMSFT365AppsSecurityBaselines", $false)
            [HardenWindowsSecurity.Logger]::LogMessage('Finished downloading/processing the required files', [HardenWindowsSecurity.LogTypeIntel]::Information)

            Write-Progress -Activity 'Applying the security measures' -Status 'Protecting' -PercentComplete 50

            :MainSwitchLabel switch ($Categories) {
                'MicrosoftSecurityBaselines' { Invoke-MicrosoftSecurityBaselines -RunUnattended }
                'Microsoft365AppsSecurityBaselines' { Invoke-Microsoft365AppsSecurityBaselines -RunUnattended }
                'MicrosoftDefender' { Invoke-MicrosoftDefender -RunUnattended }
                'AttackSurfaceReductionRules' { Invoke-AttackSurfaceReductionRules -RunUnattended }
                'BitLockerSettings' { Invoke-BitLockerSettings -RunUnattended }
                'DeviceGuard' { Invoke-DeviceGuard -RunUnattended }
                'TLSSecurity' { Invoke-TLSSecurity -RunUnattended }
                'LockScreen' { Invoke-LockScreen -RunUnattended }
                'UserAccountControl' { Invoke-UserAccountControl -RunUnattended }
                'WindowsFirewall' { Invoke-WindowsFirewall -RunUnattended }
                'OptionalWindowsFeatures' { Invoke-OptionalWindowsFeatures -RunUnattended }
                'WindowsNetworking' { Invoke-WindowsNetworking -RunUnattended }
                'MiscellaneousConfigurations' { Invoke-MiscellaneousConfigurations -RunUnattended }
                'WindowsUpdateConfigurations' { Invoke-WindowsUpdateConfigurations -RunUnattended }
                'EdgeBrowserConfigurations' { Invoke-EdgeBrowserConfigurations -RunUnattended }
                'CertificateCheckingCommands' { Invoke-CertificateCheckingCommands -RunUnattended }
                'CountryIPBlocking' { Invoke-CountryIPBlocking -RunUnattended }
                'DownloadsDefenseMeasures' { Invoke-DownloadsDefenseMeasures -RunUnattended }
                'NonAdminCommands' { Invoke-NonAdminCommands -RunUnattended }
                default {
                    foreach ($Category in ([HardenWindowsSecurity.GlobalVars]::HardeningCategorieX)) {
                        . "Invoke-$Category"
                    }
                }
            }
        }
        catch {
            $ErrorsOccurred = $true
            throw $_
        }
        finally {
            Write-Progress -Activity 'Protection completed' -Status 'Completed' -Completed
            if ($null -ne $CurrentPowerShellTitle) { [HardenWindowsSecurity.ChangePSConsoleTitle]::Set($CurrentPowerShellTitle) }
            if ($null -ne $CurrentExecutionPolicy) { Set-ExecutionPolicy -ExecutionPolicy "$CurrentExecutionPolicy" -Scope 'Process' -Force }

            [HardenWindowsSecurity.ControlledFolderAccessHandler]::reset()
            [HardenWindowsSecurity.Miscellaneous]::CleanUp()

            if ($Log) {
                $StopWatch.Stop()
                [HardenWindowsSecurity.Logger]::LogMessage("Protect-WindowsSecurity completed in $($StopWatch.Elapsed.Hours) Hours - $($StopWatch.Elapsed.Minutes) Minutes - $($StopWatch.Elapsed.Seconds) Seconds - $($StopWatch.Elapsed.Milliseconds) Milliseconds - $($StopWatch.Elapsed.Microseconds) Microseconds - $($StopWatch.Elapsed.Nanoseconds) Nanoseconds", [HardenWindowsSecurity.LogTypeIntel]::Information)
            }
            if (!$ErrorsOccurred) { pwsh.exe -NoProfile -NoLogo -NoExit }
        }
    }
    <#
.SYNOPSIS
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security
    Use the GUI for much better experience: Protect-WindowsSecurity -GUI
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security
.DESCRIPTION
    Applies the hardening security measures on Windows OS. You can run this cmdlet in interactive or headless/unattended mode.
    In interactive mode, you will be prompted for confirmation before applying each category and sub-category.
    In headless/unattended mode, you can specify which categories to apply without the need for user interaction.
    When running in headless/unattended mode, you can control the sub-categories of each category by using the following switch parameters:

    SecBaselines_NoOverrides -> Applies the Microsoft Security Baselines without the optional overrides
    MSFTDefender_SAC -> Enables Smart App Control
    MSFTDefender_NoDiagData -> Will not enable optional diagnostics data required for Smart App Control (Does not have any effect if Smart App Control is already turned on)
    MSFTDefender_NoScheduledTask -> Will not create scheduled task for fast MSFT driver block rules update
    MSFTDefender_BetaChannels -> Set Defender Engine and Intelligence update channels to beta
    LockScreen_CtrlAltDel -> Require CTRL + ALT + Delete at lock screen
    LockScreen_NoLastSignedIn -> Will not display the last signed in user at the lock screen
    UAC_NoFastSwitching -> Hide entry points for fast user switching
    UAC_OnlyElevateSigned -> Only elevate signed and validated executables
    WindowsNetworking_BlockNTLM -> Will block NTLM completely
    Miscellaneous_WindowsProtectedPrint -> Enables Windows Protected Print Mode
    CountryIPBlocking_OFAC -> Include the IP ranges of OFAC Sanctioned Countries in the firewall block rules
    MiscellaneousConfigurations_LongPathSupport -> Enables support for long paths for applications
    DeviceGuard_MandatoryVBS -> Enforces VBS and Memory Integrity in Mandatory mode
    MiscellaneousConfigurations_StrongKeyProtection -> System cryptography: Force strong key protection for user keys stored on the computer
    MiscellaneousConfigurations_ReducedTelemetry -> Applies the policies that reduce the telemetry in the OS. See the Readme for more info.

    Each of the switch parameters above will be dynamically generated based on the categories you choose.
    For example, if you choose to run the Microsoft Security Baselines category, the SecBaselines_NoOverrides switch parameter will be generated and you can use it to apply the Microsoft Security Baselines without the optional overrides.
.PARAMETER GUI
    Activates the GUI mode. The cmdlet will display a GUI window where you can use the complete set of Harden Windows Security module's features.
.PARAMETER Categories
    The hardening categories to implement. Use this to selectively apply certain categories.
    Use this parameter when executing the Protect-WindowsSecurity in silent/headless mode to automatically apply any categories you desire without user intervention.
    If not specified, there will be requests for confirmation before running each category.
.PARAMETER Verbose
    Activates elaborate messages by displaying extensive information about the actions of the Protect-WindowsSecurity cmdlet.
.PARAMETER Log
    Activates comprehensive logging by recording all the information shown on the screen and some additional data to a text file. It is strongly advised to use the -Verbose parameter when you want to enable logging.
.PARAMETER LogPath
    The path to save the log file to. If not specified, the log file will be saved in the current working directory.
.PARAMETER Offline
    Indicates that the module is being run in offline mode. Will not download any files from the internet.
    Using this parameter will make the following 3 parameters mandatory: PathToLGPO, PathToMSFTSecurityBaselines and PathToMSFT365AppsSecurityBaselines.
    Use this parameter with the -GUI parameter if you want to use the GUI to run the module in offline mode because it will skip the online version check.
.PARAMETER PathToLGPO
    The path to the 'LGPO.zip'. Make sure it's in the zip format just like it's downloaded from the Microsoft servers.
    File name can be anything.
    The parameter has argument completer so you can press tab and use the file picker GUI to select the zip file.
.PARAMETER PathToMSFTSecurityBaselines
    The path to the 'Windows 11 v23H2 Security Baseline.zip'. Make sure it's in the zip format just like it's downloaded from the Microsoft servers.
    File name can be anything.
    The parameter has argument completer so you can press tab and use the file picker GUI to select the zip file.
.PARAMETER PathToMSFT365AppsSecurityBaselines
    The path to the 'Microsoft 365 Apps for Enterprise 2306.zip'. Make sure it's in the zip format just like it's downloaded from the Microsoft servers.
    File name can be anything.
    The parameter has argument completer so you can press tab and use the file picker GUI to select the zip file.
.NOTES
    It is highly recommended to always include the Microsoft Security Baselines category and place it first as it forms the foundation of all subsequent categories.
.EXAMPLE
    Protect-WindowsSecurity -Categories 'MicrosoftSecurityBaselines', 'MicrosoftDefender', 'AttackSurfaceReductionRules'

    This example will apply the Microsoft Security Baselines, Microsoft Defender and Attack Surface Reduction Rules categories without the need for user interaction.
.EXAMPLE
    Protect-WindowsSecurity -Categories MicrosoftDefender -MSFTDefender_SAC -Verbose

    This example will apply the Microsoft Defender category with the Smart App Control sub-category, without the need for user interaction, and will show verbose messages.
.EXAMPLE
    Protect-WindowsSecurity

    This example will run the cmdlet in interactive mode and will prompt for confirmation before running each category and sub-category.
.EXAMPLE
    Protect-WindowsSecurity -Verbose -Offline -PathToLGPO 'C:\Users\Admin\Desktop\LGPO.zip' -PathToMSFTSecurityBaselines 'C:\Users\Admin\Desktop\Baselines.zip' -PathToMSFT365AppsSecurityBaselines 'C:\Users\Admin\Desktop\M365Baselines.zip' -Log -Categories MicrosoftSecurityBaselines,MicrosoftDefender -MSFTDefender_SAC

    This example instructs the cmdlet to run in offline mode and will not download any files from the internet.
    It also runs it in headless/silent mode by specifying which categories to automatically run. -MSFTDefender_SAC switch is used so the Smart App Control sub-category is also applied in the headless/silent mode.
    -Log switch is mentioned which will save the output of the cmdlet to a text file in the current working directory.
.EXAMPLE
    Protect-WindowsSecurity -GUI

    This example will allow you to use the Graphical User Interface. (highly recommended)
.EXAMPLE
    Protect-WindowsSecurity -GUI -Offline

    This example will allow you to use the Graphical User Interface and also unlocks the related controls in the GUI where you can select the required files for total offline operation.
.INPUTS
    System.String[]
    System.IO.FileInfo
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
#>
}