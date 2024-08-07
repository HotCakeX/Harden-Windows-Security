Function Protect-WindowsSecurity {
    [CmdletBinding(DefaultParameterSetName = 'Online Mode')]
    [OutputType([System.String])]
    param (
        [parameter(Mandatory = $false, ParameterSetName = 'GUI')]
        [System.Management.Automation.SwitchParameter]$GUI,

        [parameter(Mandatory = $false, ParameterSetName = 'Online Mode')]
        [parameter(Mandatory = $false, ParameterSetName = 'Offline Mode')]
        [ArgumentCompleter({
                # Get the current command and the already bound parameters
                param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)

                # Find all string constants in the AST
                $Existing = $CommandAst.FindAll(
                    # The predicate scriptblock to define the criteria for filtering the AST nodes
                    {
                        $Args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    },
                    # The recurse flag, whether to search nested scriptblocks or not.
                    $false
                ).Value

                ([HardeningModule.GlobalVars]::HardeningCategorieX) | ForEach-Object -Process {
                    # Check if the item is already selected
                    if ($_ -notin $Existing) {
                        # Return the item
                        $_
                    }
                }
            })]
        [ValidateScript({
                if ($_ -notin ([HardeningModule.GlobalVars]::HardeningCategorieX)) { throw "Invalid Category Name: $_" }
                # Return true if everything is okay
                $true
            })]
        [System.String[]]$Categories,

        [parameter(Mandatory = $false, ParameterSetName = 'Online Mode')]
        [parameter(Mandatory = $false, ParameterSetName = 'Offline Mode')]
        [System.Management.Automation.SwitchParameter]$Log,

        [System.Management.Automation.SwitchParameter]$Offline
    )

    # This offers granular control over sub-category automation, handles the parameter validation and correlation between selected categories and the subcategory switch parameter, doesn't populate the argument completer on the console with unrelated parameters
    DynamicParam {

        # Create a new dynamic parameter dictionary
        $ParamDictionary = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()

        # A script block to create and add dynamic parameters to the dictionary for the sub-categories
        [System.Management.Automation.ScriptBlock]$DynParamCreatorSubCategories = {
            param([System.String]$Name)

            # Create a parameter attribute to add the ParameterSet for 'Online Mode'
            $ParamAttrib1 = [System.Management.Automation.ParameterAttribute]@{
                Mandatory        = $false
                ParameterSetName = 'Online Mode'
            }
            # Create a parameter attribute to add the ParameterSet for 'Offline Mode'
            $ParamAttrib2 = [System.Management.Automation.ParameterAttribute]@{
                Mandatory        = $false
                ParameterSetName = 'Offline Mode'
            }
            # Add the dynamic parameter to the param dictionary
            $ParamDictionary.Add($Name, [System.Management.Automation.RuntimeDefinedParameter]::new(
                    # Define parameter name
                    $Name,
                    # Define parameter type
                    [System.Management.Automation.SwitchParameter],
                    # Add both attributes to the parameter
                    [System.Management.Automation.ParameterAttribute[]]@($ParamAttrib1, $ParamAttrib2)
                ))
        }

        if ('MicrosoftSecurityBaselines' -in $PSBoundParameters['Categories']) {
            # Create a dynamic parameter for -SecBaselines_NoOverrides
            Invoke-Command -ScriptBlock $DynParamCreatorSubCategories -ArgumentList 'SecBaselines_NoOverrides'
        }

        if ('MicrosoftDefender' -in $PSBoundParameters['Categories']) {
            # Create a dynamic parameter for -MSFTDefender_SAC
            Invoke-Command -ScriptBlock $DynParamCreatorSubCategories -ArgumentList 'MSFTDefender_SAC'
            # Create a dynamic parameter for -MSFTDefender_NoDiagData
            Invoke-Command -ScriptBlock $DynParamCreatorSubCategories -ArgumentList 'MSFTDefender_NoDiagData'
            # Create a dynamic parameter for -MSFTDefender_NoScheduledTask
            Invoke-Command -ScriptBlock $DynParamCreatorSubCategories -ArgumentList 'MSFTDefender_NoScheduledTask'
            # Create a dynamic parameter for -MSFTDefender_BetaChannels
            Invoke-Command -ScriptBlock $DynParamCreatorSubCategories -ArgumentList 'MSFTDefender_BetaChannels'
        }

        if ('LockScreen' -in $PSBoundParameters['Categories']) {
            # Create a dynamic parameter for -LockScreen_NoLastSignedIn
            Invoke-Command -ScriptBlock $DynParamCreatorSubCategories -ArgumentList 'LockScreen_NoLastSignedIn'
            # Create a dynamic parameter for -LockScreen_CtrlAltDel
            Invoke-Command -ScriptBlock $DynParamCreatorSubCategories -ArgumentList 'LockScreen_CtrlAltDel'
        }

        if ('UserAccountControl' -in $PSBoundParameters['Categories']) {
            # Create a dynamic parameter for -UAC_NoFastSwitching
            Invoke-Command -ScriptBlock $DynParamCreatorSubCategories -ArgumentList 'UAC_NoFastSwitching'
            # Create a dynamic parameter for -UAC_OnlyElevateSigned
            Invoke-Command -ScriptBlock $DynParamCreatorSubCategories -ArgumentList 'UAC_OnlyElevateSigned'
        }

        if ('CountryIPBlocking' -in $PSBoundParameters['Categories']) {
            # Create a dynamic parameter for -CountryIPBlocking_OFAC
            Invoke-Command -ScriptBlock $DynParamCreatorSubCategories -ArgumentList 'CountryIPBlocking_OFAC'
        }

        # Creating dynamic parameters for the offline mode files
        if ($PSBoundParameters.Offline.IsPresent) {

            # Opens File picker GUI so that user can select an .zip file
            [System.Management.Automation.ScriptBlock]$ArgumentCompleterZipFilePathsPicker = {
                # Load the System.Windows.Forms assembly
                Add-Type -AssemblyName 'System.Windows.Forms'
                # Create a new OpenFileDialog object
                [System.Windows.Forms.OpenFileDialog]$Dialog = New-Object -TypeName 'System.Windows.Forms.OpenFileDialog'
                # Set the filter to show only zip files
                $Dialog.Filter = 'Zip files (*.zip)|*.zip'
                # Set the title of the dialog
                $Dialog.Title = 'Select the Zip file'
                # Show the dialog and get the result
                [System.String]$Result = $Dialog.ShowDialog()
                # If the user clicked OK, return the selected file path
                if ($Result -eq 'OK') {
                    return "`'$($Dialog.FileName)`'"
                }
            }

            #Region-Dyn-Param-For-PathToLGPO

            # Create a parameter attribute collection
            $PathToLGPO_AttributesCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

            # Create a mandatory attribute and add it to the collection
            [System.Management.Automation.ParameterAttribute]$PathToLGPO_MandatoryAttrib = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $PathToLGPO_MandatoryAttrib.Mandatory = $true
            $PathToLGPO_AttributesCollection.Add($PathToLGPO_MandatoryAttrib)

            [System.Management.Automation.ParameterAttribute]$PathToLGPO_ParamSetAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $PathToLGPO_ParamSetAttribute.ParameterSetName = 'Offline Mode'
            $PathToLGPO_AttributesCollection.Add($PathToLGPO_ParamSetAttribute)

            # Create a validate script attribute and add it to the collection
            [System.Management.Automation.ValidateScriptAttribute]$PathToLGPO_ValidateScriptAttrib = New-Object -TypeName System.Management.Automation.ValidateScriptAttribute( {
                    if (-NOT ([HardeningModule.SneakAndPeek]::Search('LGPO_*/LGPO.exe', $_))) {
                        Throw 'The selected Zip file does not contain the LGPO.exe which is required for the Protect-WindowsSecurity function to work properly'
                    }
                    # Return true if everything is okay
                    $true
                })
            # Add the validate script attribute to the collection
            $PathToLGPO_AttributesCollection.Add($PathToLGPO_ValidateScriptAttrib)

            # Create an argument completer attribute and add it to the collection
            [System.Management.Automation.ArgumentCompleterAttribute]$PathToLGPO_ArgumentCompleterAttrib = New-Object -TypeName System.Management.Automation.ArgumentCompleterAttribute($ArgumentCompleterZipFilePathsPicker)
            $PathToLGPO_AttributesCollection.Add($PathToLGPO_ArgumentCompleterAttrib)

            # Create a dynamic parameter object with the attributes already assigned: Name, Type, and Attributes Collection
            [System.Management.Automation.RuntimeDefinedParameter]$PathToLGPO = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('PathToLGPO', [System.IO.FileInfo], $PathToLGPO_AttributesCollection)

            # Add the dynamic parameter object to the dictionary
            $ParamDictionary.Add('PathToLGPO', $PathToLGPO)

            #Endregion-Dyn-Param-For-PathToLGPO

            #Region-Dyn-Param-For-PathToMSFT365AppsSecurityBaselines

            # Create a parameter attribute collection
            $PathToMSFT365AppsSecurityBaselines_AttributesCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

            # Create a mandatory attribute and add it to the collection
            [System.Management.Automation.ParameterAttribute]$PathToMSFT365AppsSecurityBaselines_MandatoryAttrib = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $PathToMSFT365AppsSecurityBaselines_MandatoryAttrib.Mandatory = $true
            $PathToMSFT365AppsSecurityBaselines_AttributesCollection.Add($PathToMSFT365AppsSecurityBaselines_MandatoryAttrib)

            [System.Management.Automation.ParameterAttribute]$PathToMSFT365AppsSecurityBaselinesParamSetAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $PathToMSFT365AppsSecurityBaselinesParamSetAttribute.ParameterSetName = 'Offline Mode'
            $PathToMSFT365AppsSecurityBaselines_AttributesCollection.Add($PathToMSFT365AppsSecurityBaselinesParamSetAttribute)

            # Create a validate script attribute and add it to the collection
            [System.Management.Automation.ValidateScriptAttribute]$PathToMSFT365AppsSecurityBaselines_ValidateScriptAttrib = New-Object -TypeName System.Management.Automation.ValidateScriptAttribute( {
                    if (-NOT ([HardeningModule.SneakAndPeek]::Search('Microsoft 365 Apps for Enterprise*/Scripts/Baseline-LocalInstall.ps1', $_))) {
                        Throw 'The selected Zip file does not contain the Microsoft 365 Apps for Enterprise Security Baselines Baseline-LocalInstall.ps1 which is required for the Protect-WindowsSecurity function to work properly'
                    }
                    # Return true if everything is okay
                    $true
                })
            # Add the validate script attribute to the collection
            $PathToMSFT365AppsSecurityBaselines_AttributesCollection.Add($PathToMSFT365AppsSecurityBaselines_ValidateScriptAttrib)

            # Create an argument completer attribute and add it to the collection
            [System.Management.Automation.ArgumentCompleterAttribute]$PathToMSFT365AppsSecurityBaselines_ArgumentCompleterAttrib = New-Object -TypeName System.Management.Automation.ArgumentCompleterAttribute($ArgumentCompleterZipFilePathsPicker)
            $PathToMSFT365AppsSecurityBaselines_AttributesCollection.Add($PathToMSFT365AppsSecurityBaselines_ArgumentCompleterAttrib)

            # Create a dynamic parameter object with the attributes already assigned: Name, Type, and Attributes Collection
            [System.Management.Automation.RuntimeDefinedParameter]$PathToMSFT365AppsSecurityBaselines = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('PathToMSFT365AppsSecurityBaselines', [System.IO.FileInfo], $PathToMSFT365AppsSecurityBaselines_AttributesCollection)

            # Add the dynamic parameter object to the dictionary
            $ParamDictionary.Add('PathToMSFT365AppsSecurityBaselines', $PathToMSFT365AppsSecurityBaselines)

            #Endregion-Dyn-Param-For-PathToMSFT365AppsSecurityBaselines

            #Region-Dyn-Param-For-PathToMSFTSecurityBaselines

            # Create a parameter attribute collection
            $PathToMSFTSecurityBaselines_AttributesCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

            # Create a mandatory attribute and add it to the collection
            [System.Management.Automation.ParameterAttribute]$PathToMSFTSecurityBaselines_MandatoryAttrib = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $PathToMSFTSecurityBaselines_MandatoryAttrib.Mandatory = $true
            $PathToMSFTSecurityBaselines_AttributesCollection.Add($PathToMSFTSecurityBaselines_MandatoryAttrib)

            [System.Management.Automation.ParameterAttribute]$PathToMSFTSecurityBaselines_ParamSetAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $PathToMSFTSecurityBaselines_ParamSetAttribute.ParameterSetName = 'Offline Mode'
            $PathToMSFTSecurityBaselines_AttributesCollection.Add($PathToMSFTSecurityBaselines_ParamSetAttribute)

            # Create a validate script attribute and add it to the collection
            [System.Management.Automation.ValidateScriptAttribute]$PathToMSFTSecurityBaselines_ValidateScriptAttrib = New-Object -TypeName System.Management.Automation.ValidateScriptAttribute( {
                    if (-NOT ([HardeningModule.SneakAndPeek]::Search('Windows*Security Baseline/Scripts/Baseline-LocalInstall.ps1', $_))) {
                        Throw 'The selected Zip file does not contain the Microsoft Security Baselines Baseline-LocalInstall.ps1 which is required for the Protect-WindowsSecurity function to work properly'
                    }
                    # Return true if everything is okay
                    $true
                })
            # Add the validate script attribute to the collection
            $PathToMSFTSecurityBaselines_AttributesCollection.Add($PathToMSFTSecurityBaselines_ValidateScriptAttrib)

            # Create an argument completer attribute and add it to the collection
            [System.Management.Automation.ArgumentCompleterAttribute]$PathToMSFTSecurityBaselines_ArgumentCompleterAttrib = New-Object -TypeName System.Management.Automation.ArgumentCompleterAttribute($ArgumentCompleterZipFilePathsPicker)
            $PathToMSFTSecurityBaselines_AttributesCollection.Add($PathToMSFTSecurityBaselines_ArgumentCompleterAttrib)

            # Create a dynamic parameter object with the attributes already assigned: Name, Type, and Attributes Collection
            [System.Management.Automation.RuntimeDefinedParameter]$PathToMSFTSecurityBaselines = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('PathToMSFTSecurityBaselines', [System.IO.FileInfo], $PathToMSFTSecurityBaselines_AttributesCollection)

            # Add the dynamic parameter object to the dictionary
            $ParamDictionary.Add('PathToMSFTSecurityBaselines', $PathToMSFTSecurityBaselines)

            #Endregion-Dyn-Param-For-PathToMSFTSecurityBaselines
        }

        # Creating dynamic parameters for the LogPath
        if ($PSBoundParameters.Log.IsPresent) {

            # Create a parameter attribute collection
            $LogPath_AttributesCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

            # Define argument completer's scriptblock
            [System.Management.Automation.ScriptBlock]$ArgumentCompleterLogFilePathPicker = {
                [System.Windows.Forms.SaveFileDialog]$Dialog = New-Object -TypeName System.Windows.Forms.SaveFileDialog
                $Dialog.InitialDirectory = [System.Environment]::GetFolderPath('Desktop')
                $Dialog.Filter = 'Text files (*.txt)|*.txt'
                $Dialog.Title = 'Choose where to save the log file'
                [System.String]$Result = $Dialog.ShowDialog()
                if ($Result -eq 'OK') {
                    return "`'$($Dialog.FileName)`'"
                }
            }

            # Create an argument completer attribute and add it to the collection
            [System.Management.Automation.ArgumentCompleterAttribute]$LogPath_ArgumentCompleterAttrib = New-Object -TypeName System.Management.Automation.ArgumentCompleterAttribute($ArgumentCompleterLogFilePathPicker)
            $LogPath_AttributesCollection.Add($LogPath_ArgumentCompleterAttrib)

            # Create a mandatory attribute and add it to the collection
            [System.Management.Automation.ParameterAttribute]$LogPath_MandatoryAttrib = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $LogPath_MandatoryAttrib.Mandatory = $true
            $LogPath_AttributesCollection.Add($LogPath_MandatoryAttrib)

            # Create a parameter attribute to add the ParameterSet for 'Offline Mode'
            [System.Management.Automation.ParameterAttribute]$LogPath_ParamSetAttribute1 = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $LogPath_ParamSetAttribute1.ParameterSetName = 'Offline Mode'
            $LogPath_AttributesCollection.Add($LogPath_ParamSetAttribute1)

            # Create a parameter attribute to add the ParameterSet for 'Online Mode'
            [System.Management.Automation.ParameterAttribute]$LogPath_ParamSetAttribute2 = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $LogPath_ParamSetAttribute2.ParameterSetName = 'Online Mode'
            $LogPath_AttributesCollection.Add($LogPath_ParamSetAttribute2)

            # Create a dynamic parameter object with the attributes already assigned: Name, Type, and Attributes Collection
            [System.Management.Automation.RuntimeDefinedParameter]$LogPath = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('LogPath', [System.IO.FileInfo], $LogPath_AttributesCollection)

            # Add the dynamic parameter object to the dictionary
            $ParamDictionary.Add('LogPath', $LogPath)
        }

        if ('DownloadsDefenseMeasures' -in $PSBoundParameters['Categories']) {
            # Create a dynamic parameter for -DangerousScriptHostsBlocking
            Invoke-Command -ScriptBlock $DynParamCreatorSubCategories -ArgumentList 'DangerousScriptHostsBlocking'
        }

        if ('NonAdminCommands' -in $PSBoundParameters['Categories']) {
            # Create a dynamic parameter for -ClipboardSync
            Invoke-Command -ScriptBlock $DynParamCreatorSubCategories -ArgumentList 'ClipboardSync'
        }

        # Only use the dynamic parameters if the GUI switch is not present
        if (-NOT $PSBoundParameters.GUI.IsPresent) {
            return $ParamDictionary
        }
    }

    begin {
        [HardeningModule.Initializer]::Initialize($VerbosePreference)
        # Detecting if Verbose switch is used
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false

        # Since Dynamic parameters are only available in the parameter dictionary, we have to access them using $PSBoundParameters or assign them manually to another variable in the function's scope
        New-Variable -Name 'SecBaselines_NoOverrides' -Value $($PSBoundParameters['SecBaselines_NoOverrides']) -Force
        New-Variable -Name 'MSFTDefender_SAC' -Value $($PSBoundParameters['MSFTDefender_SAC']) -Force
        New-Variable -Name 'MSFTDefender_NoDiagData' -Value $($PSBoundParameters['MSFTDefender_NoDiagData']) -Force
        New-Variable -Name 'MSFTDefender_NoScheduledTask' -Value $($PSBoundParameters['MSFTDefender_NoScheduledTask']) -Force
        New-Variable -Name 'MSFTDefender_BetaChannels' -Value $($PSBoundParameters['MSFTDefender_BetaChannels']) -Force
        New-Variable -Name 'LockScreen_CtrlAltDel' -Value $($PSBoundParameters['LockScreen_CtrlAltDel']) -Force
        New-Variable -Name 'LockScreen_NoLastSignedIn' -Value $($PSBoundParameters['LockScreen_NoLastSignedIn']) -Force
        New-Variable -Name 'UAC_NoFastSwitching' -Value $($PSBoundParameters['UAC_NoFastSwitching']) -Force
        New-Variable -Name 'UAC_OnlyElevateSigned' -Value $($PSBoundParameters['UAC_OnlyElevateSigned']) -Force
        New-Variable -Name 'CountryIPBlocking_OFAC' -Value $($PSBoundParameters['CountryIPBlocking_OFAC']) -Force
        New-Variable -Name 'PathToLGPO' -Value $($PSBoundParameters['PathToLGPO']) -Force
        New-Variable -Name 'PathToMSFT365AppsSecurityBaselines' -Value $($PSBoundParameters['PathToMSFT365AppsSecurityBaselines']) -Force
        New-Variable -Name 'PathToMSFTSecurityBaselines' -Value $($PSBoundParameters['PathToMSFTSecurityBaselines']) -Force
        # Set the default value for LogPath to the current working directory if not specified
        New-Variable -Name 'LogPath' -Value $($PSBoundParameters['LogPath'] ?? (Join-Path -Path $(Get-Location).Path -ChildPath "Log-Protect-WindowsSecurity-$(Get-Date -Format 'yyyy-MM-dd HH-mm-ss').txt")) -Force
        New-Variable -Name 'DangerousScriptHostsBlocking' -Value $($PSBoundParameters['DangerousScriptHostsBlocking']) -Force
        New-Variable -Name 'ClipboardSync' -Value $($PSBoundParameters['ClipboardSync']) -Force

        # This assignment is used by the GUI RunSpace
        ([HardeningModule.GlobalVars]::Offline) = $PSBoundParameters['Offline'] ? $true : $false

        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName ([System.IO.Path]::Combine([HardeningModule.GlobalVars]::Path, 'Shared', 'Update-self.psm1')) -Force -Verbose:$false

        if (!([HardeningModule.GlobalVars]::Offline)) {
            Write-Verbose -Message 'Checking for updates...'
            Update-Self -InvocationStatement $MyInvocation.Statement
        }
        else {
            Write-Verbose -Message 'Skipping update check since the -Offline switch was used'
        }

        # Get the execution policy for the current process
        [System.String]$CurrentExecutionPolicy = Get-ExecutionPolicy -Scope 'Process'

        # Change the execution policy temporarily only for the current PowerShell session
        Set-ExecutionPolicy -ExecutionPolicy 'Unrestricted' -Scope 'Process' -Force

        # Get the current title of the PowerShell
        [System.String]$CurrentPowerShellTitle = $Host.UI.RawUI.WindowTitle

        # Change the title of the Windows Terminal for PowerShell tab
        $Host.UI.RawUI.WindowTitle = '❤️‍🔥Harden Windows Security❤️‍🔥'

        if ([HardeningModule.UserPrivCheck]::IsAdmin()) {
            [HardeningModule.ControlledFolderAccessHandler]::Start()
            [HardeningModule.Miscellaneous]::RequirementsCheck()
        }
        try {

            # Detecting whether GUI parameter is present or not
            if ($PSBoundParameters.GUI.IsPresent) {

                # Create and add the header to the log messages
                [System.Void][HardeningModule.GUI]::Logger.Add(@"
**********************
Harden Windows Security operation log start
Start time: $(Get-Date)
Username: $env:UserName
Machine: $env:COMPUTERNAME
Host Application: $PSHOME
Process ID: $PID
PSVersion: $([System.String]($PSVersionTable).PSVersion)
PSEdition: $PSEdition
GitCommitId: $([System.String]$(($PSVersionTable).GitCommitId))
OS Build: $([System.String]$([System.Environment]::OSVersion.Version))
Platform: $([System.String]$(($PSVersionTable).Platform))
PSCompatibleVersions: $([System.String]$(($PSVersionTable).PSCompatibleVersions))
PSRemotingProtocolVersion: $([System.String]$(($PSVersionTable).PSRemotingProtocolVersion))
SerializationVersion: $([System.String]$(($PSVersionTable).SerializationVersion))
WSManStackVersion: $([System.String]$(($PSVersionTable).WSManStackVersion))
Execution Policy: $CurrentExecutionPolicy
**********************
"@)
                # Initialize the WPF GUI
                [HardeningModule.GUI]::LoadXaml()

                # Defining a set of commands to run when the GUI window is loaded
                [HardeningModule.GUI]::Window.Add_ContentRendered({

                        try {
                            $UserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                            $User = [HardeningModule.LocalUserRetriever]::Get() | Where-Object -FilterScript { $_.SID -eq $UserSID }
                            [System.String]$NameToDisplay = (-NOT [System.String]::IsNullOrWhitespace($User.FullName)) ? $User.FullName : $User.Name
                        }
                        catch {}

                        [HardeningModule.Logger]::LogMessage(([HardeningModule.UserPrivCheck]::IsAdmin() ? "Hello $NameToDisplay, Running as Administrator" : "Hello $NameToDisplay, Running as Non-Administrator, some categories are disabled"))

                        # Set the execute button to disabled until all the prerequisites are met
                        [HardeningModule.GUI]::Window.FindName('Execute').IsEnabled = $false

                        Start-ThreadJob -ScriptBlock {
                            try {
                                . "$([HardeningModule.GlobalVars]::Path)\Shared\HardeningFunctions.ps1"
                                $PSDefaultParameterValues = @{ 'Write-Verbose:Verbose' = $true }

                                # Only download and process the files when GUI is loaded and if Offline mode is not used
                                # Because at this point user might have not selected the files to be used for offline operation
                                if (!([HardeningModule.GlobalVars]::Offline)) {
                                    Start-FileDownload -GUI -Verbose:$true *>&1 | ForEach-Object -Process {
                                        [HardeningModule.Logger]::LogMessage($_)
                                    }
                                }
                            }
                            catch {
                                $_.Exception.Message, $_.ErrorDetails, $_.ScriptStackTrace *>&1 | ForEach-Object -Process { [HardeningModule.Logger]::LogMessage($_) }
                                # when error occurs, Execute button remains disabled
                                throw $_.Exception
                            }

                            # Using dispatch since the execute button is owned by the GUI (parent) RunSpace and we're in another RunSpace (ThreadJob)
                            # Enabling the execute button after all files are downloaded and ready or if Offline switch was used and download was skipped
                            [HardeningModule.GUI]::Window.Dispatcher.Invoke({
                                    [HardeningModule.GUI]::Window.FindName('Execute').IsEnabled = $true
                                })
                        }
                    })

                # Add the click event for the execute button in the GUI RunSpace
                [HardeningModule.GUI]::Window.FindName('Execute').Add_Click({

                        # Clears any jobs from any ThreadJobs that have completed, failed, or stopped
                        Foreach ($JobToRemove in Get-Job) {
                            if ($JobToRemove.State -in 'Completed', 'Failed', 'Stopped') {
                                Remove-Job -Job $JobToRemove -Force
                            }
                        }

                        # Clear the categories and sub-categories lists
                        [HardeningModule.GUI]::SelectedCategories.Clear()
                        [HardeningModule.GUI]::SelectedSubCategories.Clear()

                        # Gather selected categories and sub-categories and store them in the GlobalVars hashtable
                        [HardeningModule.GUI]::categories.Items | Where-Object -FilterScript { $_.Content.IsChecked } | ForEach-Object -Process { [HardeningModule.GUI]::SelectedCategories.Enqueue($_.Content.Name) }
                        [HardeningModule.GUI]::subCategories.Items | Where-Object -FilterScript { $_.Content.IsChecked } | ForEach-Object -Process { [HardeningModule.GUI]::SelectedSubCategories.Enqueue($_.Content.Name) }

                        if ($DebugPreference -eq 'Continue') {
                            [HardeningModule.GlobalVars]::Host.UI.WriteDebugLine("$((Get-Job).Count) number of ThreadJobs Before")
                        }

                        $null = Start-ThreadJob -ScriptBlock {
                            # This tells the Write-ColorfulText function to write verbose texts instead of outputting PSStyle texts that don't work in the UI text block
                            $script:GUI = $true

                            . "$([HardeningModule.GlobalVars]::Path)\Shared\HardeningFunctions.ps1"

                            # Making the selected sub-categories available in the current scope because the functions called from this scriptblock wouldn't be able to access them otherwise
                            [HardeningModule.GUI]::SelectedSubCategories | ForEach-Object -Process {
                                # All of the sub-category variables are boolean since they are originally switch parameters in the CLI experience
                                Set-Variable -Name $_ -Value $true -Force
                            }

                            [System.Management.Automation.ScriptBlock]$HardeningFunctionsScriptBlock = {

                                try {

                                    [HardeningModule.GUI]::Window.Dispatcher.Invoke({
                                            # Disable Important elements while commands are being executed
                                            [HardeningModule.GUI]::Window.FindName('Execute').IsEnabled = $false
                                            [HardeningModule.GUI]::Window.FindName('ParentGrid').FindName('MainTabControlToggle').IsEnabled = $false
                                            [HardeningModule.GUI]::logPath.IsEnabled = $false
                                            [HardeningModule.GUI]::loggingViewBox.IsEnabled = $false
                                            [HardeningModule.GUI]::txtFilePath.IsEnabled = $false
                                        })

                                    # If Offline mode is used
                                    if (([HardeningModule.GlobalVars]::Offline)) {

                                        # Using dispatch to query their status from the GUI thread
                                        [HardeningModule.GUI]::Window.Dispatcher.Invoke({
                                                $script:OfflineModeToggleStatus = [HardeningModule.GUI]::enableOfflineMode.IsChecked
                                                $script:OfflineGreenLightStatus = (-NOT [System.String]::IsNullOrWhitespace([HardeningModule.GUI]::microsoftSecurityBaselineZipTextBox.Text)) -and (-NOT [System.String]::IsNullOrWhitespace([HardeningModule.GUI]::microsoft365AppsSecurityBaselineZipTextBox.Text)) -and (-NOT [System.String]::IsNullOrWhitespace([HardeningModule.GUI]::lgpoZipTextBox.Text))
                                            })

                                        # If the required files have not been processed for offline mode already
                                        if (![HardeningModule.GUI]::StartFileDownloadHasRun) {
                                            # If the checkbox on the GUI for Offline mode is checked
                                            if ($OfflineModeToggleStatus) {
                                                # Make sure all 3 fields for offline mode files were selected by the users and they are neither empty nor null
                                                if ($OfflineGreenLightStatus) {
                                                    # Process the offline mode files selected by the user
                                                    Start-FileDownload -GUI -Verbose:$true

                                                    # Set a flag indicating this code block should not happen again when the execute button is pressed
                                                    [HardeningModule.GUI]::StartFileDownloadHasRun = $true
                                                }
                                                else {
                                                    'Enable Offline Mode checkbox is checked but you have not selected all of the 3 required files for offline mode operation. Please select them and press the execute button again.'
                                                }
                                            }
                                            else {
                                                'Offline mode is being used but the Enable Offline Mode checkbox is not checked. Please check it and press the execute button again.'
                                            }
                                        }
                                    }

                                    if (!([HardeningModule.GlobalVars]::Offline) -or (([HardeningModule.GlobalVars]::Offline) -and [HardeningModule.GUI]::StartFileDownloadHasRun)) {

                                        if (![System.String]::IsNullOrWhiteSpace([HardeningModule.GUI]::SelectedCategories)) {

                                            # Make the Write-Verbose cmdlet write verbose messages regardless of the global preference or selected parameter
                                            # That is the main source of the messages in the GUI
                                            $PSDefaultParameterValues = @{ 'Write-Verbose:Verbose' = $true }

                                            # Reset the progress bar counter to prevent it from going over 100
                                            [HardeningModule.GlobalVars]::CurrentMainStep = 0

                                            :MainSwitchLabel switch ([HardeningModule.GUI]::SelectedCategories) {
                                                'MicrosoftSecurityBaselines' { Invoke-MicrosoftSecurityBaselines -RunUnattended }
                                                'Microsoft365AppsSecurityBaselines' { Invoke-Microsoft365AppsSecurityBaselines -RunUnattended }
                                                'MicrosoftDefender' { Invoke-MicrosoftDefender -RunUnattended }
                                                'AttackSurfaceReductionRules' { Invoke-AttackSurfaceReductionRules -RunUnattended }
                                                'BitLockerSettings' { Invoke-BitLockerSettings -RunUnattended }
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
                                                'CountryIPBlocking' { Invoke-CountryIPBlocking -RunUnattended -GUI }
                                                'DownloadsDefenseMeasures' { Invoke-DownloadsDefenseMeasures -RunUnattended }
                                                'NonAdminCommands' { Invoke-NonAdminCommands -RunUnattended }
                                            }

                                            New-ToastNotification -SelectedCategories [HardeningModule.GUI]::SelectedCategories
                                        }
                                        else {
                                            'No category was selected'
                                        }
                                    }
                                }
                                catch {
                                    Write-Verbose -Message $_
                                    # throw $_.Exception
                                }
                            }

                            # Run the selected categories and output their results to the GUI
                            &$HardeningFunctionsScriptBlock *>&1 | ForEach-Object -Process {
                                [HardeningModule.Logger]::LogMessage($_)
                            }

                            [HardeningModule.GUI]::Window.Dispatcher.Invoke({
                                    # Enable the disabled UI elements once all of the commands have been executed
                                    [HardeningModule.GUI]::Window.FindName('Execute').IsEnabled = $true
                                    [HardeningModule.GUI]::Window.FindName('ParentGrid').FindName('MainTabControlToggle').IsEnabled = $true
                                    [HardeningModule.GUI]::logPath.IsEnabled = $true
                                    [HardeningModule.GUI]::loggingViewBox.IsEnabled = $true
                                    [HardeningModule.GUI]::txtFilePath.IsEnabled = $true
                                })
                        } -ThrottleLimit 1

                        if ($DebugPreference -eq 'Continue') {
                            [HardeningModule.GlobalVars]::Host.UI.WriteDebugLine("$((Get-Job).Count) number of ThreadJobs After")
                        }
                    })

                # Show the GUI window
                [System.Void][HardeningModule.GUI]::Window.ShowDialog()

                # Clear any jobs created during runtime in the current RunSpace
                Foreach ($JobToRemove in Get-Job) {
                    if ($JobToRemove.State -in 'Completed', 'Failed', 'Stopped') {
                        Remove-Job -Job $JobToRemove -Force
                    }
                }
            }
        }
        catch {
            $_
            $_.Exception
            $_.InvocationInfo
        }

        # Return from the Begin block if GUI was used and then closed
        if ($PSBoundParameters.GUI.IsPresent) { Return }
    }

    process {
        # doing a try-catch-finally block on the entire code so that when CTRL + C is pressed to forcefully exit the operation,
        # or break is passed, clean up will still happen for secure exit. Any error that happens will be thrown
        try {

            # Return from the Process block if GUI was used and then closed, triggers the finally block to run for proper clean-up
            if ($PSBoundParameters.GUI.IsPresent) { Return }

            # Import all of the required functions
            . "$([HardeningModule.GlobalVars]::Path)\Shared\HardeningFunctions.ps1"

            # Start the transcript if the -Log switch is used
            if ($Log) {
                Start-Transcript -IncludeInvocationHeader -Path $LogPath

                # Create a new stopwatch object to measure the execution time
                Write-Verbose -Message 'Starting the stopwatch...'
                [System.Diagnostics.Stopwatch]$StopWatch = [Diagnostics.Stopwatch]::StartNew()
            }

            if (!$Categories) {
                Write-Host -Object "`r`n"
                Write-ColorfulText -Color Rainbow -InputText "############################################################################################################`r`n"
                Write-ColorfulText -Color MintGreen -InputText "### Please read the Readme in the GitHub repository: https://github.com/HotCakeX/Harden-Windows-Security ###`r`n"
                Write-ColorfulText -Color Rainbow -InputText "############################################################################################################`r`n"
            }

            Write-Progress -Id 0 -Activity 'Downloading the required files' -Status "Step $([HardeningModule.GlobalVars]::CurrentMainStep)/$([HardeningModule.GlobalVars]::TotalMainSteps)" -PercentComplete 1
            # Change the title of the Windows Terminal for PowerShell tab
            $Host.UI.RawUI.WindowTitle = '⏬ Downloading'

            # Download the required files
            Start-FileDownload

            # a label to break out of the main switch statements and run the finally block when user chooses to exit
            :MainSwitchLabel switch ($Categories) {
                'MicrosoftSecurityBaselines' { Invoke-MicrosoftSecurityBaselines -RunUnattended }
                'Microsoft365AppsSecurityBaselines' { Invoke-Microsoft365AppsSecurityBaselines -RunUnattended }
                'MicrosoftDefender' { Invoke-MicrosoftDefender -RunUnattended }
                'AttackSurfaceReductionRules' { Invoke-AttackSurfaceReductionRules -RunUnattended }
                'BitLockerSettings' { Invoke-BitLockerSettings -RunUnattended }
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
                    # Get the values of the ValidateSet attribute of the Categories parameter of the main function
                    foreach ($Category in ([HardeningModule.GlobalVars]::HardeningCategorieX)) {
                        # Run all of the categories' functions if the user didn't specify any
                        . "Invoke-$Category"
                    }
                }
            }
            # No code should be placed after this.
        }
        catch {
            # Throw whatever error that occurred
            Throw $_
        }
        finally {
            Write-Verbose -Message 'Finally block is running'
            [HardeningModule.ControlledFolderAccessHandler]::reset()
            [HardeningModule.Miscellaneous]::CleanUp()

            Write-Verbose -Message 'Disabling progress bars'
            foreach ($ID in 0..2) {
                Write-Progress -Id $ID -Activity 'Done' -Completed
            }

            Write-Verbose -Message 'Restoring the title of the PowerShell back to what it was prior to running the module'
            $Host.UI.RawUI.WindowTitle = $CurrentPowerShellTitle

            Write-Verbose -Message 'Setting the execution policy back to what it was prior to running the module'
            Set-ExecutionPolicy -ExecutionPolicy "$CurrentExecutionPolicy" -Scope 'Process' -Force

            if ($Log) {
                Write-Verbose -Message 'Stopping the stopwatch'
                $StopWatch.Stop()
                Write-Verbose -Message "Protect-WindowsSecurity completed in $($StopWatch.Elapsed.Hours) Hours - $($StopWatch.Elapsed.Minutes) Minutes - $($StopWatch.Elapsed.Seconds) Seconds - $($StopWatch.Elapsed.Milliseconds) Milliseconds - $($StopWatch.Elapsed.Microseconds) Microseconds - $($StopWatch.Elapsed.Nanoseconds) Nanoseconds"

                Write-Verbose -Message 'Stopping the transcription'
                Stop-Transcript
            }
        }
    }
    <#
.SYNOPSIS
    Applies the hardening measures described in the GitHub readme.
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security
.DESCRIPTION
    Applies the hardening measures on a Windows client OS. You can run this cmdlet in interactive or headless/unattended mode.
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
    CountryIPBlocking_OFAC -> Include the IP ranges of OFAC Sanctioned Countries in the firewall block rules

    Each of the switch parameters above will be dynamically generated based on the categories you choose.
    For example, if you choose to run the Microsoft Security Baselines category, the SecBaselines_NoOverrides switch parameter will be generated and you can use it to apply the Microsoft Security Baselines without the optional overrides.
.COMPONENT
    PowerShell
.FUNCTIONALITY
    Applies the hardening measures described in the GitHub readme.
.PARAMETER GUI
    Activates the GUI mode. The cmdlet will display a GUI window where you can select the categories to apply.
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

    This example will allow you to use the Graphical User Interface.
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
