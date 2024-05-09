#Requires -Version 7.4
#Requires -PSEdition Core
# Applies the style to the Protect-WindowsSecurity when running as script straight from the GitHub, as well as all of the cmdlets of the Harden Windows Security module
$PSStyle.Progress.UseOSCIndicator = $true
Function Protect-WindowsSecurity {
    [CmdletBinding(DefaultParameterSetName = 'Online Mode')]
    [OutputType([System.String])]
    [Alias('P')]
    param (
        [Alias('G')]
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

                [Categoriex]::new().GetValidValues() | ForEach-Object -Process {
                    # Check if the item is already selected
                    if ($_ -notin $Existing) {
                        # Return the item
                        $_
                    }
                }
            })]
        [ValidateScript({
                if ($_ -notin [Categoriex]::new().GetValidValues()) { throw "Invalid Category Name: $_" }
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
                    try {
                        # Load the System.IO.Compression assembly
                        [System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem') | Out-Null
                        # Open the zip file in read mode
                        [System.IO.Compression.ZipArchive]$ZipArchive = [IO.Compression.ZipFile]::OpenRead("$_")
                        # Make sure the selected zip has the required file
                        if (-NOT ($ZipArchive.Entries | Where-Object -FilterScript { $_.FullName -like 'LGPO_*/LGPO.exe' })) {
                            Throw 'The selected Zip file does not contain the LGPO.exe which is required for the Protect-WindowsSecurity function to work properly'
                        }
                    }
                    finally {
                        # Close the handle whether the zip file is valid or not
                        $ZipArchive.Dispose()
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
                    try {
                        # Load the System.IO.Compression assembly
                        [System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem') | Out-Null
                        # Open the zip file in read mode
                        [System.IO.Compression.ZipArchive]$ZipArchive = [IO.Compression.ZipFile]::OpenRead("$_")
                        # Make sure the selected zip has the required file
                        if (-NOT ($ZipArchive.Entries | Where-Object -FilterScript { $_.FullName -like 'Microsoft 365 Apps for Enterprise*/Scripts/Baseline-LocalInstall.ps1' })) {
                            Throw 'The selected Zip file does not contain the Microsoft 365 Apps for Enterprise Security Baselines Baseline-LocalInstall.ps1 which is required for the Protect-WindowsSecurity function to work properly'
                        }
                    }
                    finally {
                        # Close the handle whether the zip file is valid or not
                        $ZipArchive.Dispose()
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
                    try {
                        # Load the System.IO.Compression assembly
                        [System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem') | Out-Null
                        # Open the zip file in read mode
                        [System.IO.Compression.ZipArchive]$ZipArchive = [IO.Compression.ZipFile]::OpenRead("$_")
                        # Make sure the selected zip has the required file
                        if (-NOT ($ZipArchive.Entries | Where-Object -FilterScript { $_.FullName -like 'Windows*Security Baseline/Scripts/Baseline-LocalInstall.ps1' })) {
                            Throw 'The selected Zip file does not contain the Microsoft Security Baselines Baseline-LocalInstall.ps1 which is required for the Protect-WindowsSecurity function to work properly'
                        }
                    }
                    finally {
                        # Close the handle whether the zip file is valid or not
                        $ZipArchive.Dispose()
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
                Add-Type -AssemblyName System.Windows.Forms
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

        # Only use the dynamic parameters if the GUI switch is not present
        if (-NOT $PSBoundParameters.GUI.IsPresent) {
            return $ParamDictionary
        }
    }

    begin {
        # This class is the orchestrator of the hardening categories deciding which one of them is allowed to run
        Class Categoriex : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {

                # Only return the NonAdmin category if the user is not an administrator
                [System.Security.Principal.WindowsPrincipal]$Principal = New-Object -TypeName 'Security.Principal.WindowsPrincipal' -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())
                if (-NOT $Principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) { Return 'NonAdminCommands' }

                $Categoriex = [System.Collections.Generic.HashSet[System.String]](
                    'MicrosoftSecurityBaselines',
                    'Microsoft365AppsSecurityBaselines',
                    'MicrosoftDefender',
                    'AttackSurfaceReductionRules',
                    'BitLockerSettings',
                    'TLSSecurity',
                    'LockScreen',
                    'UserAccountControl',
                    'WindowsFirewall',
                    'OptionalWindowsFeatures',
                    'WindowsNetworking',
                    'MiscellaneousConfigurations',
                    'WindowsUpdateConfigurations',
                    'EdgeBrowserConfigurations',
                    'CertificateCheckingCommands',
                    'CountryIPBlocking',
                    'DownloadsDefenseMeasures',
                    'NonAdminCommands'
                )
                # Remove the categories that are not allowed to run on Windows Home edition
                if ((Get-CimInstance -ClassName Win32_OperatingSystem).OperatingSystemSKU -in '101', '100') {
                    foreach ($CatName in $Categoriex) {
                        if ($CatName -in 'BitLockerSettings', 'DownloadsDefenseMeasures', 'TLSSecurity', 'AttackSurfaceReductionRules', 'MicrosoftSecurityBaselines', 'Microsoft365AppsSecurityBaselines', 'CountryIPBlocking') {
                            [System.Void]$Categoriex.Remove($CatName)
                        }
                    }
                }
                return [System.String[]]$Categoriex
            }
        }

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

        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null

        $ErrorActionPreference = 'Stop'

        $PSDefaultParameterValues = @{
            'Invoke-WebRequest:HttpVersion'    = '3.0'
            'Invoke-WebRequest:SslProtocol'    = 'Tls12,Tls13'
            'Invoke-RestMethod:HttpVersion'    = '3.0'
            'Invoke-RestMethod:SslProtocol'    = 'Tls12,Tls13'
            'Invoke-WebRequest:ProgressAction' = 'SilentlyContinue'
            'Invoke-RestMethod:ProgressAction' = 'SilentlyContinue'
            'Get-BitLockerVolume:ErrorAction'  = 'SilentlyContinue'
            'Get-CimInstance:Verbose'          = $false
            'Import-Module:Verbose'            = $false
            'Copy-Item:Force'                  = $true
            'Copy-Item:ProgressAction'         = 'SilentlyContinue'
            'Test-Path:ErrorAction'            = 'SilentlyContinue'
        }

        #Region Helper-Functions-All-Experiences
        # The following functions do not rely on any script-wide or global variables
        function Select-Option {
            <#
    .synopsis
        Function to show a prompt to the user to select an option from a list of options
    .INPUTS
        System.String
        System.Management.Automation.SwitchParameter
    .OUTPUTS
        System.String
    .PARAMETER Message
        Contains the main prompt message
    .PARAMETER ExtraMessage
        Contains any extra notes for sub-categories
    #>
            [CmdletBinding()]
            param(
                [parameter(Mandatory = $True)][System.String]$Message,
                [parameter(Mandatory = $True)][System.String[]]$Options,
                [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SubCategory,
                [parameter(Mandatory = $false)][System.String]$ExtraMessage
            )

            $Selected = $null
            while ($null -eq $Selected) {

                # Use this style if showing main categories only
                if (!$SubCategory) {
                    Write-ColorfulText -C Fuchsia -I $Message
                }
                # Use this style if showing sub-categories only that need additional confirmation
                else {
                    # Show sub-category's main prompt
                    Write-ColorfulText -C Orange -I $Message
                    # Show sub-category's notes/extra message if any
                    if ($ExtraMessage) {
                        Write-ColorfulText -C PinkBoldBlink -I $ExtraMessage
                    }
                }

                for ($I = 0; $I -lt $Options.Length; $I++) {
                    Write-ColorfulText -C MintGreen -I "$($I+1): $($Options[$I])"
                }

                # Make sure user only inputs a positive integer
                [System.Int64]$SelectedIndex = 0
                $IsValid = [System.Int64]::TryParse((Read-Host -Prompt 'Select an option'), [ref]$SelectedIndex)
                if ($IsValid) {
                    if ($SelectedIndex -gt 0 -and $SelectedIndex -le $Options.Length) {
                        $Selected = $Options[$SelectedIndex - 1]
                    }
                    else {
                        Write-Warning -Message 'Invalid Option.'
                    }
                }
                else {
                    Write-Warning -Message 'Invalid input. Please only enter a positive number.'
                }
            }
            # Add verbose output, helpful when reviewing the log file
            Write-Verbose -Message "Selected: $Selected"
            return [System.String]$Selected
        }
        function Edit-Registry {
            <#
    .SYNOPSIS
        Function to modify registry
    .INPUTS
        System.String
    .OUTPUTS
        System.Void
    #>
            [CmdletBinding()]
            param (
                [System.String]$Path,
                [System.String]$Key,
                [System.String]$Value,
                [System.String]$Type,
                [System.String]$Action
            )
            Begin {
                Function Test-RegistryValue {
                    <#
                    .SYNOPSIS
                        A helper function to detect if a registry key contains a value
                        Used before attempting to delete a registry key's value
                    .INPUTS
                        Path: The registry key path
                        Name: The name of the registry value
                    .OUTPUTS
                        System.Boolean
                    #>
                    [CmdletBinding()]
                    [OutputType([System.Boolean])]
                    param(
                        [Parameter(Mandatory = $true)]
                        [System.String]$Path,

                        [Parameter(Mandatory = $true)]
                        [System.String]$Name
                    )
                    if (Test-Path -Path $Path) {
                        $Key = Get-Item -LiteralPath $Path
                        if ($null -ne $Key.GetValue($Name, $null)) {
                            return $true
                        }
                        else {
                            return $false
                        }
                    }
                    else {
                        return $false
                    }
                }

            }
            Process {
                If (-NOT (Test-Path -Path $Path)) {
                    New-Item -Path $Path -Force | Out-Null
                }
                if ($Action -eq 'AddOrModify') {
                    New-ItemProperty -Path $Path -Name $Key -Value $Value -PropertyType $Type -Force | Out-Null
                }
                elseif ($Action -eq 'Delete') {
                    if (Test-RegistryValue -Path $Path -Name $Key) {
                        Remove-ItemProperty -Path $Path -Name $Key -Force | Out-Null
                    }
                }
            }
        }
        function Compare-SecureString {
            <#
    .SYNOPSIS
        Safely compares two SecureString objects without decrypting them.
        Outputs $true if they are equal, or $false otherwise.
    .LINK
        https://stackoverflow.com/questions/48809012/compare-two-credentials-in-powershell
    .INPUTS
        System.Security.SecureString
    .OUTPUTS
        System.Boolean
    .PARAMETER SecureString1
        First secure string
    .PARAMETER SecureString2
        Second secure string to compare with the first secure string
    #>
            [CmdletBinding()]
            param(
                [System.Security.SecureString]$SecureString1,
                [System.Security.SecureString]$SecureString2
            )
            try {
                $Bstr1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString1)
                $Bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString2)
                $Length1 = [Runtime.InteropServices.Marshal]::ReadInt32($Bstr1, -4)
                $Length2 = [Runtime.InteropServices.Marshal]::ReadInt32($Bstr2, -4)
                if ( $Length1 -ne $Length2 ) {
                    return $false
                }
                for ( $I = 0; $I -lt $Length1; ++$I ) {
                    $B1 = [Runtime.InteropServices.Marshal]::ReadByte($Bstr1, $I)
                    $B2 = [Runtime.InteropServices.Marshal]::ReadByte($Bstr2, $I)
                    if ( $B1 -ne $B2 ) {
                        return $false
                    }
                }
                return $true
            }
            finally {
                if ( $Bstr1 -ne [IntPtr]::Zero ) {
                    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr1)
                }
                if ( $Bstr2 -ne [IntPtr]::Zero ) {
                    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr2)
                }
            }
        }
        Function Write-ColorfulText {
            <#
    .SYNOPSIS
        Function to write colorful text to the console
    .INPUTS
        System.String
        System.Management.Automation.SwitchParameter
    .OUTPUTS
        System.String
    .PARAMETER Color
        The color to use to display the text, uses PSStyle
     .PARAMETER InputText
        The text to display in the selected color
     #>
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $True)]
                [Alias('C')]
                [ValidateSet('Fuchsia', 'Orange', 'NeonGreen', 'MintGreen', 'PinkBoldBlink', 'PinkBold', 'Rainbow' , 'Gold', 'TeaGreenNoNewLine', 'LavenderNoNewLine', 'PinkNoNewLine', 'VioletNoNewLine', 'Violet', 'Pink', 'Lavender')]
                [System.String]$Color,

                [parameter(Mandatory = $True)]
                [Alias('I')]
                [System.String]$InputText
            )

            # If GUI is being used, write verbose text and exit
            if ($GUI) {
                Write-Verbose -Message $InputText
                Return
            }

            switch ($Color) {
                'Fuchsia' { Write-Host -Object "$($PSStyle.Foreground.FromRGB(236,68,155))$InputText$($PSStyle.Reset)"; break }
                'Orange' { Write-Host -Object "$($PSStyle.Foreground.FromRGB(255,165,0))$InputText$($PSStyle.Reset)"; break }
                'NeonGreen' { Write-Host -Object "$($PSStyle.Foreground.FromRGB(153,244,67))$InputText$($PSStyle.Reset)"; break }
                'MintGreen' { Write-Host -Object "$($PSStyle.Foreground.FromRGB(152,255,152))$InputText$($PSStyle.Reset)"; break }
                'PinkBoldBlink' { Write-Host -Object "$($PSStyle.Foreground.FromRgb(255,192,203))$($PSStyle.Bold)$($PSStyle.Blink)$InputText$($PSStyle.Reset)"; break }
                'PinkBold' { Write-Host -Object "$($PSStyle.Foreground.FromRgb(255,192,203))$($PSStyle.Bold)$($PSStyle.Reverse)$InputText$($PSStyle.Reset)"; break }
                'Gold' { Write-Host -Object "$($PSStyle.Foreground.FromRgb(255,215,0))$InputText$($PSStyle.Reset)"; break }
                'VioletNoNewLine' { Write-Host -Object "$($PSStyle.Foreground.FromRGB(153,0,255))$InputText$($PSStyle.Reset)" -NoNewline; break }
                'PinkNoNewLine' { Write-Host -Object "$($PSStyle.Foreground.FromRGB(255,0,230))$InputText$($PSStyle.Reset)" -NoNewline; break }
                'Violet' { Write-Host -Object "$($PSStyle.Foreground.FromRGB(153,0,255))$InputText$($PSStyle.Reset)"; break }
                'Pink' { Write-Host -Object "$($PSStyle.Foreground.FromRGB(255,0,230))$InputText$($PSStyle.Reset)"; break }
                'LavenderNoNewLine' { Write-Host -Object "$($PSStyle.Foreground.FromRgb(255,179,255))$InputText$($PSStyle.Reset)" -NoNewline; break }
                'Lavender' { Write-Host -Object "$($PSStyle.Foreground.FromRgb(255,179,255))$InputText$($PSStyle.Reset)"; break }
                'TeaGreenNoNewLine' { Write-Host -Object "$($PSStyle.Foreground.FromRgb(133, 222, 119))$InputText$($PSStyle.Reset)" -NoNewline; break }
                'Rainbow' {
                    [System.Drawing.Color[]]$RainbowColors = @(
                        [System.Drawing.Color]::Pink,
                        [System.Drawing.Color]::HotPink,
                        [System.Drawing.Color]::SkyBlue,
                        [System.Drawing.Color]::HotPink,
                        [System.Drawing.Color]::SkyBlue,
                        [System.Drawing.Color]::LightSkyBlue,
                        [System.Drawing.Color]::LightGreen,
                        [System.Drawing.Color]::Coral,
                        [System.Drawing.Color]::Plum,
                        [System.Drawing.Color]::Gold
                    )

                    [System.String]$Output = ''
                    for ($I = 0; $I -lt $InputText.Length; $I++) {
                        $CurrentColor = $RainbowColors[$I % $RainbowColors.Length]
                        $Output += "$($PSStyle.Foreground.FromRGB($CurrentColor.R, $CurrentColor.G, $CurrentColor.B))$($PSStyle.Blink)$($InputText[$I])$($PSStyle.BlinkOff)$($PSStyle.Reset)"
                    }
                    Write-Output -InputObject $Output
                    break
                }
                Default { Throw 'Unspecified Color' }
            }
        }
        function Get-AvailableRemovableDrives {
            <#
    .SYNOPSIS
        Function to get a removable drive to be used by BitLocker category
    .INPUTS
        None. You cannot pipe objects to this function
    .OUTPUTS
        System.String
    #>

            # An empty array of objects that holds the final removable drives list
            [System.Object[]]$AvailableRemovableDrives = @()

            Get-Volume | Where-Object -FilterScript { $_.DriveLetter -and $_.DriveType -eq 'Removable' } |
            ForEach-Object -Process {

                # Prepare to create an extremely random file name
                [System.String]$Path = "$($_.DriveLetter + ':')\$(New-Guid).$(Get-Random -Maximum 400)"

                try {
                    # Create a test file on the drive to make sure it's not write-protected
                    New-Item -Path $Path -ItemType File -Value 'test' -Force | Out-Null
                    # If the drive wasn't write-protected then delete the test file
                    Remove-Item -Path $Path -Force
                    # Add the drive to the list only if it's writable
                    $AvailableRemovableDrives += $_
                }
                catch {
                    # Drive is write protected, do nothing
                }

            }

            # If there is any Writable removable drives, sort and prepare them and then add them to the array
            if ($AvailableRemovableDrives) {
                $AvailableRemovableDrives = $AvailableRemovableDrives | Sort-Object -Property DriveLetter |
                Select-Object -Property DriveLetter, FileSystemType, DriveType, @{Name = 'Size'; Expression = { '{0:N2}' -f ($_.Size / 1GB) + ' GB' } }
            }

            if (!$AvailableRemovableDrives) {
                do {
                    switch (Select-Option -Options 'Check for removable flash drives again', 'Skip encryptions altogether', 'Exit' -Message "`nNo removable writable flash drives found. Please insert a USB flash drive. If it's already attached to the system, try ejecting it and inserting it back in.") {
                        'Check for removable flash drives again' {

                            # An empty array of objects that holds the final removable drives list
                            [System.Object[]]$AvailableRemovableDrives = @()

                            Get-Volume | Where-Object -FilterScript { $_.DriveLetter -and $_.DriveType -eq 'Removable' } |
                            ForEach-Object -Process {

                                # Prepare to create an extremely random file name
                                [System.String]$ExtremelyRandomPath = "$($_.DriveLetter + ':')\$(New-Guid).$(Get-Random -Maximum 400)"

                                try {
                                    # Create a test file on the drive to make sure it's not write-protected
                                    New-Item -Path $ExtremelyRandomPath -ItemType File -Value 'test' -Force | Out-Null
                                    # If the drive wasn't write-protected then delete the test file
                                    Remove-Item -Path $ExtremelyRandomPath -Force
                                    # Add the drive to the list only if it's writable
                                    $AvailableRemovableDrives += $_
                                }
                                catch {
                                    # Drive is write protected, do nothing
                                }
                            }

                            # If there is any Writable removable drives, sort and prepare them and then add them to the array
                            if ($AvailableRemovableDrives) {
                                $AvailableRemovableDrives = $AvailableRemovableDrives | Sort-Object -Property DriveLetter |
                                Select-Object -Property DriveLetter, FileSystemType, DriveType, @{Name = 'Size'; Expression = { '{0:N2}' -f ($_.Size / 1GB) + ' GB' } }
                            }

                        }
                        'Skip encryptions altogether' { break BitLockerCategoryLabel } # Breaks from the BitLocker category and won't process Non-OS Drives
                        'Exit' { break MainSwitchLabel }
                    }
                }
                until ($AvailableRemovableDrives)
            }

            # Initialize the maximum length variables but make sure the column widths are at least as wide as their titles such as 'DriveLetter' or 'FileSystemType' etc.
            [System.Int64]$DriveLetterLength = 10
            [System.Int64]$FileSystemTypeLength = 13
            [System.Int64]$DriveTypeLength = 8
            [System.Int64]$SizeLength = 3

            # Loop through each element in the array
            foreach ($Drive in $AvailableRemovableDrives) {
                # Compare the length of the current element with the maximum length and update if needed
                if ($Drive.DriveLetter.Length -gt $DriveLetterLength) {
                    $DriveLetterLength = $Drive.DriveLetter.Length
                }
                if ($Drive.FileSystemType.Length -gt $FileSystemTypeLength) {
                    $FileSystemTypeLength = $Drive.FileSystemType.Length
                }
                if ($Drive.DriveType.Length -gt $DriveTypeLength) {
                    $DriveTypeLength = $Drive.DriveType.Length
                }
                if (($Drive.Size | Measure-Object -Character).Characters -gt $SizeLength) {
                    # The method below is used to calculate size of the string that consists only number, but since it now has "GB" in it, it's no longer needed
                    # $SizeLength = ($Drive.Size | Measure-Object -Character).Characters
                    $SizeLength = $Drive.Size.Length
                }
            }

            # Add 3 to each maximum length for spacing
            $DriveLetterLength += 3
            $FileSystemTypeLength += 3
            $DriveTypeLength += 3
            $SizeLength += 3

            # Creating a heading for the columns
            # Write the index of the drive
            Write-ColorfulText -C LavenderNoNewLine -I ('{0,-4}' -f '#')
            # Write the name of the drive
            Write-ColorfulText -C TeaGreenNoNewLine -I ("|{0,-$DriveLetterLength}" -f 'DriveLetter')
            # Write the File System Type of the drive
            Write-ColorfulText -C PinkNoNewLine -I ("|{0,-$FileSystemTypeLength}" -f 'FileSystemType')
            # Write the Drive Type of the drive
            Write-ColorfulText -C VioletNoNewLine -I ("|{0,-$DriveTypeLength}" -f 'DriveType')
            # Write the Size of the drive
            Write-ColorfulText -C Gold ("|{0,-$SizeLength}" -f 'Size')

            # Loop through the drives and display them in a table with colors
            for ($I = 0; $I -lt $AvailableRemovableDrives.Count; $I++) {
                # Write the index of the drive
                Write-ColorfulText -C LavenderNoNewLine -I ('{0,-4}' -f ($I + 1))
                # Write the name of the drive
                Write-ColorfulText -C TeaGreenNoNewLine -I ("|{0,-$DriveLetterLength}" -f $AvailableRemovableDrives[$I].DriveLetter)
                # Write the File System Type of the drive
                Write-ColorfulText -C PinkNoNewLine -I ("|{0,-$FileSystemTypeLength}" -f $AvailableRemovableDrives[$I].FileSystemType)
                # Write the Drive Type of the drive
                Write-ColorfulText -C VioletNoNewLine -I ("|{0,-$DriveTypeLength}" -f $AvailableRemovableDrives[$I].DriveType)
                # Write the Size of the drive
                Write-ColorfulText -C Gold ("|{0,-$SizeLength}" -f $AvailableRemovableDrives[$I].Size)
            }

            # Get the max count of available network drives and add 1 to it, assign the number as exit value to break the loop when selected
            [System.Int64]$ExitCodeRemovableDriveSelection = $AvailableRemovableDrives.Count + 1

            # Write an exit option at the end of the table
            Write-Host ('{0,-4}' -f "$ExitCodeRemovableDriveSelection") -NoNewline -ForegroundColor DarkRed
            Write-Host -Object '|Skip encryptions altogether' -ForegroundColor DarkRed

            function Confirm-Choice {
                <#
        .SYNOPSIS
            A function to validate the user input
        .INPUTS
            System.String
        .OUTPUTS
            System.Boolean
        #>
                param([System.String]$Choice)

                # Initialize a flag to indicate if the input is valid or not
                [System.Boolean]$IsValid = $false
                # Initialize a variable to store the parsed integer value
                [System.Int64]$ParsedChoice = 0
                # Try to parse the input as an integer
                # If the parsing succeeded, check if the input is within the range
                if ([System.Int64]::TryParse($Choice, [ref]$ParsedChoice)) {
                    if ($ParsedChoice -in 1..$ExitCodeRemovableDriveSelection) {
                        $IsValid = $true
                        break
                    }
                }
                # Return the flag value
                return $IsValid
            }

            # Prompt the user to enter the number of the drive they want to select, or exit value to exit, until they enter a valid input
            do {
                # Read the user input as a string
                [System.String]$Choice = $(Write-Host -Object "Enter the number of the drive you want to select or press $ExitCodeRemovableDriveSelection to Cancel" -ForegroundColor cyan; Read-Host)

                # Check if the input is valid using the Confirm-Choice function
                if (-NOT (Confirm-Choice -Choice $Choice)) {
                    # Write an error message in red if invalid
                    Write-Host -Object "Invalid input. Please enter a number between 1 and $ExitCodeRemovableDriveSelection." -ForegroundColor Red
                }
            } while (-NOT (Confirm-Choice -Choice $Choice))

            # Check if the user entered the exit value to break out of the loop
            if ($Choice -eq $ExitCodeRemovableDriveSelection) {
                break BitLockerCategoryLabel
            }
            else {
                # Get the selected drive from the array and display it
                return ($($AvailableRemovableDrives[$Choice - 1]).DriveLetter + ':')
            }
        }
        function Block-CountryIP {
            <#
    .SYNOPSIS
        A function that gets a list of IP addresses and a name for them, then adds those IP addresses in the firewall block rules
    .NOTES
        -RemoteAddress in New-NetFirewallRule accepts array according to Microsoft Docs,
        so we use "[System.String[]]$IPList = $IPList -split '\r?\n' -ne ''" to convert the IP lists, which is a single multiline string, into an array

        how to query the number of IPs in each rule
        (Get-NetFirewallRule -DisplayName "OFAC Sanctioned Countries IP range blocking" -PolicyStore localhost | Get-NetFirewallAddressFilter).RemoteAddress.count
    .INPUTS
        System.String
        System.String[]
    .OUTPUTS
        System.Void
        #>
            [CmdletBinding()]
            param (
                [parameter(Mandatory = $True)][System.String[]]$IPList,
                [parameter(Mandatory = $True)][System.String]$ListName,
                [Parameter(mandatory = $false)][System.Management.Automation.SwitchParameter]$GUI
            )

            Import-Module -Name NetSecurity -Force

            # converts the list from string to string array
            [System.String[]]$IPList = $IPList -split '\r?\n' -ne ''

            # make sure the list isn't empty
            if ($IPList.count -ne 0) {
                # delete previous rules (if any) to get new up-to-date IP ranges from the sources and set new rules
                Remove-NetFirewallRule -DisplayName "$ListName IP range blocking" -PolicyStore localhost -ErrorAction SilentlyContinue

                [System.Management.Automation.ScriptBlock]$Commands1 = { New-NetFirewallRule -DisplayName "$ListName IP range blocking" -Direction Inbound -Action Block -LocalAddress Any -RemoteAddress $IPList -Description "$ListName IP range blocking" -EdgeTraversalPolicy Block -PolicyStore localhost }
                [System.Management.Automation.ScriptBlock]$Commands2 = { New-NetFirewallRule -DisplayName "$ListName IP range blocking" -Direction Outbound -Action Block -LocalAddress Any -RemoteAddress $IPList -Description "$ListName IP range blocking" -EdgeTraversalPolicy Block -PolicyStore localhost }
                if (-NOT $GUI) { &$Commands1; &$Commands2 } else { &$Commands1 | Out-Null; &$Commands2 | Out-Null }
            }
            else {
                Write-Warning -Message "The IP list was empty, skipping $ListName"
            }
        }
        function Edit-Addons {
            <#
        .SYNOPSIS
            A function to enable or disable Windows features and capabilities.
        .INPUTS
            System.String
        .OUTPUTS
            System.String
        #>
            [CmdletBinding()]
            param (
                [parameter(Mandatory = $true)]
                [ValidateSet('Capability', 'Feature')]
                [System.String]$Type,
                [parameter(Mandatory = $true, ParameterSetName = 'Capability')]
                [System.String]$CapabilityName,
                [parameter(Mandatory = $true, ParameterSetName = 'Feature')]
                [System.String]$FeatureName,
                [parameter(Mandatory = $true, ParameterSetName = 'Feature')]
                [ValidateSet('Enabling', 'Disabling')]
                [System.String]$FeatureAction
            )
            switch ($Type) {
                'Feature' {
                    [System.String]$ActionCheck = ($FeatureAction -eq 'Enabling') ? 'disabled' : 'enabled'
                    [System.String]$ActionOutput = ($FeatureAction -eq 'Enabling') ? 'enabled' : 'disabled'

                    Write-ColorfulText -Color Lavender -InputText "`n$FeatureAction $FeatureName"
                    if ((Get-WindowsOptionalFeature -Online -FeatureName $FeatureName).state -eq $ActionCheck) {
                        try {
                            if ($FeatureAction -eq 'Enabling') {
                                Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -All -NoRestart | Out-Null
                            }
                            else {
                                Disable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart | Out-Null
                            }
                            # Shows the successful message only if the process was successful
                            Write-ColorfulText -Color NeonGreen -InputText "$FeatureName was successfully $ActionOutput"
                        }
                        catch {
                            # show errors in non-terminating way
                            $_
                        }
                    }
                    else {
                        Write-ColorfulText -Color NeonGreen -InputText "$FeatureName is already $ActionOutput"
                    }
                    break
                }
                'Capability' {
                    Write-ColorfulText -Color Lavender -InputText "`nRemoving $CapabilityName"
                    if ((Get-WindowsCapability -Online | Where-Object -FilterScript { $_.Name -like "*$CapabilityName*" }).state -ne 'NotPresent') {
                        try {
                            Get-WindowsCapability -Online | Where-Object -FilterScript { $_.Name -like "*$CapabilityName*" } | Remove-WindowsCapability -Online | Out-Null
                            # Shows the successful message only if the process was successful
                            Write-ColorfulText -Color NeonGreen -InputText "$CapabilityName was successfully removed."
                        }
                        catch {
                            # show errors in non-terminating way
                            $_
                        }
                    }
                    else {
                        Write-ColorfulText -Color NeonGreen -InputText "$CapabilityName is already removed."
                    }
                    break
                }
            }
        }
        Function Write-GUI {
            <#
            .SYNOPSIS
                A function to write text to the GUI. It also saved the text to the log variable used for the log file.
            .INPUTS
                System.String
            #>
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory = $true)][System.String]$Text
            )
            # Add the text to the synchronized array list as log messages
            $SyncHash.Logger.Add([System.String](Get-Date) + ': ' + [System.String]$Text) | Out-Null

            $SyncHash.Window.Dispatcher.Invoke({
                    # Since other output streams such as verbose, error, warning are not converted to strings, we need to convert them manually
                    $SyncHash['GUI']['OutputTextBlock'].Text += [System.String]$Text + "`n"
                    $SyncHash['GUI']['ScrollerForOutputTextBlock'].ScrollToBottom()
                }, [System.Windows.Threading.DispatcherPriority]::Background)
        }
        Function Start-FileDownload {
            <#
            .SYNOPSIS
                Function to download the required files for the Harden-Windows-Security module
                Is used for both CLI and GUI experiences
            .NOTES
                The function does not rely on any script-wide or global variables
            .INPUTS
                System.String
                System.Management.Automation.SwitchParameter
                System.Collections.Hashtable
            .OUTPUTS
                System.Object[]
                Returns array of filepaths when running in CLI experience

            #>
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory = $true)][System.String]$WorkingDir,
                [AllowNull()]
                [Parameter(Mandatory = $false)][System.String]$HardeningModulePath,
                [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$IsLocally,
                [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$Offline,
                [Parameter(Mandatory = $false)][System.Collections.Hashtable]$SyncHash,
                [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$GUI
            )
            try {
                Import-Module -Name 'Microsoft.PowerShell.Archive' -Force
                Write-Verbose -Message 'Downloading the required files'

                # Create an array of files to download
                [System.Object[]]$Files = @(
                    # System.Net.WebClient requires absolute path instead of relative one
                    @{url = 'https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/Windows%2011%20v23H2%20Security%20Baseline.zip'; path = "$WorkingDir\MicrosoftSecurityBaseline.zip"; tag = 'MicrosoftSecurityBaseline' }
                    @{url = 'https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/Microsoft%20365%20Apps%20for%20Enterprise%202306.zip'; path = "$WorkingDir\Microsoft365SecurityBaseline.zip"; tag = 'Microsoft365SecurityBaseline' }
                    @{url = 'https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip'; path = "$WorkingDir\LGPO.zip"; tag = 'LGPO' }
                    @{url = 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/Main%20files/Resources/Security-Baselines-X.zip'; path = "$WorkingDir\Security-Baselines-X.zip"; tag = 'Security-Baselines-X' }
                    @{url = 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/Main%20files/Resources/Registry.csv'; path = "$WorkingDir\Registry.csv"; tag = 'Registry' }
                    @{url = 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/Main%20files/Resources/ProcessMitigations.csv'; path = "$WorkingDir\ProcessMitigations.csv"; tag = 'ProcessMitigations' }
                    @{url = 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/Main%20files/Resources/EventViewerCustomViews.zip'; path = "$WorkingDir\EventViewerCustomViews.zip"; tag = 'EventViewerCustomViews' }
                )

                # Get the total number of files to download based on whether the script is running locally or not
                [System.Int16]$TotalRequiredFiles = $IsLocally ? ($Files.Count - 4) : $Files.Count
                # Initialize a counter for the progress bar
                [System.Int16]$RequiredFilesCounter = 0

                # Start a job for each file download
                [System.Object[]]$Jobs = foreach ($File in $Files) {

                    # If running locally, skip downloading the files that are already shipped with the Harden Windows Security module
                    if ($IsLocally) {
                        if ($File.tag -in @('Security-Baselines-X', 'Registry', 'ProcessMitigations', 'EventViewerCustomViews')) {
                            Write-Verbose -Message "Skipping downloading the $($File.tag) because of local mode."
                            Continue
                        }
                    }
                    # If running in offline mode, skip downloading the files that are manually provided by the user
                    if ($Offline) {
                        if ($File.tag -in @('MicrosoftSecurityBaseline', 'Microsoft365SecurityBaseline', 'LGPO')) {
                            Write-Verbose -Message "Skipping downloading the $($File.tag) because of offline mode."
                            Continue
                        }
                    }

                    Start-Job -ScriptBlock {
                        param([System.Uri]$Url, [System.IO.FileInfo]$Path, [System.String]$Tag)
                        $ErrorActionPreference = 'Stop'

                        # Create a WebClient object
                        [System.Net.WebClient]$WC = New-Object -TypeName System.Net.WebClient
                        try {
                            # Try to download the file from the original URL
                            $WC.DownloadFile($Url, $Path)
                        }
                        catch {
                            # a switch for when the original URLs are failing and to provide Alt URL
                            switch ($Tag) {
                                'Security-Baselines-X' {
                                    Write-Host -Object 'Using Azure DevOps for Security-Baselines-X.zip' -ForegroundColor Yellow
                                    [System.Uri]$AltURL = 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/Payload/Security-Baselines-X.zip'
                                    $WC.DownloadFile($AltURL, $Path)
                                    break
                                }
                                'Registry' {
                                    Write-Host -Object 'Using Azure DevOps for Registry.csv' -ForegroundColor Yellow
                                    [System.Uri]$AltURL = 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/Payload/Registry.csv'
                                    $WC.DownloadFile($AltURL, $Path)
                                    break
                                }
                                'ProcessMitigations' {
                                    Write-Host -Object 'Using Azure DevOps for ProcessMitigations.CSV' -ForegroundColor Yellow
                                    [System.Uri]$AltURL = 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/Payload/ProcessMitigations.csv'
                                    $WC.DownloadFile($AltURL, $Path)
                                    break
                                }
                                'EventViewerCustomViews' {
                                    Write-Host -Object 'Using Azure DevOps for EventViewerCustomViews.zip' -ForegroundColor Yellow
                                    [System.Uri]$AltURL = 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/Payload/EventViewerCustomViews.zip'
                                    $WC.DownloadFile($AltURL, $Path)
                                    break
                                }
                                default {
                                    # Throw the error if any other URL fails and stop the operation
                                    Throw $_
                                }
                            }
                        }
                    } -ArgumentList $File.url, $File.path, $File.tag

                    if (-NOT $GUI) {
                        # Increment the counter by one
                        $RequiredFilesCounter++
                        # Write the progress of the download jobs
                        Write-Progress -Id 1 -ParentId 0 -Activity "Downloading $($file.tag)" -Status "$RequiredFilesCounter of $TotalRequiredFiles" -PercentComplete ($RequiredFilesCounter / $TotalRequiredFiles * 100)
                    }
                }

                # Output and remove jobs as they complete
                foreach ($Job in $Jobs) {
                    # Receive the job output and wait for it to complete before removing it
                    Receive-Job -Job $Job -Wait -AutoRemoveJob
                }

                if (-NOT $GUI) {
                    Write-Progress -Id 1 -ParentId 0 -Activity 'Downloading files completed.' -Completed
                }
            }
            catch {
                Throw 'The required files could not be downloaded, Make sure you have Internet connection.'
            }

            if ($IsLocally) {
                Write-Verbose -Message 'Local Mode; Copying the Security-Baselines-X, Registry, ProcessMitigations and EventViewerCustomViews files from the module folder to the working directory'
                Copy-Item -Path "$HardeningModulePath\Resources\Security-Baselines-X.zip" -Destination "$WorkingDir\Security-Baselines-X.zip"
                Copy-Item -Path "$HardeningModulePath\Resources\Registry.csv" -Destination "$WorkingDir\Registry.csv"
                Copy-Item -Path "$HardeningModulePath\Resources\ProcessMitigations.csv" -Destination "$WorkingDir\ProcessMitigations.csv"
                Copy-Item -Path "$HardeningModulePath\Resources\EventViewerCustomViews.zip" -Destination "$WorkingDir\EventViewerCustomViews.zip"
            }
            if ($Offline) {
                Write-Verbose -Message 'Offline Mode; Copying the Microsoft Security Baselines, Microsoft 365 Apps for Enterprise Security Baselines and LGPO files from the user provided paths to the working directory'
                Copy-Item -Path ($GUI ? $SyncHash['GUI'].LGPOZipTextBox.Text : "$PathToLGPO" ) -Destination "$WorkingDir\LGPO.zip"
                Copy-Item -Path ($GUI ? $SyncHash['GUI'].MicrosoftSecurityBaselineZipTextBox.Text : "$PathToMSFTSecurityBaselines") -Destination "$WorkingDir\MicrosoftSecurityBaseline.zip"
                Copy-Item -Path ($GUI ? $SyncHash['GUI'].Microsoft365AppsSecurityBaselineZipTextBox.Text : "$PathToMSFT365AppsSecurityBaselines" ) -Destination "$WorkingDir\Microsoft365SecurityBaseline.zip"
            }

            Write-Verbose -Message 'Unzipping the archives'
            Expand-Archive -Path "$WorkingDir\MicrosoftSecurityBaseline.zip" -DestinationPath "$WorkingDir\MicrosoftSecurityBaseline" -Force
            Expand-Archive -Path "$WorkingDir\Microsoft365SecurityBaseline.zip" -DestinationPath "$WorkingDir\Microsoft365SecurityBaseline" -Force
            Expand-Archive -Path "$WorkingDir\LGPO.zip" -DestinationPath "$WorkingDir\" -Force
            Expand-Archive -Path "$WorkingDir\Security-Baselines-X.zip" -DestinationPath "$WorkingDir\Security-Baselines-X\" -Force

            # capturing the Microsoft Security Baselines extracted path in a variable using wildcard and storing it in a variable so that we won't need to change anything in the code other than the download link when they are updated
            [System.String]$MicrosoftSecurityBaselinePath = (Get-ChildItem -Directory -Path "$WorkingDir\MicrosoftSecurityBaseline\*\").FullName
            # capturing the Microsoft 365 Security Baselines extracted path in a variable using wildcard and storing it in a variable so that we won't need to change anything in the code other than the download link when they are updated
            [System.String]$Microsoft365SecurityBaselinePath = (Get-ChildItem -Directory -Path "$WorkingDir\Microsoft365SecurityBaseline\*\").FullName
            # Storing the registry CSV file in a variable
            [System.Object[]]$RegistryCSVItems = Import-Csv -Path "$WorkingDir\Registry.csv" -Delimiter ','
            # Storing the LGPO.exe path in a variable
            [System.IO.FileInfo]$LGPOExe = Get-ChildItem -Path "$WorkingDir\LGPO_30\LGPO.exe" -File

            # Copying LGPO.exe from its folder to Microsoft Security Baseline folder in order to get it ready to be used by PowerShell script
            Copy-Item -Path $LGPOExe -Destination "$MicrosoftSecurityBaselinePath\Scripts\Tools"
            # Copying LGPO.exe from its folder to Microsoft Office 365 Apps for Enterprise Security Baseline folder in order to get it ready to be used by PowerShell script
            Copy-Item -Path $LGPOExe -Destination "$Microsoft365SecurityBaselinePath\Scripts\Tools"

            if ($GUI) {
                # These values should be passed to the SyncHash so that they will be imported in the parent RunSpace where the main hardening functions run
                $SyncHash['GlobalVars']['MicrosoftSecurityBaselinePath'] = $MicrosoftSecurityBaselinePath
                $SyncHash['GlobalVars']['Microsoft365SecurityBaselinePath'] = $Microsoft365SecurityBaselinePath
                $SyncHash['GlobalVars']['RegistryCSVItems'] = $RegistryCSVItems
                $SyncHash['GlobalVars']['LGPOExe'] = $LGPOExe
            }
            else {
                Return $MicrosoftSecurityBaselinePath, $Microsoft365SecurityBaselinePath, $RegistryCSVItems, $LGPOExe
            }
            Write-Verbose -Message 'Finished downloading and processing the required files'
        }
        #Endregion Helper-Functions-All-Experiences

        #Region Hardening-Categories-Functions-CLI-Experience
        Function Invoke-MicrosoftSecurityBaselines {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)

            $RefCurrentMainStep.Value++
            $Host.UI.RawUI.WindowTitle = '🔐 Security Baselines'
            Write-Verbose -Message 'Processing the Security Baselines category function'

            :MicrosoftSecurityBaselinesCategoryLabel switch ($RunUnattended ? ($SecBaselines_NoOverrides ? 'Yes' : 'Yes, With the Optional Overrides (Recommended)') : (Select-Option -Options 'Yes', 'Yes, With the Optional Overrides (Recommended)' , 'No', 'Exit' -Message "`nApply Microsoft Security Baseline ?")) {
                'Yes' {
                    Write-Verbose -Message "Changing the current directory to '$MicrosoftSecurityBaselinePath\Scripts\'"
                    Push-Location -Path "$MicrosoftSecurityBaselinePath\Scripts\"

                    Write-Verbose -Message 'Applying the Microsoft Security Baselines without the optional overrides'
                    Write-Progress -Id 0 -Activity 'Microsoft Security Baseline' -Status "Step $($RefCurrentMainStep.Value)/$TotalMainSteps" -PercentComplete ($RefCurrentMainStep.Value / $TotalMainSteps * 100)

                    Write-Verbose -Message 'Running the official PowerShell script included in the Microsoft Security Baseline file downloaded from Microsoft servers'
                    .\Baseline-LocalInstall.ps1 -Win11NonDomainJoined 4>$null
                }
                'Yes, With the Optional Overrides (Recommended)' {
                    Write-Verbose -Message "Changing the current directory to '$MicrosoftSecurityBaselinePath\Scripts\'"
                    Push-Location -Path "$MicrosoftSecurityBaselinePath\Scripts\"

                    Write-Verbose -Message 'Applying the Microsoft Security Baselines with the optional overrides'
                    Write-Progress -Id 0 -Activity 'Microsoft Security Baseline' -Status "Step $($RefCurrentMainStep.Value)/$TotalMainSteps" -PercentComplete ($RefCurrentMainStep.Value / $TotalMainSteps * 100)

                    Write-Verbose -Message 'Running the official PowerShell script included in the Microsoft Security Baseline file downloaded from Microsoft servers'
                    .\Baseline-LocalInstall.ps1 -Win11NonDomainJoined 4>$null

                    Start-Sleep -Seconds 1

                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Overrides for Microsoft Security Baseline\registry.pol"
                    &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\Overrides for Microsoft Security Baseline\GptTmpl.inf"

                    Write-Verbose -Message 'Re-enabling the XblGameSave Standby Task that gets disabled by Microsoft Security Baselines'
                    SCHTASKS.EXE /Change /TN \Microsoft\XblGameSave\XblGameSaveTask /Enable
                }
                'No' { break MicrosoftSecurityBaselinesCategoryLabel }
                'Exit' { break MainSwitchLabel }
            }

            Write-Verbose -Message 'Restoring the original directory location'
            Pop-Location
        }
        Function Invoke-Microsoft365AppsSecurityBaselines {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)

            $RefCurrentMainStep.Value++
            $Host.UI.RawUI.WindowTitle = '🧁 M365 Apps Security'
            Write-Verbose -Message 'Processing the M365 Apps Security category function'

            :Microsoft365AppsSecurityBaselinesCategoryLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply Microsoft 365 Apps Security Baseline ?")) {
                'Yes' {
                    Write-Verbose -Message 'Applying the Microsoft 365 Apps Security Baseline'
                    Write-Progress -Id 0 -Activity 'Microsoft 365 Apps Security Baseline' -Status "Step $($RefCurrentMainStep.Value)/$TotalMainSteps" -PercentComplete ($RefCurrentMainStep.Value / $TotalMainSteps * 100)

                    Write-Verbose -Message "Changing the current directory to '$Microsoft365SecurityBaselinePath\Scripts\'"
                    Push-Location -Path "$Microsoft365SecurityBaselinePath\Scripts\"

                    Write-Verbose -Message 'Running the official PowerShell script included in the Microsoft 365 Apps Security Baseline file downloaded from Microsoft servers'
                    .\Baseline-LocalInstall.ps1 4>$null

                    Write-Verbose -Message 'Restoring the original directory location'
                    Pop-Location

                } 'No' { break Microsoft365AppsSecurityBaselinesCategoryLabel }
                'Exit' { break MainSwitchLabel }
            }
        }
        Function Invoke-MicrosoftDefender {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)

            $RefCurrentMainStep.Value++
            $Host.UI.RawUI.WindowTitle = '🍁 MSFT Defender'
            Write-Verbose -Message 'Processing the Microsoft Defender category function'

            :MicrosoftDefenderLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Microsoft Defender category ?")) {
                'Yes' {
                    Write-Verbose -Message 'Running the Microsoft Defender category'
                    Write-Progress -Id 0 -Activity 'Microsoft Defender' -Status "Step $($RefCurrentMainStep.Value)/$TotalMainSteps" -PercentComplete ($RefCurrentMainStep.Value / $TotalMainSteps * 100)

                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Microsoft Defender Policies\registry.pol"

                    # Make sure the parameters are available in the ConfigDefender module before using them
                    [System.Collections.Hashtable]$AvailableDefenderParams = (Get-Command -Name Set-MpPreference).Parameters
                    Function Set-DefenderConfigWithCheck {
                        Param ([System.String]$Name, $Value)
                        if ($AvailableDefenderParams.ContainsKey($Name)) {
                            [System.Collections.Hashtable]$Params = @{$Name = $Value }
                            Set-MpPreference @Params
                        }
                        else {
                            Write-Warning -Message "The parameter $Name is not available yet, restart the OS one more time after updating and try again."
                        }
                    }

                    Write-Verbose -Message 'Optimizing Network Protection Performance of the Microsoft Defender'
                    Set-DefenderConfigWithCheck -Name 'AllowSwitchToAsyncInspection' -Value $True

                    Write-Verbose -Message 'Enabling Real-time protection and Security Intelligence Updates during OOBE'
                    Set-DefenderConfigWithCheck -Name 'OobeEnableRtpAndSigUpdate' -Value $True

                    Write-Verbose -Message 'Enabling Intel Threat Detection Technology'
                    Set-DefenderConfigWithCheck -Name 'IntelTDTEnabled' -Value $True

                    Write-Verbose -Message 'Enabling Restore point scan'
                    Set-DefenderConfigWithCheck -Name 'DisableRestorePoint' -Value $False

                    Write-Verbose -Message 'Disabling Performance mode of Defender that only applies to Dev drives by lowering security'
                    Set-DefenderConfigWithCheck -Name 'PerformanceModeStatus' -Value Disabled

                    Write-Verbose -Message 'Setting the Network Protection to block network traffic instead of displaying a warning'
                    Set-DefenderConfigWithCheck -Name 'EnableConvertWarnToBlock' -Value $True

                    Write-Verbose -Message 'Setting the Brute-Force Protection to use cloud aggregation to block IP addresses that are over 99% likely malicious'
                    Set-DefenderConfigWithCheck -Name 'BruteForceProtectionAggressiveness' -Value 1 # 2nd level aggression will come after further testing

                    Write-Verbose -Message 'Setting the Brute-Force Protection to prevent suspicious and malicious behaviors'
                    Set-DefenderConfigWithCheck -Name 'BruteForceProtectionConfiguredState' -Value 1

                    Write-Verbose -Message 'Setting the internal feature logic to determine blocking time for the Brute-Force Protections'
                    Set-DefenderConfigWithCheck -Name 'BruteForceProtectionMaxBlockTime' -Value 0

                    Write-Verbose -Message 'Setting the Remote Encryption Protection to use cloud intel and context, and block when confidence level is above 90%'
                    Set-DefenderConfigWithCheck -Name 'RemoteEncryptionProtectionAggressiveness' -Value 2

                    Write-Verbose -Message 'Setting the Remote Encryption Protection to prevent suspicious and malicious behaviors'
                    Set-DefenderConfigWithCheck -Name 'RemoteEncryptionProtectionConfiguredState' -Value 1

                    Write-Verbose -Message 'Setting the internal feature logic to determine blocking time for the Remote Encryption Protection'
                    Set-DefenderConfigWithCheck -Name 'RemoteEncryptionProtectionMaxBlockTime' -Value 0

                    Write-Verbose -Message 'Adding OneDrive folders of all the user accounts (personal and work accounts) to the Controlled Folder Access for Ransomware Protection'
                    Get-ChildItem -Path "$env:SystemDrive\Users\*\OneDrive*\" -Directory | ForEach-Object -Process { Add-MpPreference -ControlledFolderAccessProtectedFolders $_ }

                    Write-Verbose -Message 'Enabling Mandatory ASLR Exploit Protection system-wide'
                    Set-ProcessMitigation -System -Enable ForceRelocateImages

                    Write-Verbose -Message 'Applying the Process Mitigations'
                    [System.Object[]]$ProcessMitigations = Import-Csv -Path "$WorkingDir\ProcessMitigations.csv" -Delimiter ','

                    # Group the data by ProgramName
                    [System.Object[]]$GroupedMitigations = $ProcessMitigations | Group-Object -Property ProgramName
                    # Get the current process mitigations
                    [System.Object[]]$AllAvailableMitigations = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*')

                    # Loop through each group to remove the mitigations, this way we apply clean set of mitigations in the next step
                    Write-Verbose -Message 'Removing the existing process mitigations'
                    foreach ($Group in $GroupedMitigations) {
                        # To separate the filename from full path of the item in the CSV and then check whether it exists in the system registry
                        if ($Group.Name -match '\\([^\\]+)$') {
                            if ($Matches[1] -in $AllAvailableMitigations.pschildname) {
                                try {
                                    Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($Matches[1])" -Recurse -Force
                                }
                                catch {
                                    Write-Verbose -Message "Failed to remove $($Matches[1]), it's probably protected by the system."
                                }
                            }
                        }
                        elseif ($Group.Name -in $AllAvailableMitigations.pschildname) {
                            try {
                                Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($Group.Name)" -Recurse -Force
                            }
                            catch {
                                Write-Verbose -Message "Failed to remove $($Group.Name), it's probably protected by the system."
                            }
                        }
                    }

                    Write-Verbose -Message 'Adding the process mitigations'
                    foreach ($Group in $GroupedMitigations) {
                        # Get the program name
                        [System.String]$ProgramName = $Group.Name

                        Write-Verbose -Message "Adding process mitigations for $ProgramName"

                        # Get the list of mitigations to enable
                        [System.String[]]$EnableMitigations = $Group.Group | Where-Object -FilterScript { $_.Action -eq 'Enable' } | Select-Object -ExpandProperty Mitigation

                        # Get the list of mitigations to disable
                        [System.String[]]$DisableMitigations = $Group.Group | Where-Object -FilterScript { $_.Action -eq 'Disable' } | Select-Object -ExpandProperty Mitigation

                        # Call the Set-ProcessMitigation cmdlet with the lists of mitigations
                        if ($null -ne $EnableMitigations) {
                            if ($null -ne $DisableMitigations) {
                                Set-ProcessMitigation -Name $ProgramName -Enable $EnableMitigations -Disable $DisableMitigations
                            }
                            else {
                                Set-ProcessMitigation -Name $ProgramName -Enable $EnableMitigations
                            }
                        }
                        elseif ($null -ne $DisableMitigations) {
                            Set-ProcessMitigation -Name $ProgramName -Disable $DisableMitigations
                        }
                    }

                    Write-Verbose -Message 'Turning on Data Execution Prevention (DEP) for all applications, including 32-bit programs'
                    # Old method: bcdedit.exe /set '{current}' nx AlwaysOn | Out-Null
                    # New method using PowerShell cmdlets added in Windows 11
                    Set-BcdElement -Element 'nx' -Type 'Integer' -Value '3' -Force

                    # Suggest turning on Smart App Control only if it's in Eval mode
                    if ((Get-MpComputerStatus).SmartAppControlState -eq 'Eval') {
                        :SmartAppControlLabel switch ($RunUnattended ? ($MSFTDefender_SAC ? 'Yes' : 'No' ) : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nTurn on Smart App Control ?")) {
                            'Yes' {
                                Write-Verbose -Message 'Turning on Smart App Control'
                                Edit-Registry -path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Policy' -key 'VerifiedAndReputablePolicyState' -value '1' -type 'DWORD' -Action 'AddOrModify'

                                # Let the optional diagnostic data be enabled automatically
                                $ShouldEnableOptionalDiagnosticData = $True
                            } 'No' { break SmartAppControlLabel }
                            'Exit' { break MainSwitchLabel }
                        }
                    }

                    if (($ShouldEnableOptionalDiagnosticData -eq $True) -or ((Get-MpComputerStatus).SmartAppControlState -eq 'On')) {
                        Write-Verbose -Message 'Enabling Optional Diagnostic Data because SAC is on or user selected to turn it on'
                        &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Microsoft Defender Policies\Optional Diagnostic Data\registry.pol"
                    }
                    else {
                        # Ask user if they want to turn on optional diagnostic data only if Smart App Control is not already turned off
                        if ((Get-MpComputerStatus).SmartAppControlState -ne 'Off') {
                            :SmartAppControlLabel2 switch ($RunUnattended ? ($MSFTDefender_NoDiagData ? 'No' : 'Yes') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nEnable Optional Diagnostic Data ?" -ExtraMessage 'Required for Smart App Control usage and evaluation, read the GitHub Readme!')) {
                                'Yes' {
                                    Write-Verbose -Message 'Enabling Optional Diagnostic Data'
                                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Microsoft Defender Policies\Optional Diagnostic Data\registry.pol"
                                } 'No' { break SmartAppControlLabel2 }
                                'Exit' { break MainSwitchLabel }
                            }
                        }
                        else {
                            Write-Verbose -Message 'Smart App Control is turned off, so Optional Diagnostic Data will not be enabled'
                        }
                    }

                    Write-Verbose -Message 'Getting the state of fast weekly Microsoft recommended driver block list update scheduled task'
                    [System.String]$BlockListScheduledTaskState = (Get-ScheduledTask -TaskName 'MSFT Driver Block list update' -TaskPath '\MSFT Driver Block list update\' -ErrorAction SilentlyContinue).State

                    # Create scheduled task for fast weekly Microsoft recommended driver block list update if it doesn't exist or exists but is not Ready/Running
                    if (($BlockListScheduledTaskState -notin 'Ready', 'Running')) {
                        :TaskSchedulerCreationLabel switch ($RunUnattended ? ($MSFTDefender_NoScheduledTask ? 'No' : 'Yes') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nCreate scheduled task for fast weekly Microsoft recommended driver block list update ?")) {
                            'Yes' {
                                Write-Verbose -Message 'Creating scheduled task for fast weekly Microsoft recommended driver block list update'

                                # Create a scheduled task action, this defines how to download and install the latest Microsoft Recommended Driver Block Rules
                                [Microsoft.Management.Infrastructure.CimInstance]$Action = New-ScheduledTaskAction -Execute 'Powershell.exe' `
                                    -Argument '-NoProfile -WindowStyle Hidden -command "& {try {Invoke-WebRequest -Uri "https://aka.ms/VulnerableDriverBlockList" -OutFile VulnerableDriverBlockList.zip -ErrorAction Stop}catch{exit 1};Expand-Archive -Path .\VulnerableDriverBlockList.zip -DestinationPath "VulnerableDriverBlockList" -Force;Rename-Item -Path .\VulnerableDriverBlockList\SiPolicy_Enforced.p7b -NewName "SiPolicy.p7b" -Force;Copy-Item -Path .\VulnerableDriverBlockList\SiPolicy.p7b -Destination "$env:SystemDrive\Windows\System32\CodeIntegrity" -Force;citool --refresh -json;Remove-Item -Path .\VulnerableDriverBlockList -Recurse -Force;Remove-Item -Path .\VulnerableDriverBlockList.zip -Force; exit 0;}"'

                                # Create a scheduled task principal and assign the SYSTEM account's well-known SID to it so that the task will run under its context
                                [Microsoft.Management.Infrastructure.CimInstance]$TaskPrincipal = New-ScheduledTaskPrincipal -LogonType S4U -UserId 'S-1-5-18' -RunLevel Highest

                                # Create a trigger for the scheduled task. The task will first run one hour after its creation and from then on will run every 7 days, indefinitely
                                [Microsoft.Management.Infrastructure.CimInstance]$Time = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1) -RepetitionInterval (New-TimeSpan -Days 7)

                                # Register the scheduled task
                                Register-ScheduledTask -Action $Action -Trigger $Time -Principal $TaskPrincipal -TaskPath 'MSFT Driver Block list update' -TaskName 'MSFT Driver Block list update' -Description 'Microsoft Recommended Driver Block List update' -Force

                                # Define advanced settings for the scheduled task
                                [Microsoft.Management.Infrastructure.CimInstance]$TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility 'Win8' -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -RestartCount 4 -RestartInterval (New-TimeSpan -Hours 6) -RunOnlyIfNetworkAvailable

                                # Add the advanced settings we defined above to the scheduled task
                                Set-ScheduledTask -TaskName 'MSFT Driver Block list update' -TaskPath 'MSFT Driver Block list update' -Settings $TaskSettings
                            } 'No' { break TaskSchedulerCreationLabel }
                            'Exit' { break MainSwitchLabel }
                        }
                    }
                    else {
                        Write-Verbose -Message "Scheduled task for fast weekly Microsoft recommended driver block list update already exists and is in $BlockListScheduledTaskState state"
                    }

                    # Only display this prompt if Engine and Platform update channels are not already set to Beta
                    if (($MDAVPreferencesCurrent.EngineUpdatesChannel -ne '2') -or ($MDAVPreferencesCurrent.PlatformUpdatesChannel -ne '2')) {
                        # Set Microsoft Defender engine and platform update channel to beta - Devices in the Windows Insider Program are subscribed to this channel by default.
                        :DefenderUpdateChannelsLabel switch ($RunUnattended ? ($MSFTDefender_BetaChannels ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nSet Microsoft Defender engine and platform update channel to beta ?")) {
                            'Yes' {
                                Write-Verbose -Message 'Setting Microsoft Defender engine and platform update channel to beta'
                                Set-MpPreference -EngineUpdatesChannel beta
                                Set-MpPreference -PlatformUpdatesChannel beta
                            } 'No' { break DefenderUpdateChannelsLabel }
                            'Exit' { break MainSwitchLabel }
                        }
                    }
                    else {
                        Write-Verbose -Message 'Microsoft Defender engine and platform update channel is already set to beta'
                    }

                } 'No' { break MicrosoftDefenderLabel }
                'Exit' { break MainSwitchLabel }
            }
        }
        Function Invoke-AttackSurfaceReductionRules {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)

            $RefCurrentMainStep.Value++
            $Host.UI.RawUI.WindowTitle = '🪷 ASR Rules'
            Write-Verbose -Message 'Processing the ASR Rules category function'

            :ASRRulesCategoryLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Attack Surface Reduction Rules category ?")) {
                'Yes' {
                    Write-Verbose -Message 'Running the Attack Surface Reduction Rules category'
                    Write-Progress -Id 0 -Activity 'Attack Surface Reduction Rules' -Status "Step $($RefCurrentMainStep.Value)/$TotalMainSteps" -PercentComplete ($RefCurrentMainStep.Value / $TotalMainSteps * 100)

                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Attack Surface Reduction Rules Policies\registry.pol"
                } 'No' { break ASRRulesCategoryLabel }
                'Exit' { break MainSwitchLabel }
            }
        }
        Function Invoke-BitLockerSettings {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)

            $RefCurrentMainStep.Value++
            $Host.UI.RawUI.WindowTitle = '🔑 BitLocker'
            Write-Verbose -Message 'Processing the BitLocker category function'

            :BitLockerCategoryLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Bitlocker category ?")) {
                'Yes' {
                    Write-Verbose -Message 'Running the Bitlocker category'
                    Write-Progress -Id 0 -Activity 'Bitlocker Settings' -Status "Step $($RefCurrentMainStep.Value)/$TotalMainSteps" -PercentComplete ($RefCurrentMainStep.Value / $TotalMainSteps * 100)

                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Bitlocker Policies\registry.pol"

                    # This PowerShell script can be used to find out if the DMA Protection is ON \ OFF.
                    # The Script will show this by emitting True \ False for On \ Off respectively.

                    # if the type is not already loaded, load it
                    if (-NOT ('SystemInfo.NativeMethods' -as [System.Type])) {
                        Write-Verbose -Message 'Loading SystemInfo.NativeMethods type'
                        Add-Type -TypeDefinition $BootDMAProtectionCheck -Language CSharp -Verbose:$false
                    }
                    else {
                        Write-Verbose -Message 'SystemInfo.NativeMethods type is already loaded, skipping loading it again.'
                    }

                    # returns true or false depending on whether Kernel DMA Protection is on or off
                    [System.Boolean]$BootDMAProtection = ([SystemInfo.NativeMethods]::BootDmaCheck()) -ne 0

                    # Enables or disables DMA protection from Bitlocker Countermeasures based on the status of Kernel DMA protection.
                    if ($BootDMAProtection) {
                        Write-Host -Object 'Kernel DMA protection is enabled on the system, disabling Bitlocker DMA protection.' -ForegroundColor Blue
                        &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Overrides for Microsoft Security Baseline\Bitlocker DMA\Bitlocker DMA Countermeasure OFF\Registry.pol"
                    }
                    else {
                        Write-Host -Object 'Kernel DMA protection is unavailable on the system, enabling Bitlocker DMA protection.' -ForegroundColor Blue
                        &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Overrides for Microsoft Security Baseline\Bitlocker DMA\Bitlocker DMA Countermeasure ON\Registry.pol"
                    }

                    # Make sure there is no CD/DVD drives or mounted ISO in the system, because BitLocker throws an error when there is
                    if ((Get-CimInstance -ClassName Win32_CDROMDrive -Property *).MediaLoaded) {
                        Write-Warning -Message 'Remove any CD/DVD drives or mounted images/ISO from the system and run the Bitlocker category again.'
                        # break from the entire BitLocker category and continue to the next category
                        break BitLockerCategoryLabel
                    }

                    # check make sure Bitlocker isn't in the middle of decryption/encryption operation (on System Drive)
                    if ((Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionPercentage -notin '100', '0') {
                        $EncryptionPercentageVar = (Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionPercentage
                        Write-Host -Object "`nPlease wait for Bitlocker to finish encrypting or decrypting the Operation System Drive." -ForegroundColor Yellow
                        Write-Host -Object "Drive $env:SystemDrive encryption is currently at $EncryptionPercentageVar percent." -ForegroundColor Yellow
                        # break from the entire BitLocker category and continue to the next category
                        break BitLockerCategoryLabel
                    }

                    # A script block that generates recovery codes just like Windows does
                    [System.Management.Automation.ScriptBlock]$RecoveryPasswordContentGenerator = {
                        param ([System.Object[]]$KeyProtectorsInputFromScriptBlock)

                        return @"
BitLocker Drive Encryption recovery key

To verify that this is the correct recovery key, compare the start of the following identifier with the identifier value displayed on your PC.

Identifier:

        $(($KeyProtectorsInputFromScriptBlock | Where-Object -FilterScript { $_.keyprotectortype -eq 'RecoveryPassword' }).KeyProtectorId.Trim('{', '}'))

If the above identifier matches the one displayed by your PC, then use the following key to unlock your drive.

Recovery Key:

        $(($KeyProtectorsInputFromScriptBlock | Where-Object -FilterScript { $_.keyprotectortype -eq 'RecoveryPassword' }).RecoveryPassword)

If the above identifier doesn't match the one displayed by your PC, then this isn't the right key to unlock your drive.
Try another recovery key, or refer to https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/recovery-overview for additional assistance.

IMPORTANT: Make sure to keep it in a safe place, e.g., in OneDrive's Personal Vault which requires additional authentication to access.

"@
                    }

                    :OSDriveEncryptionLabel switch ($RunUnattended ? 'Skip encryptions altogether' : (Select-Option -SubCategory -Options 'Normal: TPM + Startup PIN + Recovery Password', 'Enhanced: TPM + Startup PIN + Startup Key + Recovery Password', 'Skip encryptions altogether', 'Exit' -Message "`nPlease select your desired security level" -ExtraMessage "If you are not sure, refer to the BitLocker category in the GitHub Readme`n")) {
                        'Normal: TPM + Startup PIN + Recovery Password' {

                            # check if Bitlocker is enabled for the system drive with Normal security level
                            if ((Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus -eq 'on') {

                                # Get the OS Drive's encryption method
                                [System.String]$EncryptionMethodOSDrive = (Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionMethod

                                # Check OS Drive's encryption method and display a warning if it's not the most secure one
                                if ($EncryptionMethodOSDrive -ine 'XtsAes256') {
                                    Write-Warning -Message "The OS Drive is encrypted with the less secure '$EncryptionMethodOSDrive' encryption method instead of 'XtsAes256'"
                                }

                                # Get the key protectors of the OS Drive
                                [System.Object[]]$KeyProtectorsOSDrive = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector
                                # Get the key protector types of the OS Drive
                                [System.String[]]$KeyProtectorTypesOSDrive = $KeyProtectorsOSDrive.keyprotectortype

                                if ($KeyProtectorTypesOSDrive -contains 'TpmPinStartupKey' -and $KeyProtectorTypesOSDrive -contains 'recoveryPassword') {

                                    switch (Select-Option -SubCategory -Options 'Yes', 'Skip OS Drive' , 'Exit' -Message "`nThe OS Drive is already encrypted with Enhanced Security level." -ExtraMessage "Are you sure you want to change it to Normal Security level?`n" ) {
                                        'Skip OS Drive' { break OSDriveEncryptionLabel }
                                        'Exit' { break MainSwitchLabel }
                                    }
                                }

                                # check if TPM + PIN + recovery password are being used as key protectors for the OS Drive
                                if ($KeyProtectorTypesOSDrive -contains 'Tpmpin' -and $KeyProtectorTypesOSDrive -contains 'recoveryPassword') {

                                    Write-ColorfulText -C MintGreen -I 'Bitlocker is already enabled for the OS drive with Normal security level.'

                                    Write-ColorfulText -C Fuchsia -I 'Here is your 48-digits recovery password for the OS drive in case you were looking for it:'
                                    Write-ColorfulText -C Rainbow -I "$(($KeyProtectorsOSDrive | Where-Object -FilterScript { $_.keyprotectortype -eq 'RecoveryPassword' }).RecoveryPassword)"
                                }
                                else {

                                    # If the OS Drive doesn't have recovery password key protector
                                    if ($KeyProtectorTypesOSDrive -notcontains 'recoveryPassword') {

                                        [System.String]$BitLockerMsg = "`nThe recovery password is missing, adding it now... `n" +
                                        "It will be saved in a text file in '$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt'"
                                        Write-Host -Object $BitLockerMsg -ForegroundColor Yellow

                                        # Add RecoveryPasswordProtector key protector to the OS drive
                                        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> $null

                                        # Get the new key protectors of the OS Drive after adding RecoveryPasswordProtector to it
                                        [System.Object[]]$KeyProtectorsOSDrive = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector

                                        # Backup the recovery code of the OS drive in a file
                                        New-Item -Path "$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsOSDrive) -ItemType File -Force | Out-Null
                                    }

                                    # If the OS Drive doesn't have (TPM + PIN) key protector
                                    if ($KeyProtectorTypesOSDrive -notcontains 'Tpmpin') {

                                        Write-Host -Object "`nTPM and Start up PIN are missing, adding them now..." -ForegroundColor Cyan

                                        do {
                                            [System.Security.SecureString]$Pin1 = $(Write-ColorfulText -C PinkBold -I "`nEnter a Pin for Bitlocker startup (between 10 to 20 characters)"; Read-Host -AsSecureString)
                                            [System.Security.SecureString]$Pin2 = $(Write-ColorfulText -C PinkBold -I 'Confirm your Bitlocker Startup Pin (between 10 to 20 characters)'; Read-Host -AsSecureString)

                                            # Compare the PINs and make sure they match
                                            [System.Boolean]$TheyMatch = Compare-SecureString -SecureString1 $Pin1 -SecureString2 $Pin2
                                            # If the PINs match and they are at least 10 characters long, max 20 characters
                                            if ( $TheyMatch -and ($Pin1.Length -in 10..20) -and ($Pin2.Length -in 10..20) ) {
                                                [System.Security.SecureString]$Pin = $Pin1
                                            }
                                            else { Write-Host -Object 'Please ensure that the PINs you entered match, and that they are between 10 to 20 characters.' -ForegroundColor red }
                                        }
                                        # Repeat this process until the entered PINs match and they are at least 10 characters long, max 20 characters
                                        until ( $TheyMatch -and ($Pin1.Length -in 10..20) -and ($Pin2.Length -in 10..20) )

                                        try {
                                            # Add TPM + PIN key protectors to the OS Drive
                                            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmAndPinProtector -Pin $Pin | Out-Null
                                            Write-ColorfulText -C MintGreen -I "`nPINs matched, enabling TPM and startup PIN now`n"
                                        }
                                        catch {
                                            Write-Host -Object 'These errors occurred, run Bitlocker category again after meeting the requirements' -ForegroundColor Red
                                            # Display errors in non-terminating way
                                            $_
                                            break BitLockerCategoryLabel
                                        }

                                        # Get the key protectors of the OS Drive
                                        [System.Object[]]$KeyProtectorsOSDrive = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector

                                        # Backup the recovery code of the OS drive in a file just in case - This is for when the disk is automatically encrypted and using TPM + Recovery code by default
                                        New-Item -Path "$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsOSDrive) -ItemType File -Force | Out-Null

                                        Write-Host -Object "The recovery password was backed up in a text file in '$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt'" -ForegroundColor Cyan
                                    }
                                }
                            }

                            # Do this if Bitlocker is not enabled for the OS drive at all
                            else {
                                Write-Host -Object "`nBitlocker is not enabled for the OS Drive, activating it now..." -ForegroundColor Yellow
                                do {
                                    [System.Security.SecureString]$Pin1 = $(Write-ColorfulText -C PinkBold -I 'Enter a Pin for Bitlocker startup (between 10 to 20 characters)'; Read-Host -AsSecureString)
                                    [System.Security.SecureString]$Pin2 = $(Write-ColorfulText -C PinkBold -I 'Confirm your Bitlocker Startup Pin (between 10 to 20 characters)'; Read-Host -AsSecureString)

                                    [System.Boolean]$TheyMatch = Compare-SecureString -SecureString1 $Pin1 -SecureString2 $Pin2

                                    if ( $TheyMatch -and ($Pin1.Length -in 10..20) -and ($Pin2.Length -in 10..20) ) {
                                        [System.Security.SecureString]$Pin = $Pin1
                                    }
                                    else { Write-Host -Object 'Please ensure that the PINs you entered match, and that they are between 10 to 20 characters.' -ForegroundColor red }
                                }
                                until ( $TheyMatch -and ($Pin1.Length -in 10..20) -and ($Pin2.Length -in 10..20) )

                                try {
                                    # Enable BitLocker for the OS Drive with TPM + PIN key protectors
                                    Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod 'XtsAes256' -Pin $Pin -TpmAndPinProtector -SkipHardwareTest *> $null
                                }
                                catch {
                                    Write-Host -Object 'These errors occurred, run Bitlocker category again after meeting the requirements' -ForegroundColor Red
                                    $_
                                    break BitLockerCategoryLabel
                                }
                                # Add recovery password key protector to the OS Drive
                                Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> $null

                                # Get the new key protectors of the OS Drive after adding RecoveryPasswordProtector to it
                                [System.Object[]]$KeyProtectorsOSDrive = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector

                                # Backup the recovery code of the OS drive in a file
                                New-Item -Path "$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsOSDrive) -ItemType File -Force | Out-Null

                                Resume-BitLocker -MountPoint $env:SystemDrive | Out-Null

                                Write-ColorfulText -C MintGreen -I "`nBitlocker is now enabled for the OS drive with Normal security level."
                                Write-Host -Object "The recovery password will be saved in a text file in '$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt'" -ForegroundColor Cyan
                            }

                        }
                        'Enhanced: TPM + Startup PIN + Startup Key + Recovery Password' {

                            # check if Bitlocker is enabled for the system drive with Enhanced security level
                            if ((Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus -eq 'on') {

                                # Get the OS Drive's encryption method
                                [System.String]$EncryptionMethodOSDrive = (Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionMethod

                                # Check OS Drive's encryption method and display a warning if it's not the most secure one
                                if ($EncryptionMethodOSDrive -ine 'XtsAes256') {
                                    Write-Warning -Message "The OS Drive is encrypted with the less secure '$EncryptionMethodOSDrive' encryption method instead of 'XtsAes256'"
                                }

                                # Get the key protectors of the OS Drive
                                [System.Object[]]$KeyProtectorsOSDrive = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector
                                # Get the key protector types of the OS Drive
                                [System.String[]]$KeyProtectorTypesOSDrive = $KeyProtectorsOSDrive.keyprotectortype

                                # check if TPM + PIN + recovery password are being used as key protectors for the OS Drive
                                if ($KeyProtectorTypesOSDrive -contains 'TpmPinStartupKey' -and $KeyProtectorTypesOSDrive -contains 'recoveryPassword') {

                                    Write-ColorfulText -C MintGreen -I 'Bitlocker is already enabled for the OS drive with Enhanced security level.'

                                    Write-ColorfulText -C Fuchsia -I 'Here is your 48-digits recovery password for the OS drive in case you were looking for it:'
                                    Write-ColorfulText -C Rainbow -I "$(($KeyProtectorsOSDrive | Where-Object -FilterScript { $_.keyprotectortype -eq 'RecoveryPassword' }).RecoveryPassword)"
                                }
                                else {

                                    # If the OS Drive doesn't have recovery password key protector
                                    if ($KeyProtectorTypesOSDrive -notcontains 'recoveryPassword') {

                                        [System.String]$BitLockerMsg = "`nThe recovery password is missing, adding it now... `n" +
                                        "It will be saved in a text file in '$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt'"
                                        Write-Host -Object $BitLockerMsg -ForegroundColor Yellow

                                        # Add RecoveryPasswordProtector key protector to the OS drive
                                        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> $null

                                        # Get the new key protectors of the OS Drive after adding RecoveryPasswordProtector to it
                                        [System.Object[]]$KeyProtectorsOSDrive = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector

                                        # Backup the recovery code of the OS drive in a file
                                        New-Item -Path "$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsOSDrive) -ItemType File -Force | Out-Null

                                    }

                                    # If the OS Drive doesn't have (TpmPinStartupKey) key protector
                                    if ($KeyProtectorTypesOSDrive -notcontains 'TpmPinStartupKey') {

                                        Write-ColorfulText -C Violet -I "`nTpm And Pin And StartupKey Protector is missing from the OS Drive, adding it now"

                                        # Check if the OS drive has ExternalKey key protector and if it does remove it
                                        # It's the standalone Startup Key protector which isn't secure on its own for the OS Drive
                                        if ($KeyProtectorTypesOSDrive -contains 'ExternalKey') {

                                                    (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector |
                                            Where-Object -FilterScript { $_.keyprotectortype -eq 'ExternalKey' } |
                                            ForEach-Object -Process { Remove-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $_.KeyProtectorId | Out-Null }
                                        }

                                        do {
                                            [System.Security.SecureString]$Pin1 = $(Write-ColorfulText -C PinkBold -I "`nEnter a Pin for Bitlocker startup (between 10 to 20 characters)"; Read-Host -AsSecureString)
                                            [System.Security.SecureString]$Pin2 = $(Write-ColorfulText -C PinkBold -I 'Confirm your Bitlocker Startup Pin (between 10 to 20 characters)'; Read-Host -AsSecureString)

                                            # Compare the PINs and make sure they match
                                            [System.Boolean]$TheyMatch = Compare-SecureString -SecureString1 $Pin1 -SecureString2 $Pin2
                                            # If the PINs match and they are at least 10 characters long, max 20 characters
                                            if ( $TheyMatch -and ($Pin1.Length -in 10..20) -and ($Pin2.Length -in 10..20) ) {
                                                [System.Security.SecureString]$Pin = $Pin1
                                            }
                                            else { Write-Host -Object 'Please ensure that the PINs you entered match, and that they are between 10 to 20 characters.' -ForegroundColor red }
                                        }
                                        # Repeat this process until the entered PINs match and they are at least 10 characters long, max 20 characters
                                        until ( $TheyMatch -and ($Pin1.Length -in 10..20) -and ($Pin2.Length -in 10..20) )

                                        Write-ColorfulText -C MintGreen -I "`nPINs matched, enabling TPM, Startup PIN and Startup Key protector now`n"

                                        try {
                                            # Add TpmAndPinAndStartupKeyProtector to the OS Drive
                                            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmAndPinAndStartupKeyProtector -StartupKeyPath (Get-AvailableRemovableDrives) -Pin $Pin | Out-Null
                                        }
                                        catch {
                                            Write-Host -Object 'There was a problem adding Startup Key to the removable drive, try ejecting and reinserting the flash drive into your device and run this category again.' -ForegroundColor Red
                                            $_
                                            break BitLockerCategoryLabel
                                        }

                                        # Get the key protectors of the OS Drive
                                        [System.Object[]]$KeyProtectorsOSDrive = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector

                                        # Backup the recovery code of the OS drive in a file just in case - This is for when the disk is automatically encrypted and using TPM + Recovery code by default
                                        New-Item -Path "$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsOSDrive) -ItemType File -Force | Out-Null

                                        Write-Host -Object "The recovery password was backed up in a text file in '$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt'" -ForegroundColor Cyan

                                    }
                                }
                            }

                            # Do this if Bitlocker is not enabled for the OS drive at all
                            else {
                                Write-Host -Object "`nBitlocker is not enabled for the OS Drive, activating it now..." -ForegroundColor Yellow

                                do {
                                    [System.Security.SecureString]$Pin1 = $(Write-ColorfulText -C PinkBold -I "`nEnter a Pin for Bitlocker startup (between 10 to 20 characters)"; Read-Host -AsSecureString)
                                    [System.Security.SecureString]$Pin2 = $(Write-ColorfulText -C PinkBold -I 'Confirm your Bitlocker Startup Pin (between 10 to 20 characters)'; Read-Host -AsSecureString)

                                    # Compare the PINs and make sure they match
                                    [System.Boolean]$TheyMatch = Compare-SecureString -SecureString1 $Pin1 -SecureString2 $Pin2
                                    # If the PINs match and they are at least 10 characters long, max 20 characters
                                    if ( $TheyMatch -and ($Pin1.Length -in 10..20) -and ($Pin2.Length -in 10..20) ) {
                                        [System.Security.SecureString]$Pin = $Pin1
                                    }
                                    else { Write-Host -Object 'Please ensure that the PINs you entered match, and that they are between 10 to 20 characters.' -ForegroundColor red }
                                }
                                # Repeat this process until the entered PINs match and they are at least 10 characters long, max 20 characters
                                until ( $TheyMatch -and ($Pin1.Length -in 10..20) -and ($Pin2.Length -in 10..20) )

                                Write-ColorfulText -C MintGreen -I "`nPINs matched, enabling TPM, Startup PIN and Startup Key protector now`n"

                                try {
                                    # Add TpmAndPinAndStartupKeyProtector to the OS Drive
                                    Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod 'XtsAes256' -TpmAndPinAndStartupKeyProtector -StartupKeyPath (Get-AvailableRemovableDrives) -Pin $Pin -SkipHardwareTest *> $null
                                }
                                catch {
                                    Write-Host -Object 'There was a problem adding Startup Key to the removable drive, try ejecting and reinserting the flash drive into your device and run this category again.' -ForegroundColor Red
                                    $_
                                    break BitLockerCategoryLabel
                                }

                                # Add recovery password key protector to the OS Drive
                                Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> $null

                                # Get the new key protectors of the OS Drive after adding RecoveryPasswordProtector to it
                                [System.Object[]]$KeyProtectorsOSDrive = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector

                                # Backup the recovery code of the OS drive in a file
                                New-Item -Path "$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsOSDrive) -ItemType File -Force | Out-Null

                                Resume-BitLocker -MountPoint $env:SystemDrive | Out-Null

                                Write-ColorfulText -C MintGreen -I "`nBitlocker is now enabled for the OS drive with Enhanced security level."
                                Write-Host -Object "The recovery password will be saved in a text file in '$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt'" -ForegroundColor Cyan
                            }
                        }
                        'Skip encryptions altogether' { break BitLockerCategoryLabel } # Exit the entire BitLocker category, only
                        'Exit' { break MainSwitchLabel }
                    }

                    # Setting Hibernate file size to full after making sure OS drive is property encrypted for holding hibernate data
                    # Making sure the system is not a VM because Hibernate on VM doesn't work and VMs have other/better options than Hibernation
                    if (-NOT ((Get-MpComputerStatus).IsVirtualMachine)) {

                        # Check to see if Hibernate is already set to full and HiberFileType is set to 2 which is Full, 1 is Reduced
                        try {
                            [System.Int64]$HiberFileType = Get-ItemPropertyValue -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power' -Name 'HiberFileType' -ErrorAction SilentlyContinue
                        }
                        catch {
                            # Do nothing if the key doesn't exist
                        }
                        if ($HiberFileType -ne 2) {

                            Write-Progress -Id 2 -ParentId 0 -Activity 'Hibernate' -Status 'Setting Hibernate file size to full' -PercentComplete 50

                            # Set Hibernate mode to full
                            &"$env:SystemDrive\Windows\System32\powercfg.exe" /h /type full | Out-Null

                            Write-Progress -Id 2 -Activity 'Setting Hibernate file size to full' -Completed
                        }
                        else {
                            Write-ColorfulText -C Pink -I "`nHibernate is already set to full.`n"
                        }
                    }

                    # If the function is running in unattended mode, skip the rest of the code in this function as they need user interaction
                    if ($RunUnattended) { break BitLockerCategoryLabel }

                    #region Non-OS-BitLocker-Drives-Detection

                    # Get the list of non OS volumes
                    [System.Object[]]$NonOSBitLockerVolumes = Get-BitLockerVolume |
                    Where-Object -FilterScript { $_.volumeType -ne 'OperatingSystem' }

                    # Get all the volumes and filter out removable ones
                    [System.Object[]]$RemovableVolumes = Get-Volume | Where-Object -FilterScript { ($_.DriveType -eq 'Removable') -and $_.DriveLetter }

                    # Check if there is any removable volumes
                    if ($RemovableVolumes) {

                        # Get the letters of all the removable volumes
                        [System.String[]]$RemovableVolumesLetters = foreach ($RemovableVolume in $RemovableVolumes) {
                            $(($RemovableVolume).DriveLetter + ':' )
                        }

                        # Filter out removable drives from BitLocker volumes to process
                        $NonOSBitLockerVolumes = $NonOSBitLockerVolumes |
                        Where-Object -FilterScript { ($_.MountPoint -notin $RemovableVolumesLetters) }

                    }
                    #endregion Non-OS-BitLocker-Drives-Detection

                    # if there is no non-OS volumes then skip the rest of the code in the BitLocker function
                    if (!$NonOSBitLockerVolumes) { break BitLockerCategoryLabel }

                    # Loop through each non-OS volume and prompt for encryption
                    foreach ($MountPoint in $($NonOSBitLockerVolumes | Sort-Object).MountPoint) {

                        # Prompt for confirmation before encrypting each drive
                        switch (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nEncrypt $MountPoint drive ?") {
                            'Yes' {

                                # Check if the non-OS drive that the user selected to be encrypted is not in the middle of any encryption/decryption operation
                                if ((Get-BitLockerVolume -MountPoint $MountPoint).EncryptionPercentage -notin '100', '0') {
                                    # Check if the drive isn't already encrypted and locked
                                    if ((Get-BitLockerVolume -MountPoint $MountPoint).lockstatus -eq 'Locked') {
                                        Write-Host -Object "`nThe drive $MountPoint is already encrypted and locked." -ForegroundColor Magenta
                                        break
                                    }
                                    else {
                                        $EncryptionPercentageVar = (Get-BitLockerVolume -MountPoint $MountPoint).EncryptionPercentage
                                        Write-Host -Object "`nPlease wait for Bitlocker to finish encrypting or decrypting drive $MountPoint" -ForegroundColor Magenta
                                        Write-Host -Object "Drive $MountPoint encryption is currently at $EncryptionPercentageVar percent." -ForegroundColor Magenta
                                        break
                                    }
                                }

                                # Check to see if Bitlocker is already turned on for the user selected drive
                                # if it is, perform multiple checks on its key protectors
                                if ((Get-BitLockerVolume -MountPoint $MountPoint).ProtectionStatus -eq 'on') {

                                    # Get the OS Drive's encryption method
                                    [System.String]$EncryptionMethodNonOSDrive = (Get-BitLockerVolume -MountPoint $MountPoint).EncryptionMethod

                                    # Check OS Drive's encryption method and display a warning if it's not the most secure one
                                    if ($EncryptionMethodNonOSDrive -ine 'XtsAes256') {
                                        Write-Warning -Message "Drive $MountPoint is encrypted with the less secure '$EncryptionMethodNonOSDrive' encryption method instead of 'XtsAes256'"
                                    }

                                    # Get the key protector types of the Non-OS Drive
                                    [System.String[]]$KeyProtectorTypesNonOS = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector.keyprotectortype

                                    # If Recovery Password and Auto Unlock key protectors are available on the drive
                                    if ($KeyProtectorTypesNonOS -contains 'RecoveryPassword' -and $KeyProtectorTypesNonOS -contains 'ExternalKey') {

                                        # Additional Check 1: if there are more than 1 ExternalKey key protector, try delete all of them and add a new one
                                        # The external key protector that is being used to unlock the drive will not be deleted
                                                    ((Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
                                        Where-Object -FilterScript { $_.keyprotectortype -eq 'ExternalKey' }).KeyProtectorId |
                                        ForEach-Object -Process {
                                            # -ErrorAction SilentlyContinue makes sure no error is thrown if the drive only has 1 External key key protector
                                            # and it's being used to unlock the drive
                                            Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_ -ErrorAction SilentlyContinue | Out-Null
                                        }

                                        # Renew the External key of the selected Non-OS Drive
                                        Enable-BitLockerAutoUnlock -MountPoint $MountPoint | Out-Null

                                        # Additional Check 2: if there are more than 1 Recovery Password, delete all of them and add a new one
                                        [System.String[]]$RecoveryPasswordKeyProtectors = ((Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
                                            Where-Object -FilterScript { $_.keyprotectortype -eq 'RecoveryPassword' }).KeyProtectorId

                                        if ($RecoveryPasswordKeyProtectors.Count -gt 1) {

                                            [System.String]$BitLockerMsg = "`nThere are more than 1 recovery password key protector associated with the drive $mountpoint `n" +
                                            "Removing all of them and adding a new one. `n" +
                                            "It will be saved in a text file in '$($MountPoint)\Drive $($MountPoint.Remove(1)) recovery password.txt'"
                                            Write-Host -Object $BitLockerMsg -ForegroundColor Yellow

                                            # Remove all of the recovery password key protectors of the selected Non-OS Drive
                                            $RecoveryPasswordKeyProtectors | ForEach-Object -Process {
                                                Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_ | Out-Null
                                            }

                                            # Add a new Recovery Password key protector after removing all of the previous ones
                                            Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector *> $null

                                            # Get the new key protectors of the Non-OS Drive after adding RecoveryPasswordProtector to it
                                            [System.Object[]]$KeyProtectorsNonOS = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector

                                            # Backup the recovery code of the Non-OS drive in a file
                                            New-Item -Path "$MountPoint\Drive $($MountPoint.Remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsNonOS) -ItemType File -Force | Out-Null

                                        }
                                        Write-ColorfulText -C MintGreen -I "`nBitlocker is already securely enabled for drive $MountPoint"

                                        # Get the new key protectors of the Non-OS Drive after adding RecoveryPasswordProtector to it
                                        # Just to simply display it on the console for the user
                                        [System.Object[]]$KeyProtectorsNonOS = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector

                                        Write-ColorfulText -C Fuchsia -I "Here is your 48-digits recovery password for drive $MountPoint in case you were looking for it:"
                                        Write-ColorfulText -C Rainbow -I "$(($KeyProtectorsNonOS | Where-Object -FilterScript { $_.keyprotectortype -eq 'RecoveryPassword' }).RecoveryPassword)"
                                    }

                                    # If the selected drive has Auto Unlock key protector but doesn't have Recovery Password
                                    elseif ($KeyProtectorTypesNonOS -contains 'ExternalKey' -and $KeyProtectorTypesNonOS -notcontains 'RecoveryPassword' ) {

                                        # if there are more than 1 ExternalKey key protector, try delete all of them and add a new one
                                        # The external key protector that is being used to unlock the drive will not be deleted
                                                    ((Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
                                        Where-Object -FilterScript { $_.keyprotectortype -eq 'ExternalKey' }).KeyProtectorId |
                                        ForEach-Object -Process {
                                            # -ErrorAction SilentlyContinue makes sure no error is thrown if the drive only has 1 External key key protector
                                            # and it's being used to unlock the drive
                                            Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_ -ErrorAction SilentlyContinue | Out-Null
                                        }

                                        # Renew the External key of the selected Non-OS Drive
                                        Enable-BitLockerAutoUnlock -MountPoint $MountPoint | Out-Null

                                        # Add Recovery Password Key protector and save it to a file inside the drive
                                        Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector *> $null

                                        # Get the new key protectors of the Non-OS Drive after adding RecoveryPasswordProtector to it
                                        [System.Object[]]$KeyProtectorsNonOS = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector

                                        # Backup the recovery code of the Non-OS drive in a file
                                        New-Item -Path "$MountPoint\Drive $($MountPoint.Remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsNonOS) -ItemType File -Force | Out-Null

                                        [System.String]$BitLockerMsg = "`nDrive $MountPoint is auto-unlocked but doesn't have Recovery Password, adding it now... `n" +
                                        "It will be saved in a text file in '$($MountPoint)\Drive $($MountPoint.Remove(1)) recovery password.txt'"
                                        Write-Host -Object $BitLockerMsg -ForegroundColor Cyan
                                    }

                                    # Check 3: If the selected drive has Recovery Password key protector but doesn't have Auto Unlock enabled
                                    elseif ($KeyProtectorTypesNonOS -contains 'RecoveryPassword' -and $KeyProtectorTypesNonOS -notcontains 'ExternalKey') {

                                        # Add Auto-unlock (a.k.a ExternalKey key protector to the drive)
                                        Enable-BitLockerAutoUnlock -MountPoint $MountPoint | Out-Null

                                        # if there are more than 1 Recovery Password, delete all of them and add a new one
                                        [System.String[]]$RecoveryPasswordKeyProtectors = ((Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
                                            Where-Object -FilterScript { $_.keyprotectortype -eq 'RecoveryPassword' }).KeyProtectorId

                                        if ($RecoveryPasswordKeyProtectors.Count -gt 1) {

                                            [System.String]$BitLockerMsg = "`nThere are more than 1 recovery password key protector associated with the drive $mountpoint `n" +
                                            'Removing all of them and adding a new one.' +
                                            "It will be saved in a text file in '$($MountPoint)\Drive $($MountPoint.Remove(1)) recovery password.txt'"
                                            Write-Host -Object $BitLockerMsg -ForegroundColor Yellow

                                            # Delete all Recovery Passwords because there were more than 1
                                            $RecoveryPasswordKeyProtectors | ForEach-Object -Process {
                                                Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_ | Out-Null
                                            }

                                            # Add a new Recovery Password
                                            Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector *> $null

                                            # Get the new key protectors of the Non-OS Drive after adding RecoveryPasswordProtector to it
                                            [System.Object[]]$KeyProtectorsNonOS = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector

                                            # Backup the recovery code of the Non-OS drive in a file
                                            New-Item -Path "$MountPoint\Drive $($MountPoint.Remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsNonOS) -ItemType File -Force | Out-Null
                                        }
                                    }
                                }

                                # Do this if Bitlocker isn't turned on at all on the user selected drive
                                else {
                                    # Enable BitLocker with RecoveryPassword key protector for the selected Non-OS drive
                                    Enable-BitLocker -MountPoint $MountPoint -RecoveryPasswordProtector *> $null

                                    # Add Auto-unlock (a.k.a ExternalKey key protector to the drive)
                                    Enable-BitLockerAutoUnlock -MountPoint $MountPoint | Out-Null

                                    # Get the new key protectors of the Non-OS Drive after adding RecoveryPasswordProtector to it
                                    [System.Object[]]$KeyProtectorsNonOS = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector

                                    # Backup the recovery code of the Non-OS drive in a file
                                    New-Item -Path "$MountPoint\Drive $($MountPoint.Remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsNonOS) -ItemType File -Force | Out-Null

                                    Write-ColorfulText -C MintGreen -I "`nBitLocker has started encrypting drive $MountPoint"
                                    Write-Host -Object "Recovery password will be saved in a text file in '$($MountPoint)\Drive $($MountPoint.Remove(1)) recovery password.txt'" -ForegroundColor Cyan
                                }
                            } 'No' { break }
                            'Exit' { break MainSwitchLabel }
                        }
                    }
                } 'No' { break BitLockerCategoryLabel }
                'Exit' { break MainSwitchLabel }
            }
        }
        Function Invoke-TLSSecurity {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)

            $RefCurrentMainStep.Value++
            $Host.UI.RawUI.WindowTitle = '🛡️ TLS'
            Write-Verbose -Message 'Processing the TLS Security category function'

            :TLSSecurityLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun TLS Security category ?")) {
                'Yes' {
                    Write-Verbose -Message 'Running the TLS Security category'
                    Write-Progress -Id 0 -Activity 'TLS Security' -Status "Step $($RefCurrentMainStep.Value)/$TotalMainSteps" -PercentComplete ($RefCurrentMainStep.Value / $TotalMainSteps * 100)

                    # creating these registry keys that have forward slashes in them
                    @(  'DES 56/56', # DES 56-bit
                        'RC2 40/128', # RC2 40-bit
                        'RC2 56/128', # RC2 56-bit
                        'RC2 128/128', # RC2 128-bit
                        'RC4 40/128', # RC4 40-bit
                        'RC4 56/128', # RC4 56-bit
                        'RC4 64/128', # RC4 64-bit
                        'RC4 128/128', # RC4 128-bit
                        'Triple DES 168' # 3DES 168-bit (Triple DES 168)
                    ) | ForEach-Object -Process {
                        [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME).CreateSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$_") | Out-Null
                    }

                    Write-Verbose -Message 'Applying the TLS Security registry settings'
                    foreach ($Item in $RegistryCSVItems) {
                        if ($Item.category -eq 'TLS') {
                            Edit-Registry -path $Item.Path -key $Item.Key -value $Item.Value -type $Item.Type -Action $Item.Action
                        }
                    }

                    Write-Verbose -Message 'Applying the TLS Security Group Policies'
                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\TLS Security\registry.pol"
                } 'No' { break TLSSecurityLabel }
                'Exit' { break MainSwitchLabel }
            }
        }
        Function Invoke-LockScreen {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)

            $RefCurrentMainStep.Value++
            $Host.UI.RawUI.WindowTitle = '💻 Lock Screen'
            Write-Verbose -Message 'Processing the Lock Screen category function'

            :LockScreenLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Lock Screen category ?")) {
                'Yes' {
                    Write-Verbose -Message 'Running the Lock Screen category'
                    Write-Progress -Id 0 -Activity 'Lock Screen' -Status "Step $($RefCurrentMainStep.Value)/$TotalMainSteps" -PercentComplete ($RefCurrentMainStep.Value / $TotalMainSteps * 100)

                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Lock Screen Policies\registry.pol"
                    &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\Lock Screen Policies\GptTmpl.inf"

                    # Apply the Don't display last signed-in policy
                    :LockScreenLastSignedInLabel switch ($RunUnattended ? ($LockScreen_NoLastSignedIn ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nDon't display last signed-in on logon screen ?" -ExtraMessage 'Read the GitHub Readme!')) {
                        'Yes' {
                            Write-Verbose -Message "Applying the Don't display last signed-in policy"
                            &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\Lock Screen Policies\Don't display last signed-in\GptTmpl.inf"
                        } 'No' { break LockScreenLastSignedInLabel }
                        'Exit' { break MainSwitchLabel }
                    }

                    # Enable CTRL + ALT + DEL
                    :CtrlAltDelLabel switch ($RunUnattended ? ($LockScreen_CtrlAltDel ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nEnable requiring CTRL + ALT + DEL on lock screen ?")) {
                        'Yes' {
                            Write-Verbose -Message 'Applying the Enable CTRL + ALT + DEL policy'
                            &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\Lock Screen Policies\Enable CTRL + ALT + DEL\GptTmpl.inf"
                        } 'No' { break CtrlAltDelLabel }
                        'Exit' { break MainSwitchLabel }
                    }
                } 'No' { break LockScreenLabel }
                'Exit' { break MainSwitchLabel }
            }
        }
        Function Invoke-UserAccountControl {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)

            $RefCurrentMainStep.Value++
            $Host.UI.RawUI.WindowTitle = '💎 UAC'
            Write-Verbose -Message 'Processing the User Account Control category function'

            :UACLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun User Account Control category ?")) {
                'Yes' {
                    Write-Verbose -Message 'Running the User Account Control category'
                    Write-Progress -Id 0 -Activity 'User Account Control' -Status "Step $($RefCurrentMainStep.Value)/$TotalMainSteps" -PercentComplete ($RefCurrentMainStep.Value / $TotalMainSteps * 100)

                    &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\User Account Control UAC Policies\GptTmpl.inf"

                    # Apply the Hide the entry points for Fast User Switching policy
                    :FastUserSwitchingLabel switch ($RunUnattended ? ($UAC_NoFastSwitching ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nHide the entry points for Fast User Switching ?" -ExtraMessage 'Read the GitHub Readme!')) {
                        'Yes' {
                            Write-Verbose -Message 'Applying the Hide the entry points for Fast User Switching policy'
                            &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\User Account Control UAC Policies\Hides the entry points for Fast User Switching\registry.pol"
                        } 'No' { break FastUserSwitchingLabel }
                        'Exit' { break MainSwitchLabel }
                    }

                    # Apply the Only elevate executables that are signed and validated policy
                    :ElevateSignedExeLabel switch ($RunUnattended ? ($UAC_OnlyElevateSigned ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nOnly elevate executables that are signed and validated ?" -ExtraMessage 'Read the GitHub Readme!')) {
                        'Yes' {
                            Write-Verbose -Message 'Applying the Only elevate executables that are signed and validated policy'
                            &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\User Account Control UAC Policies\Only elevate executables that are signed and validated\GptTmpl.inf"
                        } 'No' { break ElevateSignedExeLabel }
                        'Exit' { break MainSwitchLabel }
                    }
                } 'No' { break UACLabel }
                'Exit' { break MainSwitchLabel }
            }
        }
        Function Invoke-WindowsFirewall {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)

            $RefCurrentMainStep.Value++
            $Host.UI.RawUI.WindowTitle = '🔥 Firewall'
            Write-Verbose -Message 'Processing the Windows Firewall category function'

            :WindowsFirewallLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Windows Firewall category ?")) {
                'Yes' {
                    Write-Verbose -Message 'Running the Windows Firewall category'
                    Write-Progress -Id 0 -Activity 'Windows Firewall' -Status "Step $($RefCurrentMainStep.Value)/$TotalMainSteps" -PercentComplete ($RefCurrentMainStep.Value / $TotalMainSteps * 100)

                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Windows Firewall Policies\registry.pol"

                    Write-Verbose -Message 'Disabling Multicast DNS (mDNS) UDP-in Firewall Rules for all 3 Firewall profiles - disables only 3 rules'
                    Get-NetFirewallRule |
                    Where-Object -FilterScript { ($_.RuleGroup -eq '@%SystemRoot%\system32\firewallapi.dll,-37302') -and ($_.Direction -eq 'inbound') } |
                    ForEach-Object -Process { Disable-NetFirewallRule -DisplayName $_.DisplayName }

                } 'No' { break WindowsFirewallLabel }
                'Exit' { break MainSwitchLabel }
            }
        }
        Function Invoke-OptionalWindowsFeatures {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)

            $RefCurrentMainStep.Value++
            $Host.UI.RawUI.WindowTitle = '🏅 Optional Features'
            Write-Verbose -Message 'Processing the Optional Windows Features category function'

            :OptionalFeaturesLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Optional Windows Features category ?")) {
                'Yes' {
                    Write-Verbose -Message 'Running the Optional Windows Features category'
                    Write-Progress -Id 0 -Activity 'Optional Windows Features' -Status "Step $($RefCurrentMainStep.Value)/$TotalMainSteps" -PercentComplete ($RefCurrentMainStep.Value / $TotalMainSteps * 100)

                    # PowerShell Core (only if installed from Microsoft Store) has problem with these commands: https://github.com/PowerShell/PowerShell/issues/13866#issuecomment-1519066710
                    if ($PSHome -like "*$env:SystemDrive\Program Files\WindowsApps\Microsoft.PowerShell*") {
                        Write-Verbose -Message 'Importing DISM module to be able to run DISM commands in PowerShell Core installed from MSFT Store'
                        Import-Module -Name 'DISM' -UseWindowsPowerShell -Force -WarningAction SilentlyContinue
                    }

                    Edit-Addons -Type Feature -FeatureAction Disabling -FeatureName 'MicrosoftWindowsPowerShellV2'
                    Edit-Addons -Type Feature -FeatureAction Disabling -FeatureName 'MicrosoftWindowsPowerShellV2Root'
                    Edit-Addons -Type Feature -FeatureAction Disabling -FeatureName 'WorkFolders-Client'
                    Edit-Addons -Type Feature -FeatureAction Disabling -FeatureName 'Printing-Foundation-Features'
                    Edit-Addons -Type Feature -FeatureAction Disabling -FeatureName 'Windows-Defender-ApplicationGuard'
                    Edit-Addons -Type Feature -FeatureAction Enabling -FeatureName 'Containers-DisposableClientVM'
                    Edit-Addons -Type Feature -FeatureAction Enabling -FeatureName 'Microsoft-Hyper-V'
                    Edit-Addons -Type Capability -CapabilityName 'Media.WindowsMediaPlayer'
                    Edit-Addons -Type Capability -CapabilityName 'Browser.InternetExplorer'
                    Edit-Addons -Type Capability -CapabilityName 'wmic'
                    Edit-Addons -Type Capability -CapabilityName 'Microsoft.Windows.Notepad.System'
                    Edit-Addons -Type Capability -CapabilityName 'Microsoft.Windows.WordPad'
                    Edit-Addons -Type Capability -CapabilityName 'Microsoft.Windows.PowerShell.ISE'
                    Edit-Addons -Type Capability -CapabilityName 'App.StepsRecorder'

                    # Uninstall VBScript that is now uninstallable as an optional features since Windows 11 insider Dev build 25309 - Won't do anything in other builds
                    if (Get-WindowsCapability -Online | Where-Object -FilterScript { $_.Name -like '*VBSCRIPT*' }) {
                        try {
                            Write-ColorfulText -Color Lavender -InputText "`nUninstalling VBSCRIPT"
                            Get-WindowsCapability -Online | Where-Object -FilterScript { $_.Name -like '*VBSCRIPT*' } | Remove-WindowsCapability -Online
                            # Shows the successful message only if removal process was successful
                            Write-ColorfulText -Color NeonGreen -InputText 'VBSCRIPT has been uninstalled'
                        }
                        catch {
                            # show errors in non-terminating way
                            $_
                        }
                    }
                } 'No' { break OptionalFeaturesLabel }
                'Exit' { break MainSwitchLabel }
            }
        }
        Function Invoke-WindowsNetworking {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)

            $RefCurrentMainStep.Value++
            $Host.UI.RawUI.WindowTitle = '📶 Networking'
            Write-Verbose -Message 'Processing the Windows Networking category function'

            :WindowsNetworkingLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Windows Networking category ?")) {
                'Yes' {
                    Write-Verbose -Message 'Running the Windows Networking category'
                    Write-Progress -Id 0 -Activity 'Windows Networking' -Status "Step $($RefCurrentMainStep.Value)/$TotalMainSteps" -PercentComplete ($RefCurrentMainStep.Value / $TotalMainSteps * 100)

                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Windows Networking Policies\registry.pol"
                    &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\Windows Networking Policies\GptTmpl.inf"

                    Write-Verbose -Message 'Disabling LMHOSTS lookup protocol on all network adapters'
                    Edit-Registry -path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -key 'EnableLMHOSTS' -value '0' -type 'DWORD' -Action 'AddOrModify'

                    Write-Verbose -Message 'Setting the Network Location of all connections to Public'
                    Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Public
                } 'No' { break WindowsNetworkingLabel }
                'Exit' { break MainSwitchLabel }
            }
        }
        Function Invoke-MiscellaneousConfigurations {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)

            $RefCurrentMainStep.Value++
            $Host.UI.RawUI.WindowTitle = '🥌 Miscellaneous'
            Write-Verbose -Message 'Processing the Miscellaneous Configurations category function'

            :MiscellaneousLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Miscellaneous Configurations category ?")) {
                'Yes' {
                    Write-Verbose -Message 'Running the Miscellaneous Configurations category'
                    Write-Progress -Id 0 -Activity 'Miscellaneous Configurations' -Status "Step $($RefCurrentMainStep.Value)/$TotalMainSteps" -PercentComplete ($RefCurrentMainStep.Value / $TotalMainSteps * 100)

                    Write-Verbose -Message 'Applying the Miscellaneous Configurations registry settings'
                    foreach ($Item in $RegistryCSVItems) {
                        if ($Item.category -eq 'Miscellaneous') {
                            Edit-Registry -path $Item.Path -key $Item.Key -value $Item.Value -type $Item.Type -Action $Item.Action
                        }
                    }

                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Miscellaneous Policies\registry.pol"
                    &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\Miscellaneous Policies\GptTmpl.inf"

                    Write-Verbose -Message 'Adding all Windows users to the "Hyper-V Administrators" security group to be able to use Hyper-V and Windows Sandbox'
                    Get-LocalUser | Where-Object -FilterScript { $_.enabled -eq 'True' } | ForEach-Object -Process { Add-LocalGroupMember -SID 'S-1-5-32-578' -Member "$($_.SID)" -ErrorAction SilentlyContinue }

                    # Makes sure auditing for the "Other Logon/Logoff Events" subcategory under the Logon/Logoff category is enabled, doesn't touch affect any other sub-category
                    # For tracking Lock screen unlocks and locks
                    # auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
                    # Using GUID
                    Write-Verbose -Message 'Enabling auditing for the "Other Logon/Logoff Events" subcategory under the Logon/Logoff category'
                    auditpol /set /subcategory:"{0CCE921C-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null

                    # Query all Audits status
                    # auditpol /get /category:*
                    # Get the list of SubCategories and their associated GUIDs
                    # auditpol /list /subcategory:* /r

                    # Event Viewer custom views are saved in "$env:SystemDrive\ProgramData\Microsoft\Event Viewer\Views". files in there can be backed up and restored on new Windows installations.
                    if (Test-Path -Path "$env:SystemDrive\ProgramData\Microsoft\Event Viewer\Views\Hardening Script") {
                        Remove-Item -Path "$env:SystemDrive\ProgramData\Microsoft\Event Viewer\Views\Hardening Script" -Recurse -Force
                    }

                    Write-Verbose -Message 'Creating new sub-folder automatically and importing the custom views of the event viewer'
                    Expand-Archive -Path "$WorkingDir\EventViewerCustomViews.zip" -DestinationPath "$env:SystemDrive\ProgramData\Microsoft\Event Viewer\Views\Hardening Script" -Force
                } 'No' { break MiscellaneousLabel }
                'Exit' { break MainSwitchLabel }
            }
        }
        Function Invoke-WindowsUpdateConfigurations {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)

            $RefCurrentMainStep.Value++
            $Host.UI.RawUI.WindowTitle = '🪟 Windows Update'
            Write-Verbose -Message 'Processing the Windows Update category function'

            :WindowsUpdateLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply Windows Update Policies ?")) {
                'Yes' {
                    Write-Verbose -Message 'Running the Windows Update category'
                    Write-Progress -Id 0 -Activity 'Windows Update Configurations' -Status "Step $($RefCurrentMainStep.Value)/$TotalMainSteps" -PercentComplete ($RefCurrentMainStep.Value / $TotalMainSteps * 100)

                    Write-Verbose -Message 'Enabling restart notification for Windows update'
                    Edit-Registry -path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -key 'RestartNotificationsAllowed2' -value '1' -type 'DWORD' -Action 'AddOrModify'

                    Write-Verbose -Message 'Applying the Windows Update Group Policies'
                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Windows Update Policies\registry.pol"
                } 'No' { break WindowsUpdateLabel }
                'Exit' { break MainSwitchLabel }
            }
        }
        Function Invoke-EdgeBrowserConfigurations {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)

            $RefCurrentMainStep.Value++
            $Host.UI.RawUI.WindowTitle = '🦔 Edge'
            Write-Verbose -Message 'Processing the Edge Browser category function'

            :MSEdgeLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply Edge Browser Configurations ?")) {
                'Yes' {
                    Write-Verbose -Message 'Running the Edge Browser category'
                    Write-Progress -Id 0 -Activity 'Edge Browser Configurations' -Status "Step $($RefCurrentMainStep.Value)/$TotalMainSteps" -PercentComplete ($RefCurrentMainStep.Value / $TotalMainSteps * 100)

                    Write-Verbose -Message 'Applying the Edge Browser registry settings'
                    foreach ($Item in $RegistryCSVItems) {
                        if ($Item.category -eq 'Edge') {
                            Edit-Registry -path $Item.Path -key $Item.Key -value $Item.Value -type $Item.Type -Action $Item.Action
                        }
                    }
                } 'No' { break MSEdgeLabel }
                'Exit' { break MainSwitchLabel }
            }
        }
        Function Invoke-CertificateCheckingCommands {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)

            $RefCurrentMainStep.Value++
            $Host.UI.RawUI.WindowTitle = '🎟️ Certificates'
            Write-Verbose -Message 'Processing the Certificate Checking category function'

            :CertCheckingLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Certificate Checking category ?")) {
                'Yes' {
                    Write-Verbose -Message 'Running the Certificate Checking category'
                    Write-Progress -Id 0 -Activity 'Certificate Checking Commands' -Status "Step $($RefCurrentMainStep.Value)/$TotalMainSteps" -PercentComplete ($RefCurrentMainStep.Value / $TotalMainSteps * 100)

                    try {
                        Write-Verbose -Message 'Downloading sigcheck64.exe from https://live.sysinternals.com'
                        Invoke-WebRequest -Uri 'https://live.sysinternals.com/sigcheck64.exe' -OutFile 'sigcheck64.exe'
                    }
                    catch {
                        Write-Error -Message 'sigcheck64.exe could not be downloaded from https://live.sysinternals.com' -ErrorAction Continue
                        break CertCheckingLabel
                    }
                    Write-Host -NoNewline -Object "`nListing valid certificates not rooted to the Microsoft Certificate Trust List in the" -ForegroundColor Yellow; Write-Host -Object " Current User store`n" -ForegroundColor cyan
                    .\sigcheck64.exe -tuv -accepteula -nobanner

                    Write-Host -NoNewline -Object "`nListing valid certificates not rooted to the Microsoft Certificate Trust List in the" -ForegroundColor Yellow; Write-Host -Object " Local Machine Store`n" -ForegroundColor Blue
                    .\sigcheck64.exe -tv -accepteula -nobanner

                    # Remove the downloaded sigcheck64.exe after using it
                    Remove-Item -Path .\sigcheck64.exe -Force
                } 'No' { break CertCheckingLabel }
                'Exit' { break MainSwitchLabel }
            }
        }
        Function Invoke-CountryIPBlocking {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)

            $RefCurrentMainStep.Value++
            $Host.UI.RawUI.WindowTitle = '🧾 Country IPs'
            Write-Verbose -Message 'Processing the Country IP Blocking category function'

            :IPBlockingLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Country IP Blocking category ?")) {
                'Yes' {
                    Write-Verbose -Message 'Running the Country IP Blocking category'
                    Write-Progress -Id 0 -Activity 'Country IP Blocking' -Status "Step $($RefCurrentMainStep.Value)/$TotalMainSteps" -PercentComplete ($RefCurrentMainStep.Value / $TotalMainSteps * 100)

                    :IPBlockingTerrLabel switch ($RunUnattended ? 'Yes' : (Select-Option -SubCategory -Options 'Yes', 'No' -Message 'Add countries in the State Sponsors of Terrorism list to the Firewall block list?')) {
                        'Yes' {
                            Write-Verbose -Message 'Blocking IP ranges of countries in State Sponsors of Terrorism list'
                            Block-CountryIP -IPList (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/StateSponsorsOfTerrorism.txt') -ListName 'State Sponsors of Terrorism'
                        } 'No' { break IPBlockingTerrLabel }
                    }
                    :IPBlockingOFACLabel switch ($RunUnattended ? ($CountryIPBlocking_OFAC ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No' -Message 'Add OFAC Sanctioned Countries to the Firewall block list?')) {
                        'Yes' {
                            Write-Verbose -Message 'Blocking IP ranges of countries in OFAC sanction list'
                            Block-CountryIP -IPList (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/OFACSanctioned.txt') -ListName 'OFAC Sanctioned Countries'
                        } 'No' { break IPBlockingOFACLabel }
                    }
                } 'No' { break IPBlockingLabel }
                'Exit' { break MainSwitchLabel }
            }
        }
        Function Invoke-DownloadsDefenseMeasures {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)

            $RefCurrentMainStep.Value++
            $Host.UI.RawUI.WindowTitle = '🎇 Downloads Defense Measures'
            Write-Verbose -Message 'Processing the Downloads Defense Measures category function'

            :DownloadsDefenseMeasuresLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Downloads Defense Measures category ?")) {
                'Yes' {
                    Write-Verbose -Message 'Running the Downloads Defense Measures category'
                    Write-Progress -Id 0 -Activity 'Downloads Defense Measures' -Status "Step $($RefCurrentMainStep.Value)/$TotalMainSteps" -PercentComplete ($RefCurrentMainStep.Value / $TotalMainSteps * 100)

                    if (-NOT (Get-Module -ListAvailable -Name 'WDACConfig' -Verbose:$false)) {
                        Write-Verbose -Message 'Installing WDACConfig module because it is not installed'
                        Install-Module -Name 'WDACConfig' -Force -Verbose:$false
                    }

                    Write-Verbose -Message 'Getting the currently deployed base policy names'
                    [System.String[]]$CurrentBasePolicyNames = ((&"$env:SystemDrive\Windows\System32\CiTool.exe" -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { ($_.IsSystemPolicy -ne 'True') -and ($_.PolicyID -eq $_.BasePolicyID) }).FriendlyName

                    # Only deploy the Downloads-Defense-Measures policy if it is not already deployed
                    if ('Downloads-Defense-Measures' -notin $CurrentBasePolicyNames) {

                        Write-Verbose -Message 'Detecting the Downloads folder path on system'
                        [System.IO.FileInfo]$DownloadsPathSystem = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.path
                        Write-Verbose -Message "The Downloads folder path on system is $DownloadsPathSystem"

                        # Getting the current user's name
                        [System.Security.Principal.SecurityIdentifier]$UserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().user.value
                        [System.String]$UserName = (Get-LocalUser | Where-Object -FilterScript { $_.SID -eq $UserSID }).name

                        # Checking if the Edge preferences file exists
                        if (Test-Path -Path "$env:SystemDrive\Users\$UserName\AppData\Local\Microsoft\Edge\User Data\Default\Preferences") {

                            Write-Verbose -Message 'Detecting the Downloads path in Edge'
                            [PSCustomObject]$CurrentUserEdgePreference = ConvertFrom-Json -InputObject (Get-Content -Raw -Path "$env:SystemDrive\Users\$UserName\AppData\Local\Microsoft\Edge\User Data\Default\Preferences")
                            [System.IO.FileInfo]$DownloadsPathEdge = $CurrentUserEdgePreference.savefile.default_directory

                            # Ensure there is an Edge browser profile and it was initialized
                            if ((-NOT [System.String]::IsNullOrWhitespace($DownloadsPathEdge.FullName))) {

                                Write-Verbose -Message "The Downloads path in Edge is $DownloadsPathEdge"

                                # Display a warning for now
                                if ($DownloadsPathEdge.FullName -ne $DownloadsPathSystem.FullName) {
                                    Write-Warning -Message "The Downloads path in Edge ($($DownloadsPathEdge.FullName)) is different than the system's Downloads path ($($DownloadsPathSystem.FullName))"
                                }
                            }
                        }

                        Write-Verbose -Message 'Creating and deploying the Downloads-Defense-Measures policy'
                        New-DenyWDACConfig -PathWildCards -PolicyName 'Downloads-Defense-Measures' -FolderPath "$DownloadsPathSystem\*" -Deploy -Verbose:$Verbose -SkipVersionCheck -EmbeddedVerboseOutput
                    }
                    else {
                        Write-Verbose -Message 'The Downloads-Defense-Measures policy is already deployed'
                    }

                } 'No' { break DownloadsDefenseMeasuresLabel }
                'Exit' { break MainSwitchLabel }
            }
        }
        Function Invoke-NonAdminCommands {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)

            $RefCurrentMainStep.Value++
            $Host.UI.RawUI.WindowTitle = '🏷️ Non-Admins'
            Write-Verbose -Message 'Processing the Non-Admin category function'

            :NonAdminLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Non-Admin category ?")) {
                'Yes' {
                    Write-Verbose -Message 'Running the Non-Admin category'
                    Write-Progress -Id 0 -Activity 'Non-Admin category' -Status "Step $($RefCurrentMainStep.Value)/$TotalMainSteps" -PercentComplete ($RefCurrentMainStep.Value / $TotalMainSteps * 100)

                    Write-Verbose -Message 'Applying the Non-Admin registry settings'
                    foreach ($Item in $RegistryCSVItems) {
                        if ($Item.category -eq 'NonAdmin') {
                            Edit-Registry -path $Item.Path -key $Item.Key -value $Item.Value -type $Item.Type -Action $Item.Action
                        }
                    }

                    # Only suggest restarting the device if Admin related categories were run and the code was not running in unattended mode
                    if (!$Categories -and $IsAdmin) {
                        Write-Host -Object "`r`n"
                        Write-ColorfulText -C Rainbow -I "################################################################################################`r`n"
                        Write-ColorfulText -C MintGreen -I "###  Please Restart your device to completely apply the security measures and Group Policies ###`r`n"
                        Write-ColorfulText -C Rainbow -I "################################################################################################`r`n"
                    }
                } 'No' { break NonAdminLabel }
                'Exit' { break MainSwitchLabel }
            }
        }
        #Endregion Hardening-Categories-Functions-CLI-Experience

        # Determining whether to use the files inside the module or download them from the GitHub repository
        [System.Boolean]$IsLocally = $false
        # Test for $null or '' or all-whitespace or any stringified value being ''
        if (-NOT [System.String]::IsNullOrWhitespace($PSCommandPath)) {
            try {
                # Get the name of the file that called the function
                [System.String]$PSCommandPathToProcess = Split-Path -Path $PSCommandPath -Leaf
            }
            catch {}
            if ($PSCommandPathToProcess -eq 'Protect-WindowsSecurity.psm1') {
                Write-Verbose -Message 'Running Protect-WindowsSecurity function as part of the Harden-Windows-Security module'

                Write-Verbose -Message 'Importing the required sub-modules'
                Import-Module -FullyQualifiedName "$HardeningModulePath\Shared\Update-self.psm1" -Force -Verbose:$false

                # Set the flag to true to indicate that the module is running locally
                $IsLocally = $true

                if (!$Offline) {
                    Write-Verbose -Message 'Checking for updates...'
                    Update-Self -InvocationStatement $MyInvocation.Statement
                }
                else {
                    Write-Verbose -Message 'Skipping update check since the -Offline switch was used'
                }
            }
        }
        else {
            Write-Verbose -Message '$PSCommandPath was not found, Protect-WindowsSecurity function was most likely called from the GitHub repository'
        }

        [System.Security.Principal.WindowsPrincipal]$Principal = New-Object -TypeName 'Security.Principal.WindowsPrincipal' -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())
        [System.Boolean]$IsAdmin = $Principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) ? $True : $false

        # Get the execution policy for the current process
        [System.String]$CurrentExecutionPolicy = Get-ExecutionPolicy -Scope 'Process'

        # Change the execution policy temporarily only for the current PowerShell session
        Set-ExecutionPolicy -ExecutionPolicy 'Unrestricted' -Scope 'Process' -Force

        # Get the current title of the PowerShell
        [System.String]$CurrentPowerShellTitle = $Host.UI.RawUI.WindowTitle

        # Change the title of the Windows Terminal for PowerShell tab
        $Host.UI.RawUI.WindowTitle = '❤️‍🔥Harden Windows Security❤️‍🔥'

        # Minimum OS build number required for the hardening measures
        [System.Decimal]$Requiredbuild = '22621.3155'
        # Fetching Temp Directory
        [System.String]$CurrentUserTempDirectoryPath = [System.IO.Path]::GetTempPath()
        # The total number of the main categories for the parent/main progress bar to render
        [System.Int32]$TotalMainSteps = 18
        # Defining a boolean variable to determine whether optional diagnostic data should be enabled for Smart App Control or not
        [System.Boolean]$ShouldEnableOptionalDiagnosticData = $false

        Write-Verbose -Message 'Creating the working directory'
        [System.IO.DirectoryInfo]$WorkingDir = New-Item -ItemType Directory -Path "$CurrentUserTempDirectoryPath\HardeningXStuff\" -Force

        if ($IsAdmin) {
            Write-Verbose -Message 'Getting the current configurations and preferences of the Microsoft Defender...'

            # These commands create additional RunSpaces to contact Windows PowerShell since these cmdlets aren't natively available in PowerShell Core
            # If they are run in new RunSpaces, they are not discarded when their parent RunSpace is discarded
            [Microsoft.Management.Infrastructure.CimInstance]$MDAVConfigCurrent = Get-MpComputerStatus
            [Microsoft.Management.Infrastructure.CimInstance]$MDAVPreferencesCurrent = Get-MpPreference

            Write-Verbose -Message 'Backing up the current Controlled Folder Access allowed apps list in order to restore them at the end'
            # doing this so that when we Add and then Remove PowerShell executables in Controlled folder access exclusions
            # no user customization will be affected
            [System.IO.FileInfo[]]$CFAAllowedAppsBackup = $MDAVPreferencesCurrent.ControlledFolderAccessAllowedApplications

            Write-Verbose -Message 'Temporarily adding the currently running PowerShell executables to the Controlled Folder Access allowed apps list'
            # so that the script can run without interruption. This change is reverted at the end.
            # Adding powercfg.exe so Controlled Folder Access won't complain about it in BitLocker category when setting hibernate file size to full
            foreach ($FilePath in (((Get-ChildItem -Path "$PSHOME\*.exe" -File).FullName) + "$env:SystemDrive\Windows\System32\powercfg.exe")) {
                Add-MpPreference -ControlledFolderAccessAllowedApplications $FilePath
            }
        }

        #region RequirementsCheck
        # Home edition and Home edition single-language SKUs
        if ((Get-CimInstance -ClassName Win32_OperatingSystem).OperatingSystemSKU -in '101', '100') {
            Write-Warning -Message 'The Windows Home edition has been detected, some categories are unavailable and the remaining categories are applied in a best effort fashion.'
        }

        # Get OS build version
        [System.Decimal]$OSBuild = [System.Environment]::OSVersion.Version.Build
        # Get the Update Build Revision (UBR) number
        [System.Decimal]$UBR = Get-ItemPropertyValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'UBR'
        # Create the full OS build number as seen in Windows Settings
        [System.Decimal]$FullOSBuild = "$OSBuild.$UBR"

        Write-Verbose -Message 'Checking if the OS build is equal or greater than the required build...'
        if (-NOT ($FullOSBuild -ge $Requiredbuild)) {
            Throw "You're not using the latest build of the Windows OS. A minimum build of $Requiredbuild is required but your OS build is $FullOSBuild`nPlease go to Windows Update to install the updates and then try again."
        }

        if ($IsAdmin) {
            Write-Verbose -Message 'Checking if Secure Boot is enabled...'
            if (-NOT (Confirm-SecureBootUEFI)) {
                Throw 'Secure Boot is not enabled. Please enable it in your UEFI settings and try again.'
            }

            Write-Verbose -Message 'Checking if TPM is available and enabled...'
            [System.Object]$TPM = Get-Tpm
            if (-NOT ($TPM.tpmpresent -and $TPM.tpmenabled)) {
                Throw 'TPM is not available or enabled, please enable it in UEFI settings and try again.'
            }

            if (-NOT ($MDAVConfigCurrent.AMServiceEnabled -eq $true)) {
                Throw 'Microsoft Defender Anti Malware service is not enabled, please enable it and then try again.'
            }

            if (-NOT ($MDAVConfigCurrent.AntispywareEnabled -eq $true)) {
                Throw 'Microsoft Defender Anti Spyware is not enabled, please enable it and then try again.'
            }

            if (-NOT ($MDAVConfigCurrent.AntivirusEnabled -eq $true)) {
                Throw 'Microsoft Defender Anti Virus is not enabled, please enable it and then try again.'
            }

            if ($MDAVConfigCurrent.AMRunningMode -ne 'Normal') {
                Throw "Microsoft Defender is running in $($MDAVConfigCurrent.AMRunningMode) state, please remove any 3rd party AV and then try again."
            }
        }
        #endregion RequirementsCheck

        try {

            # Detecting whether GUI parameter is present or not
            if ($PSBoundParameters.GUI.IsPresent) {

                # Load the PresentationFramework assembly to use the Xaml reader
                Add-Type -AssemblyName PresentationFramework

                # Capture the currently available RunSpaces before initiating any new RunSpaces
                $RunSpacesBefore = Get-Runspace

                # A synchronized hashtable to store all of the data that needs to be shared between the RunSpaces
                $SyncHash = [System.Collections.Hashtable]::Synchronized(@{})

                # A nested hashtable to store all of the exported functions
                $SyncHash['ExportedFunctions'] = [System.Collections.Hashtable]@{}

                # A nested hashtable to store all of the variables from the function scope
                $SyncHash['GlobalVars'] = [System.Collections.Hashtable]@{}

                # A nested hashtable to store all of the GUI elements
                $SyncHash['GUI'] = [System.Collections.Hashtable]@{}

                # To store the log messages
                $SyncHash.Logger = [System.Collections.ArrayList]::Synchronized((New-Object -TypeName System.Collections.ArrayList))

                # Create and add the header to the log messages
                $SyncHash.Logger.Add(@"
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
"@) | Out-Null # Because it outputs the index of the added item

                # For storing the RunSpace data
                $SyncHash.ListOfStuff = New-Object -TypeName System.Collections.ArrayList

                # Initialize a flag to determine whether to write logs or not, set to false by default
                $SyncHash.ShouldWriteLogs = $false

                # Creating a RunSpace for the GUI
                $GUIRunSpace = [System.Management.Automation.RunSpaces.RunSpaceFactory]::CreateRunSpace()
                $GUIRunSpace.ApartmentState = 'STA'
                $GUIRunSpace.ThreadOptions = 'ReuseThread'

                # Creating a PowerShell object for the GUI
                $GUIPowerShell = [System.Management.Automation.PowerShell]::Create()
                # Assigning the RunSpace to the PowerShell object
                $GUIPowerShell.RunSpace = $GUIRunSpace
                # Opening the RunSpace
                $GUIRunSpace.Open()

                # Adding the Xaml and the synchronized hashtable variables to the RunSpace
                $GUIRunSpace.SessionStateProxy.SetVariable('SyncHash', $SyncHash)
                $GUIRunSpace.SessionStateProxy.SetVariable('Xaml', $Xaml)

                # This will set up the RunSpace to already know these variables and what data assigned to them
                $SyncHash['GlobalVars']['IsLocally'] = $IsLocally
                $SyncHash['GlobalVars']['IsAdmin'] = $IsAdmin
                $SyncHash['GlobalVars']['CurrentExecutionPolicy'] = $CurrentExecutionPolicy
                $SyncHash['GlobalVars']['Requiredbuild'] = $Requiredbuild
                $SyncHash['GlobalVars']['CurrentUserTempDirectoryPath'] = $CurrentUserTempDirectoryPath
                $SyncHash['GlobalVars']['ShouldEnableOptionalDiagnosticData'] = $ShouldEnableOptionalDiagnosticData
                $SyncHash['GlobalVars']['HardeningModulePath'] = $HardeningModulePath
                $SyncHash['GlobalVars']['MDAVConfigCurrent'] = $MDAVConfigCurrent
                $SyncHash['GlobalVars']['MDAVPreferencesCurrent'] = $MDAVPreferencesCurrent
                $SyncHash['GlobalVars']['CFAAllowedAppsBackup'] = $CFAAllowedAppsBackup
                $SyncHash['GlobalVars']['Offline'] = ($Offline -eq $true) ? $true : $false
                $SyncHash['GlobalVars']['WorkingDir'] = $WorkingDir
                $SyncHash['GlobalVars']['BootDMAProtectionCheck'] = $BootDMAProtectionCheck
                $SyncHash['GlobalVars']['ValidAllowedCategories'] = [Categoriex]::new().GetValidValues()

                # Adding the parent host to the synchronized hashtable
                $SyncHash.ParentHost = $Host

                # Pass any necessary function as nested hashtable inside of the main synced hashtable
                # so they can be easily passed to any other RunSpaces
                'Write-GUI', 'Start-FileDownload', 'Edit-Registry', 'Block-CountryIP' | ForEach-Object -Process {
                    $SyncHash['ExportedFunctions']["$_"] = Get-Item -Path "Function:$_"
                }

                # Add the script to the GUI PowerShell object
                [System.Void]$GUIPowerShell.AddScript({

                        $Reader = New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $Xaml
                        $SyncHash.Window = [System.Windows.Markup.XamlReader]::Load( $Reader )

                        # Finding the ParentGrid
                        [System.Windows.DependencyObject]$ParentGrid = $SyncHash.Window.FindName('ParentGrid')
                        [System.Windows.DependencyObject]$MainTabControlToggle = $ParentGrid.FindName('MainTabControlToggle')
                        [System.Windows.DependencyObject]$MainContentControl = $MainTabControlToggle.FindName('MainContentControl')

                        # Due to using ToggleButton as Tab Control element, this is somehow considered the parent of all inner elements
                        [System.Windows.Style]$MainContentControlStyle = $MainContentControl.FindName('MainContentControlStyle')

                        # Create variables for all elements inside of $MainContentControlStyle
                        $XAML.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
                            $SyncHash['GUI'][$_.Name] = $MainContentControlStyle.FindName($_.Name)
                        }

                        # Creating variables for the important elements inside of the ParentGrid
                        $SyncHash['GUI']['OutputTextBlock'] = $SyncHash.Window.FindName('ParentGrid').FindName('OutputTextBlock')
                        $SyncHash['GUI']['ScrollerForOutputTextBlock'] = $SyncHash.Window.FindName('ParentGrid').FindName('ScrollerForOutputTextBlock')

                        # Redefining all of the exported variables inside of the RunSpace
                        $SyncHash.GlobalVars.GetEnumerator() | ForEach-Object -Process {
                            Set-Variable -Name $_.Key -Value $_.Value -Force
                        }

                        # Redefining all of the exported functions inside of the RunSpace
                        $SyncHash.ExportedFunctions.GetEnumerator() | ForEach-Object -Process {
                            New-Item -Path "Function:\$($_.Key)" -Value $_.Value.ScriptBlock -Force | Out-Null
                        }

                        #Region assigning image source paths to the buttons

                        # If the script is running in the context of module then use the local images
                        if ($IsLocally) {
                            [System.String]$GUIIconPath = "$HardeningModulePath\Resources\Media\path.png"
                            [System.String]$GUILogPath = "$HardeningModulePath\Resources\Media\log.png"
                            [System.String]$GUIExecutePath = "$HardeningModulePath\Resources\Media\start.png"
                        }
                        # If the script is running directly from GitHub repository, download the required image files to the working directory and use them
                        else {
                            [System.String]$RandomStringFromGUID = [System.Guid]::newGuid().ToString().Replace('-', '')

                            Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/Main%20files/Resources/Media/Path.png' -OutFile "$CurrentUserTempDirectoryPath\$RandomStringFromGUID path.png"
                            Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/Main%20files/Resources/Media/Log.png' -OutFile "$CurrentUserTempDirectoryPath\$RandomStringFromGUID log.png"
                            Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/Main%20files/Resources/Media/start.png' -OutFile "$CurrentUserTempDirectoryPath\$RandomStringFromGUID start.png"
                            # Used for the toast notification icon later in the code
                            Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/Main%20files/Resources/Media/ToastNotificationIcon.png' -OutFile "$WorkingDir\ToastNotificationIcon.png"

                            [System.String]$GUIIconPath = "$CurrentUserTempDirectoryPath\$RandomStringFromGUID path.png"
                            [System.String]$GUILogPath = "$CurrentUserTempDirectoryPath\$RandomStringFromGUID log.png"
                            [System.String]$GUIExecutePath = "$CurrentUserTempDirectoryPath\$RandomStringFromGUID start.png"
                        }

                        $SyncHash['GUI'].PathIcon1.Source = $GUIIconPath
                        $SyncHash['GUI'].PathIcon2.Source = $GUIIconPath
                        $SyncHash['GUI'].PathIcon3.Source = $GUIIconPath
                        $SyncHash['GUI'].LogButtonIcon.Source = $GUILogPath
                        $ParentGrid.FindName('ExecuteButtonIcon').Source = $GUIExecutePath
                        #Endregion assigning image source paths to the buttons

                        # Defining the correlation between Categories and which Sub-Categories they activate
                        [System.Collections.Hashtable]$Correlation = @{
                            'MicrosoftSecurityBaselines' = @('SecBaselines_NoOverrides')
                            'MicrosoftDefender'          = @('MSFTDefender_SAC', 'MSFTDefender_NoDiagData', 'MSFTDefender_NoScheduledTask', 'MSFTDefender_BetaChannels')
                            'LockScreen'                 = @('LockScreen_CtrlAltDel', 'LockScreen_NoLastSignedIn')
                            'UserAccountControl'         = @('UAC_NoFastSwitching', 'UAC_OnlyElevateSigned')
                            'CountryIPBlocking'          = @('CountryIPBlocking_OFAC')
                        }
                        function Update-SubCategories {
                            <#
                        .SYNOPSIS
                            Function to update sub-category items based on the checked categories
                        #>

                            # Disable all sub-category items first
                            $SyncHash['GUI'].SubCategories.Items | ForEach-Object -Process { $_.IsEnabled = $false }

                            # Get all checked categories
                            $CheckedCategories = $SyncHash['GUI'].Categories.Items | Where-Object -FilterScript { $_.Content.IsChecked }

                            # Enable the corresponding sub-category items
                            foreach ($CategoryItem in $CheckedCategories) {
                                $CategoryContent = $CategoryItem.Content.Name
                                $Correlation[$CategoryContent] | ForEach-Object -Process {
                                    $SubCategoryName = $_
                                    $SyncHash['GUI'].SubCategories.Items | Where-Object -FilterScript { $_.Content.Name -eq $SubCategoryName } | ForEach-Object -Process {
                                        $_.IsEnabled = $true
                                    }
                                }
                            }

                            # Uncheck sub-category items whose category is not selected
                            $SyncHash['GUI'].SubCategories.Items | Where-Object -FilterScript { $_.IsEnabled -eq $false } | ForEach-Object -Process {
                                $_.Content.IsChecked = $false
                            }

                            # Disable categories that are not valid for the current session
                            foreach ($Item in $SyncHash['GUI'].Categories.Items) {
                                if ($Item.Content.Name -notin $ValidAllowedCategories) {
                                    $Item.IsEnabled = $false
                                }
                            }
                        }

                        # Add Checked and Unchecked event handlers to category checkboxes
                        foreach ($CategoryItem in $SyncHash['GUI'].Categories.Items) {
                            $CheckBox = $CategoryItem.Content
                            # Set the DataContext to the ListViewItem
                            $CheckBox.DataContext = $CategoryItem
                            $CheckBox.Add_Checked({ Update-SubCategories })
                            $CheckBox.Add_Unchecked({ Update-SubCategories })
                        }

                        # Register an event handler for the window size changed event
                        $SyncHash.Window.add_SizeChanged({
                                # Calculate the max width based on the window width
                                # Subtract 50 to account for the padding and margin
                                [System.Int64]$NewMaxWidth = $SyncHash.Window.ActualWidth - 50

                                # Update the main TextBox's MaxWidth property dynamically, instead of setting it to a fixed value in the XAML
                                $SyncHash['GUI']['OutputTextBlock'].MaxWidth = $NewMaxWidth
                            })

                        #Region Check-Uncheck buttons for Categories

                        # Add click event for 'Check All' button
                        $SyncHash['GUI'].SelectAllCategories.Add_Checked({
                                $SyncHash['GUI'].Categories.Items | ForEach-Object -Process {
                                    if ($_.Content.Name -in $ValidAllowedCategories) {
                                        $_.Content.IsChecked = $true
                                    }
                                }
                            })

                        # Add click event for 'Uncheck All' button
                        $SyncHash['GUI'].SelectAllCategories.Add_Unchecked({
                                $SyncHash['GUI'].Categories.Items | ForEach-Object -Process {
                                    $_.Content.IsChecked = $false
                                }
                            })
                        #Endregion Check-Uncheck buttons for Categories

                        #Region Check-Uncheck buttons for Sub-Categories
                        # Add click event for 'Check All' button for enabled sub-categories
                        $SyncHash['GUI'].SelectAllSubCategories.Add_Checked({
                                $SyncHash['GUI'].SubCategories.Items | Where-Object -FilterScript { $_.IsEnabled -eq $true } | ForEach-Object -Process {
                                    $CheckBox = $_.Content
                                    $CheckBox.IsChecked = $true
                                }
                            })

                        # Add click event for 'Uncheck All' button from sub-categories, regardless of whether they are enabled or disabled
                        $SyncHash['GUI'].SelectAllSubCategories.Add_Unchecked({
                                $SyncHash['GUI'].SubCategories.Items | ForEach-Object -Process {
                                    $CheckBox = $_.Content
                                    $CheckBox.IsChecked = $false
                                }
                            })
                        #Endregion Check-Uncheck buttons for Sub-Categories

                        #Region 3-Log related elements

                        # Initially set the visibility of the text area for the selected LogPath to Collapsed since nothing is selected by the user
                        $SyncHash['GUI'].txtFilePath.Visibility = 'Collapsed'

                        # Initialize the LogPath button element as disabled since the checkbox to enable logging hasn't been checked yet
                        $SyncHash['GUI'].LogPath.IsEnabled = $false

                        # If the Log checkbox is checked, enable the LogPath button
                        $SyncHash['GUI'].Log.Add_Checked({
                                $SyncHash['GUI'].LogPath.IsEnabled = $true
                            })

                        # If the Log checkbox is unchecked, disable the LogPath button and set the selected LogPath text area's visibility to collapsed again
                        $SyncHash['GUI'].Log.Add_Unchecked({
                                $SyncHash['GUI'].LogPath.IsEnabled = $false

                                $SyncHash['GUI'].txtFilePath.Visibility = 'Collapsed'
                            })

                        # Event handler for the Log Path button click to open a file path picker dialog
                        $SyncHash['GUI'].LogPath.Add_Click({

                                Add-Type -AssemblyName System.Windows.Forms
                                [System.Windows.Forms.SaveFileDialog]$Dialog = New-Object -TypeName System.Windows.Forms.SaveFileDialog
                                $Dialog.InitialDirectory = [System.Environment]::GetFolderPath('Desktop')
                                $Dialog.Filter = 'Text files (*.txt)|*.txt'
                                $Dialog.Title = 'Choose where to save the log file'

                                if ($Dialog.ShowDialog() -eq 'OK') {
                                    $SyncHash['GUI'].txtFilePath.Text = $Dialog.FileName

                                    # set the selected LogPath text area's visibly to enabled once the user selected a file path
                                    $SyncHash['GUI'].txtFilePath.Visibility = 'Visible'

                                    Write-GUI -Text "Logs will be saved in: $($SyncHash['GUI'].txtFilePath.Text)"

                                    $SyncHash.ShouldWriteLogs = $true
                                }
                            })

                        #Endregion 3-Log related elements

                        #Region Offline-Mode-Tab

                        # If the Offline Mode checkbox is checked
                        $SyncHash['GUI'].EnableOfflineMode.Add_Checked({
                                $SyncHash['GUI'].MicrosoftSecurityBaselineZipButton.IsEnabled = $true
                                $SyncHash['GUI'].MicrosoftSecurityBaselineZipTextBox.IsEnabled = $true
                                $SyncHash['GUI'].Microsoft365AppsSecurityBaselineZipButton.IsEnabled = $true
                                $SyncHash['GUI'].Microsoft365AppsSecurityBaselineZipTextBox.IsEnabled = $true
                                $SyncHash['GUI'].LGPOZipButton.IsEnabled = $true
                                $SyncHash['GUI'].LGPOZipTextBox.IsEnabled = $true
                            })

                        # Function to disable the Offline Mode configuration inputs
                        Function Disable-OfflineModeConfigInputs {
                            $SyncHash['GUI'].MicrosoftSecurityBaselineZipButton.IsEnabled = $false
                            $SyncHash['GUI'].MicrosoftSecurityBaselineZipTextBox.IsEnabled = $false
                            $SyncHash['GUI'].Microsoft365AppsSecurityBaselineZipButton.IsEnabled = $false
                            $SyncHash['GUI'].Microsoft365AppsSecurityBaselineZipTextBox.IsEnabled = $false
                            $SyncHash['GUI'].LGPOZipButton.IsEnabled = $false
                            $SyncHash['GUI'].LGPOZipTextBox.IsEnabled = $false
                        }

                        # Initially disable the Offline Mode configuration inputs until the Offline Mode checkbox is checked
                        Disable-OfflineModeConfigInputs

                        # Actions to take when the Offline Mode parameter was not passed with the function
                        if (-NOT $Offline) {

                            # Disable the Offline mode checkbox if -Offline parameter was not used with the function
                            $SyncHash['GUI'].EnableOfflineMode.IsEnabled = $false

                            # Display a message showing how to activate the offline mode

                            # Add a new row definition for the text message
                            [System.Windows.Controls.RowDefinition]$OfflineModeUnavailableRow = New-Object -Type System.Windows.Controls.RowDefinition
                            $OfflineModeUnavailableRow.Height = 50
                            $SyncHash['GUI'].Grid2.RowDefinitions.Add($OfflineModeUnavailableRow)

                            # Create a new text box
                            [System.Windows.Controls.TextBox]$OfflineModeUnavailableNoticeBox = New-Object -Type System.Windows.Controls.TextBox
                            $OfflineModeUnavailableNoticeBox.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Stretch
                            $OfflineModeUnavailableNoticeBox.VerticalAlignment = [System.Windows.VerticalAlignment]::Stretch
                            $OfflineModeUnavailableNoticeBox.TextWrapping = [System.Windows.TextWrapping]::Wrap
                            $OfflineModeUnavailableNoticeBox.SetValue([System.Windows.Controls.Grid]::ColumnSpanProperty, 2)
                            $OfflineModeUnavailableNoticeBox.Text = 'To enable offline mode, use: Protect-WindowsSecurity -GUI -Offline'
                            $OfflineModeUnavailableNoticeBox.TextAlignment = 'Center'
                            $OfflineModeUnavailableNoticeBox.Background = 'transparent'
                            $OfflineModeUnavailableNoticeBox.FontSize = 20
                            $OfflineModeUnavailableNoticeBox.BorderThickness = '0,0,0,0'
                            $OfflineModeUnavailableNoticeBox.Margin = New-Object -Type System.Windows.Thickness -ArgumentList (10, 20, 10, 0)
                            $OfflineModeUnavailableNoticeBox.ToolTip = 'To enable offline mode, use: Protect-WindowsSecurity -GUI -Offline'
                            $OfflineModeUnavailableNoticeBox.SetValue([System.Windows.Controls.Grid]::RowProperty, 4)

                            # Create a gradient brush for the text color
                            [System.Windows.Media.LinearGradientBrush]$GradientBrush = New-Object -TypeName System.Windows.Media.LinearGradientBrush
                            $GradientBrush.GradientStops.Add((New-Object -TypeName System.Windows.Media.GradientStop -ArgumentList ('Purple', 0)))
                            $GradientBrush.GradientStops.Add((New-Object -TypeName System.Windows.Media.GradientStop -ArgumentList ('Blue', 1)))
                            $OfflineModeUnavailableNoticeBox.Foreground = $GradientBrush

                            # Add the text box to the grid
                            $SyncHash['GUI'].Grid2.Children.Add($OfflineModeUnavailableNoticeBox)
                        }

                        # If the Offline Mode checkbox is Unchecked
                        $SyncHash['GUI'].EnableOfflineMode.Add_Unchecked({
                                Disable-OfflineModeConfigInputs
                            })

                        # Define the click event for the Microsoft Security Baseline Zip button
                        $SyncHash['GUI'].MicrosoftSecurityBaselineZipButton.Add_Click({

                                Add-Type -AssemblyName System.Windows.Forms
                                [System.Windows.Forms.OpenFileDialog]$Dialog = New-Object -TypeName 'System.Windows.Forms.OpenFileDialog'
                                $Dialog.InitialDirectory = [System.Environment]::GetFolderPath('Desktop')
                                $Dialog.Filter = 'Zip files (*.zip)|*.zip'
                                $Dialog.Title = 'Select the Microsoft Security Baseline Zip file'

                                if ($Dialog.ShowDialog() -eq 'OK') {

                                    try {
                                        # Load the System.IO.Compression assembly
                                        [System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem') | Out-Null
                                        # Open the zip file in read mode
                                        [System.IO.Compression.ZipArchive]$ZipArchive = [IO.Compression.ZipFile]::OpenRead($Dialog.FileName)
                                        # Make sure the selected zip has the required file
                                        if (-NOT ($ZipArchive.Entries | Where-Object -FilterScript { $_.FullName -like 'Windows*Security Baseline/Scripts/Baseline-LocalInstall.ps1' })) {
                                            Write-GUI -Text 'The selected Zip file does not contain the Microsoft Security Baselines Baseline-LocalInstall.ps1 which is required for the Protect-WindowsSecurity function to work properly'
                                        }
                                        else {
                                            $SyncHash['GUI'].MicrosoftSecurityBaselineZipTextBox.Text = $Dialog.FileName
                                        }
                                    }
                                    catch {
                                        Write-GUI -Text $_.Exception.Message
                                    }
                                    finally {
                                        # Close the handle whether the zip file is valid or not
                                        $ZipArchive.Dispose()
                                    }
                                }
                            })

                        # Define the click event for the Microsoft 365 Apps Security Baseline Zip button
                        $SyncHash['GUI'].Microsoft365AppsSecurityBaselineZipButton.Add_Click({

                                Add-Type -AssemblyName System.Windows.Forms
                                [System.Windows.Forms.OpenFileDialog]$Dialog = New-Object -TypeName 'System.Windows.Forms.OpenFileDialog'
                                $Dialog.InitialDirectory = [System.Environment]::GetFolderPath('Desktop')
                                $Dialog.Filter = 'Zip files (*.zip)|*.zip'
                                $Dialog.Title = 'Select the Microsoft 365 Apps Security Baseline Zip file'

                                if ($Dialog.ShowDialog() -eq 'OK') {

                                    try {
                                        # Load the System.IO.Compression assembly
                                        [System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem') | Out-Null
                                        # Open the zip file in read mode
                                        [System.IO.Compression.ZipArchive]$ZipArchive = [IO.Compression.ZipFile]::OpenRead($Dialog.FileName )
                                        # Make sure the selected zip has the required file
                                        if (-NOT ($ZipArchive.Entries | Where-Object -FilterScript { $_.FullName -like 'Microsoft 365 Apps for Enterprise*/Scripts/Baseline-LocalInstall.ps1' })) {
                                            Write-GUI -Text 'The selected Zip file does not contain the Microsoft 365 Apps for Enterprise Security Baselines Baseline-LocalInstall.ps1 which is required for the Protect-WindowsSecurity function to work properly'
                                        }
                                        else {
                                            $SyncHash['GUI'].Microsoft365AppsSecurityBaselineZipTextBox.Text = $Dialog.FileName
                                        }
                                    }
                                    catch {
                                        Write-GUI -Text $_.Exception.Message
                                    }
                                    finally {
                                        # Close the handle whether the zip file is valid or not
                                        $ZipArchive.Dispose()
                                    }
                                }
                            })

                        # Define the click event for the LGPO Zip button
                        $SyncHash['GUI'].LGPOZipButton.Add_Click({

                                Add-Type -AssemblyName System.Windows.Forms
                                [System.Windows.Forms.OpenFileDialog]$Dialog = New-Object -TypeName 'System.Windows.Forms.OpenFileDialog'
                                $Dialog.InitialDirectory = [System.Environment]::GetFolderPath('Desktop')
                                $Dialog.Filter = 'Zip files (*.zip)|*.zip'
                                $Dialog.Title = 'Select the LGPO Zip file'

                                if ($Dialog.ShowDialog() -eq 'OK') {

                                    try {
                                        # Load the System.IO.Compression assembly
                                        [System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem') | Out-Null
                                        # Open the zip file in read mode
                                        [System.IO.Compression.ZipArchive]$ZipArchive = [IO.Compression.ZipFile]::OpenRead($Dialog.FileName)
                                        # Make sure the selected zip has the required file
                                        if (-NOT ($ZipArchive.Entries | Where-Object -FilterScript { $_.FullName -like 'LGPO_*/LGPO.exe' })) {
                                            Write-GUI -Text 'The selected Zip file does not contain the LGPO.exe which is required for the Protect-WindowsSecurity function to work properly'
                                        }
                                        else {
                                            $SyncHash['GUI'].LGPOZipTextBox.Text = $Dialog.FileName
                                        }
                                    }
                                    catch {
                                        Write-GUI -Text $_.Exception.Message
                                    }
                                    finally {
                                        # Close the handle whether the zip file is valid or not
                                        $ZipArchive.Dispose()
                                    }
                                }
                            })
                        #Endregion Offline-Mode-Tab

                        # Update the sub-categories based on the initial unchecked state of the categories
                        Update-SubCategories

                        # Set a flag indicating that the required files for the Offline operation mode have been processed
                        # When the execute button was clicked, so it won't run twice
                        $SyncHash.StartFileDownloadHasRun = $false

                        # Defining a set of commands to run when the GUI window is loaded
                        $SyncHash.Window.Add_ContentRendered({

                                Write-GUI -Text ($IsAdmin ? 'Hello, Running as Administrator' : 'Hello, Running as Non-Administrator, some categories are disabled')

                                # Set the execute button to disabled until all the prerequisites are met
                                $SyncHash.window.FindName('Execute').IsEnabled = $false

                                # Create a new RunSpace for the prerequisites commands
                                $PeReqRunSpace = [System.Management.Automation.RunSpaces.RunSpaceFactory]::CreateRunSpace()
                                $PeReqRunSpace.ApartmentState = 'STA'
                                $PeReqRunSpace.ThreadOptions = 'ReuseThread'

                                # Create a new PowerShell object for the prerequisites commands
                                $PeReqPowerShell = [System.Management.Automation.PowerShell]::Create()
                                $PeReqPowerShell.RunSpace = $PeReqRunSpace

                                # Open the RunSpace
                                $PeReqRunSpace.Open()
                                # Add the synchronized hashtable variables to the RunSpace
                                $PeReqRunSpace.SessionStateProxy.SetVariable('SyncHash', $SyncHash)

                                # Define the script to run in the prerequisites RunSpace
                                [System.Void]$PeReqPowerShell.AddScript({

                                        # Make the Write-Verbose parameter output verbose messages regardless of the global preference or selected parameter
                                        $PSDefaultParameterValues = @{
                                            'Invoke-WebRequest:HttpVersion'    = '3.0'
                                            'Invoke-WebRequest:SslProtocol'    = 'Tls12,Tls13'
                                            'Invoke-RestMethod:HttpVersion'    = '3.0'
                                            'Invoke-RestMethod:SslProtocol'    = 'Tls12,Tls13'
                                            'Invoke-WebRequest:ProgressAction' = 'SilentlyContinue'
                                            'Invoke-RestMethod:ProgressAction' = 'SilentlyContinue'
                                            'Copy-Item:Force'                  = $true
                                            'Copy-Item:ProgressAction'         = 'SilentlyContinue'
                                            'Test-Path:ErrorAction'            = 'SilentlyContinue'
                                            'Write-Verbose:Verbose'            = $true
                                        }

                                        # Make all of the main function's variable available again in the 2nd nested RunSpace
                                        $SyncHash.GlobalVars.GetEnumerator() | ForEach-Object -Process {
                                            Set-Variable -Name $_.Key -Value $_.Value -Force
                                        }

                                        # Make all of the main function's functions available again in the 2nd nested RunSpace
                                        $SyncHash.ExportedFunctions.GetEnumerator() | ForEach-Object -Process {
                                            New-Item -Path "Function:\$($_.Key)" -Value $_.Value.ScriptBlock -Force | Out-Null
                                        }

                                        [System.Management.Automation.ScriptBlock]$prerequisitesScriptBlock = {

                                            try {

                                                # Capture the currently available RunSpaces
                                                $RunSpacesBefore = Get-Runspace

                                                # Only download and process the files when GUI is loaded if Offline mode is not used
                                                # Because at this point user might have not selected the files to be used for offline operation
                                                if (-NOT $Offline) {
                                                    Start-FileDownload -WorkingDir $WorkingDir -HardeningModulePath:$HardeningModulePath -Offline:$Offline -SyncHash $SyncHash -IsLocally:$IsLocally -GUI -Verbose:$true
                                                }

                                                # If any new RunSpace was created during the operation, they should be removed prior to removing the current RunSpace otherwise they'd be lingering and occupying resources
                                                # Additional RunSpaces are created automatically for remote proxying to Windows PowerShell because of the cmdlets that are not natively available in PowerShell Core such as Defender cmdlets
                                                $RunSpacesAfter = Get-Runspace

                                                # Determine the RunSpaces that were created during the operation
                                                $RunSpacesToClose = Compare-Object -ReferenceObject $RunSpacesBefore -DifferenceObject $RunSpacesAfter |
                                                Where-Object -FilterScript { $_.SideIndicator -eq '=>' } |
                                                Select-Object -ExpandProperty InputObject

                                                # Close and dispose of the RunSpaces that were created during the operation
                                                if ($RunSpacesToClose) {
                                                    $RunSpacesToClose | ForEach-Object -Process {
                                                        $_.Close()
                                                        $_.Dispose()
                                                    }
                                                }
                                            }
                                            catch {
                                                # Display any error message in a non-terminating way for visibility on the GUI
                                                Write-Output -Message $_.Exception.Message
                                            }
                                        }

                                        &$prerequisitesScriptBlock *>&1 | ForEach-Object -Process {
                                            Write-GUI -Text $_ }

                                        # Using dispatch since the execute button is owned by the GUI (parent) RunSpace and we're in the 2nd nested RunSpace
                                        # Enabling the execute button after all files are downloaded and ready for action
                                        $SyncHash.Window.Dispatcher.Invoke({
                                                $SyncHash.window.FindName('Execute').IsEnabled = $true
                                            })
                                    })

                                # Begin the asynchronous operation of the prerequisites RunSpace
                                $PeReqAsyncObject = $PeReqPowerShell.BeginInvoke()

                                # Add the prerequisites RunSpace and the related PowerShell object to the list of RunSpaces for later disposal
                                $SyncHash.ListOfStuff.Add(([PSCustomObject]@{
                                            Name       = 'PrerequisitesRunSpace'
                                            PowerShell = $PeReqPowerShell
                                            Handle     = $PeReqAsyncObject
                                            RunSpace   = $PeReqRunSpace
                                        }))
                            })

                        # Add the click event for the execute button in the GUI RunSpace
                        $SyncHash.window.FindName('Execute').Add_Click({

                                # Close and dispose of the prerequisites RunSpace and the related PowerShell object when the execute button is pressed
                                $prerequisitesRunSpace = $SyncHash.ListOfStuff | Where-Object { $_.Name -eq 'PrerequisitesRunSpace' }
                                $prerequisitesRunSpace.PowerShell.Dispose()
                                $prerequisitesRunSpace.RunSpace.Close()
                                $prerequisitesRunSpace.RunSpace.Dispose()

                                # Invoke the garbage collector manually to free up resources faster
                                [System.GC]::Collect()

                                # Disable all UI elements in Grid1 except for the textblock while commands are being executed
                                $AllControls = $SyncHash.window.FindName('ParentGrid').Children

                                foreach ($Control in $AllControls) {
                                    # Textblock's parent is the ScrollViewer
                                    if ($Control.Name -notin 'ScrollerForOutputTextBlock') {
                                        $Control.IsEnabled = $false
                                    }
                                }

                                # Gather selected categories
                                $SelectedCategories = $SyncHash['GUI'].Categories.Items | Where-Object -FilterScript { $_.Content.IsChecked } | ForEach-Object -Process { $_.Content.Name }

                                # Gather selected sub-categories
                                # $SelectedSubCategories = $SyncHash['GUI'].SubCategories.Items | Where-Object -FilterScript { $_.Content.IsChecked } | ForEach-Object -Process { $_.Content.Name }

                                # Make the Write-Verbose cmdlet write verbose messages regardless of the global preference or selected parameter
                                # That is the main source of the messages in the GUI
                                $PSDefaultParameterValues = @{
                                    'Write-Verbose:Verbose' = $true
                                }

                                [System.Management.Automation.ScriptBlock]$HardeningFunctionsScriptBlock = {

                                    # Redefine all of the variables in the current scope
                                    $SyncHash.GlobalVars.GetEnumerator() | ForEach-Object -Process {
                                        Set-Variable -Name $_.Key -Value $_.Value -Force
                                    }

                                    # Making the selected sub-categories available in the current scope because the functions called from this scriptblock wouldn't be able to access them otherwise
                                    $SyncHash['GUI'].SubCategories.Items | Where-Object -FilterScript { $_.Content.IsChecked } | ForEach-Object -Process { $_.Content.Name } | ForEach-Object -Process {
                                        # All of the sub-category variables are boolean since they are originally switch parameters in the CLI experience
                                        Set-Variable -Name $_ -Value $true -Force
                                    }

                                    # If Offline mode is used
                                    if ($Offline) {
                                        # If the required files have not been processed for offline mode already
                                        if ($SyncHash.StartFileDownloadHasRun -eq $false) {
                                            # If the checkbox on the GUI for Offline mode is checked
                                            if ($SyncHash['GUI'].EnableOfflineMode.IsChecked) {
                                                # Make sure all 3 fields for offline mode files were selected by the users and they are neither empty nor null
                                                if ((-NOT [System.String]::IsNullOrWhitespace($SyncHash['GUI'].MicrosoftSecurityBaselineZipTextBox.Text)) -and (-NOT [System.String]::IsNullOrWhitespace($SyncHash['GUI'].Microsoft365AppsSecurityBaselineZipTextBox.Text)) -and (-NOT [System.String]::IsNullOrWhitespace($SyncHash['GUI'].LGPOZipTextBox.Text))) {
                                                    # Process the offline mode files selected by the user
                                                    Start-FileDownload -WorkingDir $WorkingDir -HardeningModulePath:$HardeningModulePath -Offline:$Offline -SyncHash $SyncHash -IsLocally:$IsLocally -GUI -Verbose:$true

                                                    # Set a flag indicating this code block should not happen again when the execute button is pressed
                                                    $SyncHash.StartFileDownloadHasRun = $true

                                                    # Redefine all of the variables in the current scope, Again
                                                    # This step is necessary because the Start-FileDownload function adds 5 new variables to the GlobalVars hashtable and if the offline mode is used, the function is not run when GUI is loaded initially
                                                    $SyncHash.GlobalVars.GetEnumerator() | ForEach-Object -Process {
                                                        Set-Variable -Name $_.Key -Value $_.Value -Force
                                                    }
                                                }
                                                else {
                                                    Write-GUI -Text 'Enable Offline Mode checkbox is checked but you have not selected all of the 3 required files for offline mode operation. Please select them and press the execute button again.'
                                                    Return
                                                }
                                            }
                                            else {
                                                Write-GUI -Text 'Offline mode is being used but the Enable Offline Mode checkbox is not checked. Please check it and press the execute button again.'
                                                Return
                                            }
                                        }
                                    }

                                    #Region Helper-Functions-GUI-Experience
                                    function Edit-Addons {
                                        <#
    .SYNOPSIS
        A function to enable or disable Windows features and capabilities.
    .INPUTS
        System.String
    .OUTPUTS
        System.String
    #>
                                        [CmdletBinding()]
                                        param (
                                            [parameter(Mandatory = $true)]
                                            [ValidateSet('Capability', 'Feature')]
                                            [System.String]$Type,
                                            [parameter(Mandatory = $true, ParameterSetName = 'Capability')]
                                            [System.String]$CapabilityName,
                                            [parameter(Mandatory = $true, ParameterSetName = 'Feature')]
                                            [System.String]$FeatureName,
                                            [parameter(Mandatory = $true, ParameterSetName = 'Feature')]
                                            [ValidateSet('Enabling', 'Disabling')]
                                            [System.String]$FeatureAction
                                        )
                                        switch ($Type) {
                                            'Feature' {
                                                [System.String]$ActionCheck = ($FeatureAction -eq 'Enabling') ? 'disabled' : 'enabled'
                                                [System.String]$ActionOutput = ($FeatureAction -eq 'Enabling') ? 'enabled' : 'disabled'

                                                Write-Output -InputObject "`n$FeatureAction $FeatureName"
                                                if ((Get-WindowsOptionalFeature -Online -FeatureName $FeatureName).state -eq $ActionCheck) {
                                                    try {
                                                        if ($FeatureAction -eq 'Enabling') {
                                                            Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -All -NoRestart | Out-Null
                                                        }
                                                        else {
                                                            Disable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart | Out-Null
                                                        }
                                                        # Shows the successful message only if the process was successful
                                                        Write-Output -InputObject "$FeatureName was successfully $ActionOutput"
                                                    }
                                                    catch {
                                                        # show errors in non-terminating way
                                                        $_
                                                    }
                                                }
                                                else {
                                                    Write-Output -InputObject "$FeatureName is already $ActionOutput"
                                                }
                                                break
                                            }
                                            'Capability' {
                                                Write-Output -InputObject "`nRemoving $CapabilityName"
                                                if ((Get-WindowsCapability -Online | Where-Object -FilterScript { $_.Name -like "*$CapabilityName*" }).state -ne 'NotPresent') {
                                                    try {
                                                        Get-WindowsCapability -Online | Where-Object -FilterScript { $_.Name -like "*$CapabilityName*" } | Remove-WindowsCapability -Online | Out-Null
                                                        # Shows the successful message only if the process was successful
                                                        Write-Output -InputObject "$CapabilityName was successfully removed."
                                                    }
                                                    catch {
                                                        # show errors in non-terminating way
                                                        $_
                                                    }
                                                }
                                                else {
                                                    Write-Output -InputObject "$CapabilityName is already removed."
                                                }
                                                break
                                            }
                                        }
                                    }
                                    #Endregion Helper-Functions-GUI-Experience

                                    #Region Hardening-Categories-Functions-GUI-Experience
                                    Function Invoke-MicrosoftSecurityBaselines {
                                        Write-Verbose -Message '========================='
                                        Write-Verbose -Message 'Processing the Security Baselines category function'
                                        Write-Verbose -Message "Changing the current directory to '$MicrosoftSecurityBaselinePath\Scripts\'"

                                        Push-Location -Path "$MicrosoftSecurityBaselinePath\Scripts\"

                                        :MicrosoftSecurityBaselinesCategoryLabel switch ($SecBaselines_NoOverrides ? 'Yes' : 'Yes, With the Optional Overrides (Recommended)') {
                                            'Yes' {
                                                Write-Verbose -Message 'Applying the Microsoft Security Baselines without the optional overrides'

                                                Write-Verbose -Message 'Running the official PowerShell script included in the Microsoft Security Baseline file downloaded from Microsoft servers'
                                                .\Baseline-LocalInstall.ps1 -Win11NonDomainJoined 4>$null
                                            }
                                            'Yes, With the Optional Overrides (Recommended)' {
                                                Write-Verbose -Message 'Applying the Microsoft Security Baselines with the optional overrides'

                                                Write-Verbose -Message 'Running the official PowerShell script included in the Microsoft Security Baseline file downloaded from Microsoft servers'
                                                .\Baseline-LocalInstall.ps1 -Win11NonDomainJoined 4>$null

                                                Start-Sleep -Seconds 1

                                                &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Overrides for Microsoft Security Baseline\registry.pol"
                                                &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\Overrides for Microsoft Security Baseline\GptTmpl.inf"

                                                Write-Verbose -Message 'Re-enabling the XblGameSave Standby Task that gets disabled by Microsoft Security Baselines'
                                                SCHTASKS.EXE /Change /TN \Microsoft\XblGameSave\XblGameSaveTask /Enable
                                            }
                                            'No' { break MicrosoftSecurityBaselinesCategoryLabel }
                                        }

                                        Write-Verbose -Message 'Restoring the original directory location'
                                        Pop-Location
                                    }
                                    Function Invoke-Microsoft365AppsSecurityBaselines {
                                        Write-Verbose -Message '========================='
                                        Write-Verbose -Message 'Processing the M365 Apps Security category function'
                                        Write-Verbose -Message 'Applying the Microsoft 365 Apps Security Baseline'
                                        Write-Verbose -Message "Changing the current directory to '$Microsoft365SecurityBaselinePath\Scripts\'"

                                        Push-Location -Path "$Microsoft365SecurityBaselinePath\Scripts\"

                                        Write-Verbose -Message 'Running the official PowerShell script included in the Microsoft 365 Apps Security Baseline file downloaded from Microsoft servers'
                                        .\Baseline-LocalInstall.ps1 4>$null

                                        Write-Verbose -Message 'Restoring the original directory location'
                                        Pop-Location
                                    }
                                    Function Invoke-MicrosoftDefender {
                                        Write-Verbose -Message '========================='
                                        Write-Verbose -Message 'Processing the Microsoft Defender category function'
                                        Write-Verbose -Message 'Running the Microsoft Defender category'

                                        &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Microsoft Defender Policies\registry.pol"

                                        # Make sure the parameters are available in the ConfigDefender module before using them
                                        [System.Collections.Hashtable]$AvailableDefenderParams = (Get-Command -Name Set-MpPreference).Parameters
                                        Function Set-DefenderConfigWithCheck {
                                            Param ([System.String]$Name, $Value)
                                            if ($AvailableDefenderParams.ContainsKey($Name)) {
                                                [System.Collections.Hashtable]$Params = @{$Name = $Value }
                                                Set-MpPreference @Params
                                            }
                                            else {
                                                Write-Warning -Message "The parameter $Name is not available yet, restart the OS one more time after updating and try again."
                                            }
                                        }

                                        Write-Verbose -Message 'Optimizing Network Protection Performance of the Microsoft Defender'
                                        Set-DefenderConfigWithCheck -Name 'AllowSwitchToAsyncInspection' -Value $True

                                        Write-Verbose -Message 'Enabling Real-time protection and Security Intelligence Updates during OOBE'
                                        Set-DefenderConfigWithCheck -Name 'OobeEnableRtpAndSigUpdate' -Value $True

                                        Write-Verbose -Message 'Enabling Intel Threat Detection Technology'
                                        Set-DefenderConfigWithCheck -Name 'IntelTDTEnabled' -Value $True

                                        Write-Verbose -Message 'Enabling Restore point scan'
                                        Set-DefenderConfigWithCheck -Name 'DisableRestorePoint' -Value $False

                                        Write-Verbose -Message 'Disabling Performance mode of Defender that only applies to Dev drives by lowering security'
                                        Set-DefenderConfigWithCheck -Name 'PerformanceModeStatus' -Value Disabled

                                        Write-Verbose -Message 'Setting the Network Protection to block network traffic instead of displaying a warning'
                                        Set-DefenderConfigWithCheck -Name 'EnableConvertWarnToBlock' -Value $True

                                        Write-Verbose -Message 'Setting the Brute-Force Protection to use cloud aggregation to block IP addresses that are over 99% likely malicious'
                                        Set-DefenderConfigWithCheck -Name 'BruteForceProtectionAggressiveness' -Value 1 # 2nd level aggression will come after further testing

                                        Write-Verbose -Message 'Setting the Brute-Force Protection to prevent suspicious and malicious behaviors'
                                        Set-DefenderConfigWithCheck -Name 'BruteForceProtectionConfiguredState' -Value 1

                                        Write-Verbose -Message 'Setting the internal feature logic to determine blocking time for the Brute-Force Protections'
                                        Set-DefenderConfigWithCheck -Name 'BruteForceProtectionMaxBlockTime' -Value 0

                                        Write-Verbose -Message 'Setting the Remote Encryption Protection to use cloud intel and context, and block when confidence level is above 90%'
                                        Set-DefenderConfigWithCheck -Name 'RemoteEncryptionProtectionAggressiveness' -Value 2

                                        Write-Verbose -Message 'Setting the Remote Encryption Protection to prevent suspicious and malicious behaviors'
                                        Set-DefenderConfigWithCheck -Name 'RemoteEncryptionProtectionConfiguredState' -Value 1

                                        Write-Verbose -Message 'Setting the internal feature logic to determine blocking time for the Remote Encryption Protection'
                                        Set-DefenderConfigWithCheck -Name 'RemoteEncryptionProtectionMaxBlockTime' -Value 0

                                        Write-Verbose -Message 'Adding OneDrive folders of all the user accounts (personal and work accounts) to the Controlled Folder Access for Ransomware Protection'
                                        Get-ChildItem -Path "$env:SystemDrive\Users\*\OneDrive*\" -Directory | ForEach-Object -Process { Add-MpPreference -ControlledFolderAccessProtectedFolders $_ }

                                        Write-Verbose -Message 'Enabling Mandatory ASLR Exploit Protection system-wide'
                                        Set-ProcessMitigation -System -Enable ForceRelocateImages

                                        Write-Verbose -Message 'Applying the Process Mitigations'
                                        [System.Object[]]$ProcessMitigations = Import-Csv -Path "$WorkingDir\ProcessMitigations.csv" -Delimiter ','

                                        # Group the data by ProgramName
                                        [System.Object[]]$GroupedMitigations = $ProcessMitigations | Group-Object -Property ProgramName
                                        # Get the current process mitigations
                                        [System.Object[]]$AllAvailableMitigations = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*')

                                        # Loop through each group to remove the mitigations, this way we apply clean set of mitigations in the next step
                                        Write-Verbose -Message 'Removing the existing process mitigations'
                                        foreach ($Group in $GroupedMitigations) {
                                            # To separate the filename from full path of the item in the CSV and then check whether it exists in the system registry
                                            if ($Group.Name -match '\\([^\\]+)$') {
                                                if ($Matches[1] -in $AllAvailableMitigations.pschildname) {
                                                    try {
                                                        Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($Matches[1])" -Recurse -Force
                                                    }
                                                    catch {
                                                        Write-Verbose -Message "Failed to remove $($Matches[1]), it's probably protected by the system."
                                                    }
                                                }
                                            }
                                            elseif ($Group.Name -in $AllAvailableMitigations.pschildname) {
                                                try {
                                                    Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($Group.Name)" -Recurse -Force
                                                }
                                                catch {
                                                    Write-Verbose -Message "Failed to remove $($Group.Name), it's probably protected by the system."
                                                }
                                            }
                                        }

                                        Write-Verbose -Message 'Adding the process mitigations'
                                        foreach ($Group in $GroupedMitigations) {
                                            # Get the program name
                                            [System.String]$ProgramName = $Group.Name

                                            Write-Verbose -Message "Adding process mitigations for $ProgramName"

                                            # Get the list of mitigations to enable
                                            [System.String[]]$EnableMitigations = $Group.Group | Where-Object -FilterScript { $_.Action -eq 'Enable' } | Select-Object -ExpandProperty Mitigation

                                            # Get the list of mitigations to disable
                                            [System.String[]]$DisableMitigations = $Group.Group | Where-Object -FilterScript { $_.Action -eq 'Disable' } | Select-Object -ExpandProperty Mitigation

                                            # Call the Set-ProcessMitigation cmdlet with the lists of mitigations
                                            if ($null -ne $EnableMitigations) {
                                                if ($null -ne $DisableMitigations) {
                                                    Set-ProcessMitigation -Name $ProgramName -Enable $EnableMitigations -Disable $DisableMitigations
                                                }
                                                else {
                                                    Set-ProcessMitigation -Name $ProgramName -Enable $EnableMitigations
                                                }
                                            }
                                            elseif ($null -ne $DisableMitigations) {
                                                Set-ProcessMitigation -Name $ProgramName -Disable $DisableMitigations
                                            }
                                        }

                                        Write-Verbose -Message 'Turning on Data Execution Prevention (DEP) for all applications, including 32-bit programs'
                                        # Old method: bcdedit.exe /set '{current}' nx AlwaysOn | Out-Null
                                        # New method using PowerShell cmdlets added in Windows 11
                                        Set-BcdElement -Element 'nx' -Type 'Integer' -Value '3' -Force

                                        # Suggest turning on Smart App Control only if it's in Eval mode
                                        if ((Get-MpComputerStatus).SmartAppControlState -eq 'Eval') {
                                            :SmartAppControlLabel switch ($MSFTDefender_SAC ? 'Yes' : 'No' ) {
                                                'Yes' {
                                                    Write-Verbose -Message 'Turning on Smart App Control'
                                                    Edit-Registry -path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Policy' -key 'VerifiedAndReputablePolicyState' -value '1' -type 'DWORD' -Action 'AddOrModify'

                                                    # Let the optional diagnostic data be enabled automatically
                                                    $ShouldEnableOptionalDiagnosticData = $True
                                                } 'No' { break SmartAppControlLabel }
                                            }
                                        }

                                        if (($ShouldEnableOptionalDiagnosticData -eq $True) -or ((Get-MpComputerStatus).SmartAppControlState -eq 'On')) {
                                            Write-Verbose -Message 'Enabling Optional Diagnostic Data because SAC is on or user selected to turn it on'
                                            &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Microsoft Defender Policies\Optional Diagnostic Data\registry.pol"
                                        }
                                        else {
                                            # Ask user if they want to turn on optional diagnostic data only if Smart App Control is not already turned off
                                            if ((Get-MpComputerStatus).SmartAppControlState -ne 'Off') {
                                                :SmartAppControlLabel2 switch ($MSFTDefender_NoDiagData ? 'No' : 'Yes') {
                                                    'Yes' {
                                                        Write-Verbose -Message 'Enabling Optional Diagnostic Data'
                                                        &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Microsoft Defender Policies\Optional Diagnostic Data\registry.pol"
                                                    } 'No' { break SmartAppControlLabel2 }
                                                }
                                            }
                                            else {
                                                Write-Verbose -Message 'Smart App Control is turned off, so Optional Diagnostic Data will not be enabled'
                                            }
                                        }

                                        Write-Verbose -Message 'Getting the state of fast weekly Microsoft recommended driver block list update scheduled task'
                                        [System.String]$BlockListScheduledTaskState = (Get-ScheduledTask -TaskName 'MSFT Driver Block list update' -TaskPath '\MSFT Driver Block list update\' -ErrorAction SilentlyContinue).State

                                        # Create scheduled task for fast weekly Microsoft recommended driver block list update if it doesn't exist or exists but is not Ready/Running
                                        if (($BlockListScheduledTaskState -notin 'Ready', 'Running')) {
                                            :TaskSchedulerCreationLabel switch ($MSFTDefender_NoScheduledTask ? 'No' : 'Yes') {
                                                'Yes' {
                                                    Write-Verbose -Message 'Creating scheduled task for fast weekly Microsoft recommended driver block list update'

                                                    # Create a scheduled task action, this defines how to download and install the latest Microsoft Recommended Driver Block Rules
                                                    [Microsoft.Management.Infrastructure.CimInstance]$Action = New-ScheduledTaskAction -Execute 'Powershell.exe' `
                                                        -Argument '-NoProfile -WindowStyle Hidden -command "& {try {Invoke-WebRequest -Uri "https://aka.ms/VulnerableDriverBlockList" -OutFile VulnerableDriverBlockList.zip -ErrorAction Stop}catch{exit 1};Expand-Archive -Path .\VulnerableDriverBlockList.zip -DestinationPath "VulnerableDriverBlockList" -Force;Rename-Item -Path .\VulnerableDriverBlockList\SiPolicy_Enforced.p7b -NewName "SiPolicy.p7b" -Force;Copy-Item -Path .\VulnerableDriverBlockList\SiPolicy.p7b -Destination "$env:SystemDrive\Windows\System32\CodeIntegrity" -Force;citool --refresh -json;Remove-Item -Path .\VulnerableDriverBlockList -Recurse -Force;Remove-Item -Path .\VulnerableDriverBlockList.zip -Force; exit 0;}"'

                                                    # Create a scheduled task principal and assign the SYSTEM account's well-known SID to it so that the task will run under its context
                                                    [Microsoft.Management.Infrastructure.CimInstance]$TaskPrincipal = New-ScheduledTaskPrincipal -LogonType S4U -UserId 'S-1-5-18' -RunLevel Highest

                                                    # Create a trigger for the scheduled task. The task will first run one hour after its creation and from then on will run every 7 days, indefinitely
                                                    [Microsoft.Management.Infrastructure.CimInstance]$Time = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1) -RepetitionInterval (New-TimeSpan -Days 7)

                                                    # Register the scheduled task
                                                    Register-ScheduledTask -Action $Action -Trigger $Time -Principal $TaskPrincipal -TaskPath 'MSFT Driver Block list update' -TaskName 'MSFT Driver Block list update' -Description 'Microsoft Recommended Driver Block List update' -Force | Out-Null

                                                    # Define advanced settings for the scheduled task
                                                    [Microsoft.Management.Infrastructure.CimInstance]$TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility 'Win8' -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -RestartCount 4 -RestartInterval (New-TimeSpan -Hours 6) -RunOnlyIfNetworkAvailable

                                                    # Add the advanced settings we defined above to the scheduled task
                                                    Set-ScheduledTask -TaskName 'MSFT Driver Block list update' -TaskPath 'MSFT Driver Block list update' -Settings $TaskSettings | Out-Null
                                                } 'No' { break TaskSchedulerCreationLabel }
                                            }
                                        }
                                        else {
                                            Write-Verbose -Message "Scheduled task for fast weekly Microsoft recommended driver block list update already exists and is in $BlockListScheduledTaskState state"
                                        }

                                        # Only display this prompt if Engine and Platform update channels are not already set to Beta
                                        if (($MDAVPreferencesCurrent.EngineUpdatesChannel -ne '2') -or ($MDAVPreferencesCurrent.PlatformUpdatesChannel -ne '2')) {
                                            # Set Microsoft Defender engine and platform update channel to beta - Devices in the Windows Insider Program are subscribed to this channel by default.
                                            :DefenderUpdateChannelsLabel switch ($MSFTDefender_BetaChannels ? 'Yes' : 'No') {
                                                'Yes' {
                                                    Write-Verbose -Message 'Setting Microsoft Defender engine and platform update channel to beta'
                                                    Set-MpPreference -EngineUpdatesChannel beta
                                                    Set-MpPreference -PlatformUpdatesChannel beta
                                                } 'No' { break DefenderUpdateChannelsLabel }
                                            }
                                        }
                                        else {
                                            Write-Verbose -Message 'Microsoft Defender engine and platform update channel is already set to beta'
                                        }
                                    }
                                    Function Invoke-AttackSurfaceReductionRules {
                                        Write-Verbose -Message '========================='
                                        Write-Verbose -Message 'Processing the ASR Rules category function'
                                        Write-Verbose -Message 'Running the Attack Surface Reduction Rules category'
                                        &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Attack Surface Reduction Rules Policies\registry.pol"
                                    }
                                    Function Invoke-BitLockerSettings {
                                        Write-Verbose -Message '========================='
                                        Write-Verbose -Message 'Processing the BitLocker category function'
                                        Write-Verbose -Message 'Running the Bitlocker category'

                                        &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Bitlocker Policies\registry.pol"

                                        # This PowerShell script can be used to find out if the DMA Protection is ON \ OFF.
                                        # The Script will show this by emitting True \ False for On \ Off respectively.

                                        # if the type is not already loaded, load it
                                        if (-NOT ('SystemInfo.NativeMethods' -as [System.Type])) {
                                            Write-Verbose -Message 'Loading SystemInfo.NativeMethods type' -Verbose:$false
                                            Add-Type -TypeDefinition $BootDMAProtectionCheck -Language CSharp -Verbose:$false
                                        }
                                        else {
                                            Write-Verbose -Message 'SystemInfo.NativeMethods type is already loaded, skipping loading it again.'
                                        }

                                        # returns true or false depending on whether Kernel DMA Protection is on or off
                                        [System.Boolean]$BootDMAProtection = ([SystemInfo.NativeMethods]::BootDmaCheck()) -ne 0

                                        # Enables or disables DMA protection from Bitlocker Countermeasures based on the status of Kernel DMA protection.
                                        if ($BootDMAProtection) {
                                            Write-Host -Object 'Kernel DMA protection is enabled on the system, disabling Bitlocker DMA protection.' -ForegroundColor Blue
                                            &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Overrides for Microsoft Security Baseline\Bitlocker DMA\Bitlocker DMA Countermeasure OFF\Registry.pol"
                                        }
                                        else {
                                            Write-Host -Object 'Kernel DMA protection is unavailable on the system, enabling Bitlocker DMA protection.' -ForegroundColor Blue
                                            &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Overrides for Microsoft Security Baseline\Bitlocker DMA\Bitlocker DMA Countermeasure ON\Registry.pol"
                                        }

                                        if (-NOT ((Get-MpComputerStatus).IsVirtualMachine)) {

                                            # Check to see if Hibernate is already set to full and HiberFileType is set to 2 which is Full, 1 is Reduced
                                            try {
                                                [System.Int64]$HiberFileType = Get-ItemPropertyValue -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power' -Name 'HiberFileType' -ErrorAction SilentlyContinue
                                            }
                                            catch {
                                                # Do nothing if the key doesn't exist
                                            }
                                            if ($HiberFileType -ne 2) {
                                                # Set Hibernate mode to full
                                                &"$env:SystemDrive\Windows\System32\powercfg.exe" /h /type full | Out-Null
                                            }
                                            else {
                                                Write-Output -InputObject 'Hibernate is already set to full.'
                                            }
                                        }
                                    }
                                    Function Invoke-TLSSecurity {
                                        Write-Verbose -Message '========================='
                                        Write-Verbose -Message 'Processing the TLS Security category function'
                                        Write-Verbose -Message 'Running the TLS Security category'

                                        # creating these registry keys that have forward slashes in them
                                        @(  'DES 56/56', # DES 56-bit
                                            'RC2 40/128', # RC2 40-bit
                                            'RC2 56/128', # RC2 56-bit
                                            'RC2 128/128', # RC2 128-bit
                                            'RC4 40/128', # RC4 40-bit
                                            'RC4 56/128', # RC4 56-bit
                                            'RC4 64/128', # RC4 64-bit
                                            'RC4 128/128', # RC4 128-bit
                                            'Triple DES 168' # 3DES 168-bit (Triple DES 168)
                                        ) | ForEach-Object -Process {
                                            [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME).CreateSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$_") | Out-Null
                                        }

                                        Write-Verbose -Message 'Applying the TLS Security registry settings'
                                        foreach ($Item in $RegistryCSVItems) {
                                            if ($Item.category -eq 'TLS') {
                                                Edit-Registry -path $Item.Path -key $Item.Key -value $Item.Value -type $Item.Type -Action $Item.Action
                                            }
                                        }

                                        Write-Verbose -Message 'Applying the TLS Security Group Policies'
                                        &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\TLS Security\registry.pol"
                                    }
                                    Function Invoke-LockScreen {
                                        Write-Verbose -Message '========================='
                                        Write-Verbose -Message 'Processing the Lock Screen category function'
                                        Write-Verbose -Message 'Running the Lock Screen category'

                                        &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Lock Screen Policies\registry.pol"
                                        &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\Lock Screen Policies\GptTmpl.inf"

                                        # Apply the Don't display last signed-in policy
                                        :LockScreenLastSignedInLabel switch ($LockScreen_NoLastSignedIn ? 'Yes' : 'No') {
                                            'Yes' {
                                                Write-Verbose -Message "Applying the Don't display last signed-in policy"
                                                &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\Lock Screen Policies\Don't display last signed-in\GptTmpl.inf"
                                            } 'No' { break LockScreenLastSignedInLabel }
                                        }

                                        # Enable CTRL + ALT + DEL
                                        :CtrlAltDelLabel switch ($LockScreen_CtrlAltDel ? 'Yes' : 'No') {
                                            'Yes' {
                                                Write-Verbose -Message 'Applying the Enable CTRL + ALT + DEL policy'
                                                &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\Lock Screen Policies\Enable CTRL + ALT + DEL\GptTmpl.inf"
                                            } 'No' { break CtrlAltDelLabel }
                                        }
                                    }
                                    Function Invoke-UserAccountControl {
                                        Write-Verbose -Message '========================='
                                        Write-Verbose -Message 'Processing the User Account Control category function'
                                        Write-Verbose -Message 'Running the User Account Control category'

                                        &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\User Account Control UAC Policies\GptTmpl.inf"

                                        # Apply the Hide the entry points for Fast User Switching policy
                                        :FastUserSwitchingLabel switch ($UAC_NoFastSwitching ? 'Yes' : 'No') {
                                            'Yes' {
                                                Write-Verbose -Message 'Applying the Hide the entry points for Fast User Switching policy'
                                                &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\User Account Control UAC Policies\Hides the entry points for Fast User Switching\registry.pol"
                                            } 'No' { break FastUserSwitchingLabel }
                                        }

                                        # Apply the Only elevate executables that are signed and validated policy
                                        :ElevateSignedExeLabel switch ($UAC_OnlyElevateSigned ? 'Yes' : 'No') {
                                            'Yes' {
                                                Write-Verbose -Message 'Applying the Only elevate executables that are signed and validated policy'
                                                &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\User Account Control UAC Policies\Only elevate executables that are signed and validated\GptTmpl.inf"
                                            } 'No' { break ElevateSignedExeLabel }
                                        }
                                    }
                                    Function Invoke-WindowsFirewall {
                                        Write-Verbose -Message '========================='
                                        Write-Verbose -Message 'Processing the Windows Firewall category function'
                                        Write-Verbose -Message 'Running the Windows Firewall category'

                                        &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Windows Firewall Policies\registry.pol"

                                        Write-Verbose -Message 'Disabling Multicast DNS (mDNS) UDP-in Firewall Rules for all 3 Firewall profiles - disables only 3 rules'
                                        Get-NetFirewallRule |
                                        Where-Object -FilterScript { ($_.RuleGroup -eq '@%SystemRoot%\system32\firewallapi.dll,-37302') -and ($_.Direction -eq 'inbound') } |
                                        ForEach-Object -Process { Disable-NetFirewallRule -DisplayName $_.DisplayName }
                                    }
                                    Function Invoke-OptionalWindowsFeatures {
                                        Write-Verbose -Message '========================='
                                        Write-Verbose -Message 'Processing the Optional Windows Features category function'
                                        Write-Verbose -Message 'Running the Optional Windows Features category'

                                        # PowerShell Core (only if installed from Microsoft Store) has problem with these commands: https://github.com/PowerShell/PowerShell/issues/13866#issuecomment-1519066710
                                        if ($PSHome -like "*$env:SystemDrive\Program Files\WindowsApps\Microsoft.PowerShell*") {
                                            Write-Verbose -Message 'Importing DISM module to be able to run DISM commands in PowerShell Core installed from MSFT Store'
                                            Import-Module -Name 'DISM' -UseWindowsPowerShell -Force -WarningAction SilentlyContinue
                                        }

                                        Edit-Addons -Type Feature -FeatureAction Disabling -FeatureName 'MicrosoftWindowsPowerShellV2'
                                        Edit-Addons -Type Feature -FeatureAction Disabling -FeatureName 'MicrosoftWindowsPowerShellV2Root'
                                        Edit-Addons -Type Feature -FeatureAction Disabling -FeatureName 'WorkFolders-Client'
                                        Edit-Addons -Type Feature -FeatureAction Disabling -FeatureName 'Printing-Foundation-Features'
                                        Edit-Addons -Type Feature -FeatureAction Disabling -FeatureName 'Windows-Defender-ApplicationGuard'
                                        Edit-Addons -Type Feature -FeatureAction Enabling -FeatureName 'Containers-DisposableClientVM'
                                        Edit-Addons -Type Feature -FeatureAction Enabling -FeatureName 'Microsoft-Hyper-V'
                                        Edit-Addons -Type Capability -CapabilityName 'Media.WindowsMediaPlayer'
                                        Edit-Addons -Type Capability -CapabilityName 'Browser.InternetExplorer'
                                        Edit-Addons -Type Capability -CapabilityName 'wmic'
                                        Edit-Addons -Type Capability -CapabilityName 'Microsoft.Windows.Notepad.System'
                                        Edit-Addons -Type Capability -CapabilityName 'Microsoft.Windows.WordPad'
                                        Edit-Addons -Type Capability -CapabilityName 'Microsoft.Windows.PowerShell.ISE'
                                        Edit-Addons -Type Capability -CapabilityName 'App.StepsRecorder'

                                        # Uninstall VBScript that is now uninstallable as an optional features since Windows 11 insider Dev build 25309 - Won't do anything in other builds
                                        if (Get-WindowsCapability -Online | Where-Object -FilterScript { $_.Name -like '*VBSCRIPT*' }) {
                                            try {
                                                Write-Output -InputObject "`nUninstalling VBSCRIPT"
                                                Get-WindowsCapability -Online | Where-Object -FilterScript { $_.Name -like '*VBSCRIPT*' } | Remove-WindowsCapability -Online
                                                # Shows the successful message only if removal process was successful
                                                Write-Output -InputObject 'VBSCRIPT has been uninstalled'
                                            }
                                            catch {
                                                # show errors in non-terminating way
                                                $_
                                            }
                                        }
                                    }
                                    Function Invoke-WindowsNetworking {
                                        Write-Verbose -Message '========================='
                                        Write-Verbose -Message 'Processing the Windows Networking category function'
                                        Write-Verbose -Message 'Running the Windows Networking category'

                                        &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Windows Networking Policies\registry.pol"
                                        &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\Windows Networking Policies\GptTmpl.inf"

                                        Write-Verbose -Message 'Disabling LMHOSTS lookup protocol on all network adapters'
                                        Edit-Registry -path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -key 'EnableLMHOSTS' -value '0' -type 'DWORD' -Action 'AddOrModify'

                                        Write-Verbose -Message 'Setting the Network Location of all connections to Public'
                                        Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Public
                                    }
                                    Function Invoke-MiscellaneousConfigurations {
                                        Write-Verbose -Message '========================='
                                        Write-Verbose -Message 'Processing the Miscellaneous Configurations category function'
                                        Write-Verbose -Message 'Running the Miscellaneous Configurations category'

                                        Write-Verbose -Message 'Applying the Miscellaneous Configurations registry settings'
                                        foreach ($Item in $RegistryCSVItems) {
                                            if ($Item.category -eq 'Miscellaneous') {
                                                Edit-Registry -path $Item.Path -key $Item.Key -value $Item.Value -type $Item.Type -Action $Item.Action
                                            }
                                        }

                                        &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Miscellaneous Policies\registry.pol"
                                        &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\Miscellaneous Policies\GptTmpl.inf"

                                        Write-Verbose -Message 'Adding all Windows users to the "Hyper-V Administrators" security group to be able to use Hyper-V and Windows Sandbox'
                                        # Ignoring the errors that occur when the user is already a member of the group - SilentlyContinue would show the error message at the end of the RunSpace because of Try-Catch handling, which we don't need
                                        Get-LocalUser | Where-Object -FilterScript { $_.enabled -eq 'True' } | ForEach-Object -Process { Add-LocalGroupMember -SID 'S-1-5-32-578' -Member "$($_.SID)" -ErrorAction Ignore }

                                        # Makes sure auditing for the "Other Logon/Logoff Events" subcategory under the Logon/Logoff category is enabled, doesn't touch affect any other sub-category
                                        # For tracking Lock screen unlocks and locks
                                        # auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
                                        # Using GUID
                                        Write-Verbose -Message 'Enabling auditing for the "Other Logon/Logoff Events" subcategory under the Logon/Logoff category'
                                        auditpol /set /subcategory:"{0CCE921C-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null

                                        # Query all Audits status
                                        # auditpol /get /category:*
                                        # Get the list of SubCategories and their associated GUIDs
                                        # auditpol /list /subcategory:* /r

                                        # Event Viewer custom views are saved in "$env:SystemDrive\ProgramData\Microsoft\Event Viewer\Views". files in there can be backed up and restored on new Windows installations.
                                        if (Test-Path -Path "$env:SystemDrive\ProgramData\Microsoft\Event Viewer\Views\Hardening Script") {
                                            Remove-Item -Path "$env:SystemDrive\ProgramData\Microsoft\Event Viewer\Views\Hardening Script" -Recurse -Force
                                        }

                                        Write-Verbose -Message 'Creating new sub-folder automatically and importing the custom views of the event viewer'
                                        Expand-Archive -Path "$WorkingDir\EventViewerCustomViews.zip" -DestinationPath "$env:SystemDrive\ProgramData\Microsoft\Event Viewer\Views\Hardening Script" -Force
                                    }
                                    Function Invoke-WindowsUpdateConfigurations {
                                        Write-Verbose -Message '========================='
                                        Write-Verbose -Message 'Processing the Windows Update category function'
                                        Write-Verbose -Message 'Running the Windows Update category'

                                        Write-Verbose -Message 'Enabling restart notification for Windows update'
                                        Edit-Registry -path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -key 'RestartNotificationsAllowed2' -value '1' -type 'DWORD' -Action 'AddOrModify'

                                        Write-Verbose -Message 'Applying the Windows Update Group Policies'
                                        &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Windows Update Policies\registry.pol"
                                    }
                                    Function Invoke-EdgeBrowserConfigurations {
                                        Write-Verbose -Message '========================='
                                        Write-Verbose -Message 'Processing the Edge Browser category function'
                                        Write-Verbose -Message 'Running the Edge Browser category'

                                        Write-Verbose -Message 'Applying the Edge Browser registry settings'
                                        foreach ($Item in $RegistryCSVItems) {
                                            if ($Item.category -eq 'Edge') {
                                                Edit-Registry -path $Item.Path -key $Item.Key -value $Item.Value -type $Item.Type -Action $Item.Action
                                            }
                                        }
                                    }
                                    Function Invoke-CertificateCheckingCommands {
                                        Write-Verbose -Message '========================='
                                        Write-Verbose -Message 'Processing the Certificate Checking category function'
                                        Write-Verbose -Message 'Running the Certificate Checking category'

                                        try {
                                            Write-Verbose -Message 'Downloading sigcheck64.exe from https://live.sysinternals.com'
                                            Invoke-WebRequest -Uri 'https://live.sysinternals.com/sigcheck64.exe' -OutFile 'sigcheck64.exe'
                                        }
                                        catch {
                                            Write-Error -Message 'sigcheck64.exe could not be downloaded from https://live.sysinternals.com' -ErrorAction Continue
                                            break CertCheckingLabel
                                        }
                                        Write-Host -NoNewline -Object "`nListing valid certificates not rooted to the Microsoft Certificate Trust List in the" -ForegroundColor Yellow; Write-Host -Object " Current User store`n" -ForegroundColor cyan
                                        .\sigcheck64.exe -tuv -accepteula -nobanner

                                        Write-Host -NoNewline -Object "`nListing valid certificates not rooted to the Microsoft Certificate Trust List in the" -ForegroundColor Yellow; Write-Host -Object " Local Machine Store`n" -ForegroundColor Blue
                                        .\sigcheck64.exe -tv -accepteula -nobanner

                                        # Remove the downloaded sigcheck64.exe after using it
                                        Remove-Item -Path .\sigcheck64.exe -Force
                                    }
                                    Function Invoke-CountryIPBlocking {
                                        Write-Verbose -Message '========================='
                                        Write-Verbose -Message 'Processing the Country IP Blocking category function'
                                        Write-Verbose -Message 'Running the Country IP Blocking category'

                                        Write-Verbose -Message 'Blocking IP ranges of countries in State Sponsors of Terrorism list'
                                        Block-CountryIP -IPList (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/StateSponsorsOfTerrorism.txt') -ListName 'State Sponsors of Terrorism' -GUI

                                        :IPBlockingOFACLabel switch ($CountryIPBlocking_OFAC ? 'Yes' : 'No') {
                                            'Yes' {
                                                Write-Verbose -Message 'Blocking IP ranges of countries in OFAC sanction list'
                                                Block-CountryIP -IPList (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/OFACSanctioned.txt') -ListName 'OFAC Sanctioned Countries' -GUI
                                            } 'No' { break IPBlockingOFACLabel }
                                        }
                                    }
                                    Function Invoke-DownloadsDefenseMeasures {
                                        Write-Verbose -Message '========================='
                                        Write-Verbose -Message 'Processing the Downloads Defense Measures category function'
                                        Write-Verbose -Message 'Running the Downloads Defense Measures category'

                                        if (-NOT (Get-Module -ListAvailable -Name 'WDACConfig' -Verbose:$false)) {
                                            Write-Verbose -Message 'Installing WDACConfig module because it is not installed'
                                            Install-Module -Name 'WDACConfig' -Force -Verbose:$false
                                        }

                                        Write-Verbose -Message 'Getting the currently deployed base policy names'
                                        [System.String[]]$CurrentBasePolicyNames = ((&"$env:SystemDrive\Windows\System32\CiTool.exe" -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { ($_.IsSystemPolicy -ne 'True') -and ($_.PolicyID -eq $_.BasePolicyID) }).FriendlyName

                                        # Only deploy the Downloads-Defense-Measures policy if it is not already deployed
                                        if ('Downloads-Defense-Measures' -notin $CurrentBasePolicyNames) {

                                            Write-Verbose -Message 'Detecting the Downloads folder path on system'
                                            [System.IO.FileInfo]$DownloadsPathSystem = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.path
                                            Write-Verbose -Message "The Downloads folder path on system is $DownloadsPathSystem"

                                            # Getting the current user's name
                                            [System.Security.Principal.SecurityIdentifier]$UserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().user.value
                                            [System.String]$UserName = (Get-LocalUser | Where-Object -FilterScript { $_.SID -eq $UserSID }).name

                                            # Checking if the Edge preferences file exists
                                            if (Test-Path -Path "$env:SystemDrive\Users\$UserName\AppData\Local\Microsoft\Edge\User Data\Default\Preferences") {

                                                Write-Verbose -Message 'Detecting the Downloads path in Edge'
                                                [PSCustomObject]$CurrentUserEdgePreference = ConvertFrom-Json -InputObject (Get-Content -Raw -Path "$env:SystemDrive\Users\$UserName\AppData\Local\Microsoft\Edge\User Data\Default\Preferences")
                                                [System.IO.FileInfo]$DownloadsPathEdge = $CurrentUserEdgePreference.savefile.default_directory

                                                # Ensure there is an Edge browser profile and it was initialized
                                                if ((-NOT [System.String]::IsNullOrWhitespace($DownloadsPathEdge.FullName))) {

                                                    Write-Verbose -Message "The Downloads path in Edge is $DownloadsPathEdge"

                                                    # Display a warning for now
                                                    if ($DownloadsPathEdge.FullName -ne $DownloadsPathSystem.FullName) {
                                                        Write-Warning -Message "The Downloads path in Edge ($($DownloadsPathEdge.FullName)) is different than the system's Downloads path ($($DownloadsPathSystem.FullName))"
                                                    }
                                                }
                                            }

                                            Write-Verbose -Message 'Creating and deploying the Downloads-Defense-Measures policy'
                                            New-DenyWDACConfig -PathWildCards -PolicyName 'Downloads-Defense-Measures' -FolderPath "$DownloadsPathSystem\*" -Deploy -Verbose:$Verbose -SkipVersionCheck -EmbeddedVerboseOutput
                                        }
                                        else {
                                            Write-Verbose -Message 'The Downloads-Defense-Measures policy is already deployed'
                                        }
                                    }
                                    Function Invoke-NonAdminCommands {
                                        Write-Verbose -Message '========================='
                                        Write-Verbose -Message 'Processing the Non-Admin category function'
                                        Write-Verbose -Message 'Running the Non-Admin category'
                                        Write-Verbose -Message 'Applying the Non-Admin registry settings'
                                        foreach ($Item in $RegistryCSVItems) {
                                            if ($Item.category -eq 'NonAdmin') {
                                                Edit-Registry -path $Item.Path -key $Item.Key -value $Item.Value -type $Item.Type -Action $Item.Action
                                            }
                                        }
                                    }
                                    #Endregion Hardening-Categories-Functions-GUI-Experience

                                    if ($null -ne $SelectedCategories) {

                                        :MainSwitchLabel switch ($SelectedCategories) {
                                            'MicrosoftSecurityBaselines' { Invoke-MicrosoftSecurityBaselines }
                                            'Microsoft365AppsSecurityBaselines' { Invoke-Microsoft365AppsSecurityBaselines }
                                            'MicrosoftDefender' { Invoke-MicrosoftDefender }
                                            'AttackSurfaceReductionRules' { Invoke-AttackSurfaceReductionRules }
                                            'BitLockerSettings' { Invoke-BitLockerSettings }
                                            'TLSSecurity' { Invoke-TLSSecurity }
                                            'LockScreen' { Invoke-LockScreen }
                                            'UserAccountControl' { Invoke-UserAccountControl }
                                            'WindowsFirewall' { Invoke-WindowsFirewall }
                                            'OptionalWindowsFeatures' { Invoke-OptionalWindowsFeatures }
                                            'WindowsNetworking' { Invoke-WindowsNetworking }
                                            'MiscellaneousConfigurations' { Invoke-MiscellaneousConfigurations }
                                            'WindowsUpdateConfigurations' { Invoke-WindowsUpdateConfigurations }
                                            'EdgeBrowserConfigurations' { Invoke-EdgeBrowserConfigurations }
                                            'CertificateCheckingCommands' { Invoke-CertificateCheckingCommands }
                                            'CountryIPBlocking' { Invoke-CountryIPBlocking }
                                            'DownloadsDefenseMeasures' { Invoke-DownloadsDefenseMeasures }
                                            'NonAdminCommands' { Invoke-NonAdminCommands }
                                            # This never runs because the $SelectedCategories is empty/null when no categories are selected
                                            default { 'No category was selected' }
                                        }

                                        # Display a toast notification when the selected categories have been run
                                        powershell.exe -Sta -Command {
                                            function Out-ToastNotification {
                                                <#
                                            .SYNOPSIS
                                                Displays a toast notification on the screen.
                                                It uses Windows PowerShell because the required types are not available to PowerShell Core
                                            .PARAMETER Title
                                                The title of the toast notification.
                                            .PARAMETER Body
                                                The body of the toast notification.
                                            .PARAMETER ImagePath
                                                The path to the image that will be displayed on the toast notification.
                                            #>
                                                Param (
                                                    [System.String]$Title,
                                                    [System.String]$Body,
                                                    [System.IO.FileInfo]$ImagePath
                                                )

                                                # Load the necessary Windows Runtime types for toast notifications
                                                [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null

                                                # Get the template content for the chosen template
                                                $Template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::('ToastImageAndText02'))

                                                # Convert the template to an XML document
                                                $XML = [System.Xml.XmlDocument]$Template.GetXml()

                                                # set the image source in the XML
                                                [System.Xml.XmlElement]$ImagePlaceHolder = $XML.toast.visual.binding.image
                                                $ImagePlaceHolder.SetAttribute('src', $ImagePath)

                                                # Set the title text in the XML
                                                [System.Xml.XmlElement]$TitlePlaceHolder = $XML.toast.visual.binding.text | Where-Object -FilterScript { $_.id -eq '1' }
                                                [System.Void]$TitlePlaceHolder.AppendChild($XML.CreateTextNode($Title))

                                                # Set the body text in the XML
                                                [System.Xml.XmlElement]$BodyPlaceHolder = $XML.toast.visual.binding.text | Where-Object -FilterScript { $_.id -eq '2' }
                                                [System.Void]$BodyPlaceHolder.AppendChild($XML.CreateTextNode($Body))

                                                # Load the XML content into a serializable XML document
                                                $SerializedXml = New-Object -TypeName 'Windows.Data.Xml.Dom.XmlDocument'
                                                $SerializedXml.LoadXml($XML.OuterXml)

                                                # Create a new toast notification with the serialized XML
                                                [Windows.UI.Notifications.ToastNotification]$Toast = [Windows.UI.Notifications.ToastNotification]::new($SerializedXml)

                                                # Set a tag and group for the notification (used for managing notifications)
                                                $Toast.Tag = 'Harden Windows Security'
                                                $Toast.Group = 'Harden Windows Security'

                                                # Set the notification to expire after 5 seconds
                                                $Toast.ExpirationTime = [DateTimeOffset]::Now.AddSeconds(5)

                                                # Create a toast notifier with a specific application ID
                                                $Notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Harden Windows Security')

                                                # Show the notification
                                                $Notifier.Show($Toast)
                                            }

                                            Out-ToastNotification -Title 'Completed' -body "$($args[0]) selected categories have been run." -ImagePath $args[1]
                                            # If the module is running locally, the toast notification image will be taken from the module directory, if not it will be taken from the working directory where it was already downloaded from the GitHub repo
                                        } -args $SelectedCategories.Count, ($IsLocally ? "$HardeningModulePath\Resources\Media\ToastNotificationIcon.png" : "$WorkingDir\ToastNotificationIcon.png") *>&1 # To display any error message or other streams from the script block on the console

                                        # Display the runspace count for debugging purposes
                                        # $SyncHash.ParentHost.UI.WriteDebugLine("Current RunSpace Count is: $((Get-Runspace).Count)")
                                    }
                                    else {
                                        Write-GUI -Text 'No category was selected'
                                    }
                                }

                                # Run the selected categories and output their results to the GUI
                                &$HardeningFunctionsScriptBlock *>&1 | ForEach-Object -Process {
                                    Write-GUI -Text $_ }

                                # $SyncHash.Window.Dispatcher.Invoke({
                                # Enable all UI elements once all of the commands have been executed
                                $AllControls = $SyncHash.window.FindName('ParentGrid').Children

                                foreach ($Control in $AllControls) {
                                    $Control.IsEnabled = $true
                                }
                                #   })
                            })

                        # Defining what happens when the GUI window is closed
                        $SyncHash.Window.add_Closed({
                                #    [System.Windows.MessageBox]::Show('The window is closing.')

                                if ($SyncHash.ShouldWriteLogs) {

                                    # Create and add the footer to the log file
                                    $SyncHash.Logger.Add(@"
**********************
Harden Windows Security operation log end
End time: $(Get-Date)
**********************
"@) | Out-Null

                                    Add-Content -Value $SyncHash.Logger -Path $SyncHash['GUI'].txtFilePath.Text -Force
                                }
                            })

                        # Inside the GUI RunSpace
                        $SyncHash.Window.add_Loaded({
                                $SyncHash.IsFullyLoaded = $true
                            })

                        # Show the GUI window
                        $SyncHash.Window.ShowDialog() | Out-Null
                        # Save any errors that occurred in the GUI RunSpace inside of the SyncHash object so we can access and display them later when the GUI is closed
                        $SyncHash.Error = $Error
                    })

                # It's not Async so don't need its handle saved in a variable
                [System.Void]$GUIPowerShell.Invoke()
            }
        }

        finally {
            if ($PSBoundParameters.GUI.IsPresent) {
                if ($SyncHash.Error) {
                    $SyncHash.Error | ForEach-Object -Process {
                        # Only show the terminating error message instead of those suppressed by -ErrorAction SilentlyContinue
                        if ($null -ne $_.Exception.InnerException) {
                            # a non-terminating error that isn't caught by the try-catch block and isn't even normally displayed
                            # Caused by some built-in ConfigCI cmdlet most likely, when using New-DenyWDACConfig cmdlet
                            # So skip this error and show any other errors
                            if ($_.Exception.Message -like '*Exception calling "GetVersionInfo" with "1" argument*') {
                                continue
                            }
                            Write-Host -Object $_.Exception.Message -ForegroundColor Red
                            Write-Host -Object $_.exception.CommandInvocation -ForegroundColor Red
                        }
                    }
                }

                $GUIPowerShell.Dispose()
                $GUIRunSpace.Close()
                $GUIRunSpace.Dispose()

                # If any new RunSpace was created during the GUI operation, they will be removed to free up memory
                # Additional RunSpaces are created automatically for remote proxying to Windows PowerShell because of the cmdlets that are not natively available in PowerShell Core such as Defender cmdlets
                $RunSpacesAfter = Get-Runspace

                # Determine the RunSpaces that were created during the operation
                $RunSpacesToClose = Compare-Object -ReferenceObject $RunSpacesBefore -DifferenceObject $RunSpacesAfter |
                Where-Object -FilterScript { $_.SideIndicator -eq '=>' } |
                Select-Object -ExpandProperty InputObject

                # Close and dispose of the RunSpaces that were created during the operation
                if ($RunSpacesToClose) {
                    $RunSpacesToClose | ForEach-Object -Process {
                        $_.Close()
                        $_.Dispose()
                    }
                }

                # Invoke the garbage collector
                [System.GC]::Collect()
                [System.GC]::WaitForPendingFinalizers()
            }
        }

        # Return from the Begin block if GUI was used and then closed
        if ($PSBoundParameters.GUI.IsPresent) { Return }
    }

    process {
        # doing a try-catch-finally block on the entire script so that when CTRL + C is pressed to forcefully exit the script,
        # or break is passed, clean up will still happen for secure exit. Any error that happens will be thrown
        try {

            # Return from the Process block if GUI was used and then closed, triggers the finally block to run for proper clean-up
            if ($PSBoundParameters.GUI.IsPresent) { Return }

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

            # Create a variable to store the current step number for the progress bar
            [System.Int64]$CurrentMainStep = 0
            # Create a reference variable that points to the original variable
            [ref]$RefCurrentMainStep = $CurrentMainStep

            Write-Progress -Id 0 -Activity 'Downloading the required files' -Status "Step $($RefCurrentMainStep.Value)/$TotalMainSteps" -PercentComplete 1
            # Change the title of the Windows Terminal for PowerShell tab
            $Host.UI.RawUI.WindowTitle = '⏬ Downloading'

            # Download the required files and assign the output to variables
            $FileDownloadOutput = Start-FileDownload -WorkingDir $WorkingDir -HardeningModulePath:$HardeningModulePath -Offline:$Offline -IsLocally:$IsLocally
            $MicrosoftSecurityBaselinePath = $FileDownloadOutput[0]
            $Microsoft365SecurityBaselinePath = $FileDownloadOutput[1]
            $RegistryCSVItems = $FileDownloadOutput[2]
            $LGPOExe = $FileDownloadOutput[3]

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
                    [Categoriex]::new().GetValidValues() | ForEach-Object -Process {
                        # Run all of the categories' functions if the user didn't specify any
                        . "Invoke-$_"
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

            if ($IsAdmin) {
                Write-Verbose -Message 'Reverting the PowerShell executables and powercfg.exe allow listings in Controlled folder access'
                foreach ($FilePath in (((Get-ChildItem -Path "$PSHOME\*.exe" -File).FullName) + "$env:SystemDrive\Windows\System32\powercfg.exe")) {
                    Remove-MpPreference -ControlledFolderAccessAllowedApplications $FilePath
                }

                # restoring the original Controlled folder access allow list - if user already had added PowerShell executables to the list
                # they will be restored as well, so user customization will remain intact
                if ($null -ne $CFAAllowedAppsBackup) {
                    Set-MpPreference -ControlledFolderAccessAllowedApplications $CFAAllowedAppsBackup
                }
            }

            if (Test-Path -Path $WorkingDir) {
                Write-Verbose -Message 'Removing the working directory'
                Remove-Item -Recurse -Path $WorkingDir -Force
            }

            Write-Verbose -Message 'Disabling progress bars'
            0..2 | ForEach-Object -Process { Write-Progress -Id $_ -Activity 'Done' -Completed }

            Write-Verbose -Message 'Restoring the title of the PowerShell back to what it was prior to running the script/module'
            $Host.UI.RawUI.WindowTitle = $CurrentPowerShellTitle

            Write-Verbose -Message 'Setting the execution policy back to what it was prior to running the script/module'
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

# bootDMAProtection check - checks for Kernel DMA Protection status in System information or msinfo32
[System.String]$BootDMAProtectionCheck = @'
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

        public static byte BootDmaCheck()
        {
            Int32 result;
            Int32 SystemInformationLength = 1;
            IntPtr SystemInformation = Marshal.AllocHGlobal(SystemInformationLength);
            Int32 ReturnLength;

            result = NativeMethods.NtQuerySystemInformation(
            NativeMethods.SYSTEM_DMA_GUARD_POLICY_INFORMATION.SystemDmaGuardPolicyInformation,
            SystemInformation,
            SystemInformationLength,
            out ReturnLength);

            if (result == 0)
            {
                byte info = Marshal.ReadByte(SystemInformation, 0);
                return info;
            }

            return 0;
        }
    }
}
'@

[System.Xml.XmlDocument]$Xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" x:Name="Window" WindowStartupLocation="CenterScreen" SizeToContent="WidthAndHeight" MinHeight="700" MinWidth="700" FontFamily="Trebuchet MS" FontSize="16" Background="#FFFFC0CB">
    <Window.Resources>
        <!--BEGIN global scrollbars styles-->
        <Style x:Key="ElderScrolls" TargetType="{x:Type Thumb}">
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate>
                        <Grid x:Name="Grid">
                            <Rectangle HorizontalAlignment="Stretch" VerticalAlignment="Stretch" Width="Auto" Height="Auto" Fill="Transparent"/>
                            <Border x:Name="RectangleX" CornerRadius="10 0 0 10" HorizontalAlignment="Stretch" VerticalAlignment="Stretch" Width="Auto" Height="Auto" Background="{TemplateBinding Background}"/>
                        </Grid>
                        <ControlTemplate.Triggers>
                            <Trigger Property="Tag" Value="Horizontal">
                                <Setter TargetName="RectangleX" Property="Width" Value="Auto"/>
                                <Setter TargetName="RectangleX" Property="Height" Value="7"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="{x:Type ScrollBar}" TargetType="{x:Type ScrollBar}">
            <Setter Property="Stylus.IsFlicksEnabled" Value="False"/>
            <Setter Property="Foreground" Value="#AAA81A99"/>
            <Setter Property="Background" Value="DarkGray"/>
            <Setter Property="Width" Value="10"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="{x:Type ScrollBar}">
                        <Grid x:Name="GridRoot" Width="12" Background="{x:Null}">
                            <Track x:Name="PART_Track" Grid.Row="0" IsDirectionReversed="true" Focusable="False">
                                <Track.Thumb>
                                    <Thumb x:Name="Thumb" Background="{TemplateBinding Foreground}" Style="{DynamicResource ElderScrolls}"/>
                                </Track.Thumb>
                                <Track.IncreaseRepeatButton>
                                    <RepeatButton x:Name="PageUp" Command="ScrollBar.PageDownCommand" Opacity="0" Focusable="False"/>
                                </Track.IncreaseRepeatButton>
                                <Track.DecreaseRepeatButton>
                                    <RepeatButton x:Name="PageDown" Command="ScrollBar.PageUpCommand" Opacity="0" Focusable="False"/>
                                </Track.DecreaseRepeatButton>
                            </Track>
                        </Grid>
                        <ControlTemplate.Triggers>
                            <Trigger SourceName="Thumb" Property="IsMouseOver" Value="true">
                                <Setter Value="{DynamicResource ButtonSelectBrush}" TargetName="Thumb" Property="Background"/>
                            </Trigger>
                            <Trigger SourceName="Thumb" Property="IsDragging" Value="true">
                                <Setter Value="{DynamicResource DarkBrush}" TargetName="Thumb" Property="Background"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="false">
                                <Setter TargetName="Thumb" Property="Visibility" Value="Collapsed"/>
                            </Trigger>
                            <Trigger Property="Orientation" Value="Horizontal">
                                <Setter TargetName="GridRoot" Property="LayoutTransform">
                                    <Setter.Value>
                                        <RotateTransform Angle="-90"/>
                                    </Setter.Value>
                                </Setter>
                                <Setter TargetName="PART_Track" Property="LayoutTransform">
                                    <Setter.Value>
                                        <RotateTransform Angle="-90"/>
                                    </Setter.Value>
                                </Setter>
                                <Setter Property="Width" Value="Auto"/>
                                <Setter Property="Height" Value="12"/>
                                <Setter TargetName="Thumb" Property="Tag" Value="Horizontal"/>
                                <Setter TargetName="PageDown" Property="Command" Value="ScrollBar.PageLeftCommand"/>
                                <Setter TargetName="PageUp" Property="Command" Value="ScrollBar.PageRightCommand"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <!--END global scrollbars styles-->
        <ControlTemplate x:Key="CustomCheckBoxTemplate" TargetType="{x:Type CheckBox}">
            <StackPanel Orientation="Horizontal" Margin="0,2.5,0,2.5">
                <!-- Grid to contain the ellipses -->
                <Grid Width="20" Height="20">
                    <!-- Outer Ellipse (Border) with pink stroke and white fill -->
                    <Ellipse x:Name="BorderEllipse" Stroke="#FFF485F0" StrokeThickness="1" Fill="White" Width="20" Height="20">
                        <Ellipse.Effect>
                            <DropShadowEffect ShadowDepth="0" Direction="0" Color="#FFF485F0" Opacity="1" BlurRadius="6" RenderingBias="Quality"/>
                        </Ellipse.Effect>
                    </Ellipse>
                    <!-- Inner Ellipse (Indicator) -->
                    <Ellipse x:Name="IndicatorEllipse" Fill="#FFA91BEF" Width="15" Height="15" Visibility="Collapsed"/>
                </Grid>
                <!-- ContentPresenter for the text -->
                <ContentPresenter Margin="5,0,0,0" VerticalAlignment="Center" HorizontalAlignment="Left">
                    <!-- Apply a style trigger for IsEnabled -->
                    <ContentPresenter.Style>
                        <Style TargetType="{x:Type ContentPresenter}">
                            <Style.Triggers>
                                <Trigger Property="IsEnabled" Value="False">
                                    <!-- Set the text color to gray when not enabled -->
                                    <Setter Property="TextElement.Foreground" Value="Gray"/>
                                    <!-- apply a blur effect to the text -->
                                    <Setter Property="Effect">
                                        <Setter.Value>
                                            <BlurEffect Radius="2"/>
                                        </Setter.Value>
                                    </Setter>
                                </Trigger>
                            </Style.Triggers>
                        </Style>
                    </ContentPresenter.Style>
                </ContentPresenter>
            </StackPanel>
            <ControlTemplate.Triggers>
                <Trigger Property="IsChecked" Value="true">
                    <!-- Show the inner ellipse when checked -->
                    <Setter TargetName="IndicatorEllipse" Property="Visibility" Value="Visible"/>
                </Trigger>
                <Trigger Property="IsChecked" Value="false">
                    <!-- Hide the inner ellipse when unchecked -->
                    <Setter TargetName="IndicatorEllipse" Property="Visibility" Value="Collapsed"/>
                </Trigger>
                <!-- New trigger for IsEnabled -->
                <Trigger Property="IsEnabled" Value="False">
                    <!-- Change the color of the BorderEllipse when not enabled -->
                    <Setter TargetName="BorderEllipse" Property="Fill" Value="Gray"/>
                    <!-- Hide the IndicatorEllipse when not enabled -->
                    <Setter TargetName="IndicatorEllipse" Property="Visibility" Value="Collapsed"/>
                </Trigger>
            </ControlTemplate.Triggers>
        </ControlTemplate>
        <!-- Global style for font color -->
        <SolidColorBrush x:Key="GlobalFontColor" Color="#000000"/>
        <!-- Base style for all controls -->
        <Style TargetType="{x:Type Control}" x:Key="BaseControlStyle">
            <Setter Property="Foreground" Value="{StaticResource GlobalFontColor}"/>
        </Style>
        <!-- Derived styles for specific controls -->
        <Style TargetType="{x:Type CheckBox}" BasedOn="{StaticResource BaseControlStyle}"/>
        <!-- Style for TabControl -->
        <!--

        <Style TargetType="TabItem"><Setter Property="FontSize" Value="16"/><Setter Property="FontWeight" Value="Bold"/><Setter Property="Padding" Value="20,20,20,0"/><Setter Property="Margin" Value="5,5,5,0"/><Setter Property="Height" Value="60"/><Setter Property="ToolTip" Value="{Binding Header, RelativeSource={RelativeSource Self}}"/><Setter Property="Foreground" Value="Black"/><Setter Property="Background" Value="Transparent"/><Setter Property="BorderBrush" Value="Transparent"/><Setter Property="BorderThickness" Value="0"/><Setter Property="Template"><Setter.Value><ControlTemplate TargetType="TabItem"><Border x:Name="Border" Background="Transparent" BorderBrush="Transparent" BorderThickness="0"><ContentPresenter x:Name="ContentSite" VerticalAlignment="Center" HorizontalAlignment="Center" ContentSource="Header" Margin="20" TextBlock.Foreground="Black"/></Border><ControlTemplate.Triggers><Trigger Property="IsSelected" Value="True"><Setter TargetName="Border" Property="Background"><Setter.Value><LinearGradientBrush StartPoint="0,0" EndPoint="1,0"><GradientStop Color="#78ffd6" Offset="0.0"/><GradientStop Color="#a8ff78" Offset="1.0"/></LinearGradientBrush></Setter.Value></Setter></Trigger><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Border" Property="Background"><Setter.Value><LinearGradientBrush StartPoint="0,0" EndPoint="1,0"><GradientStop Color="#a8ff78" Offset="0.0"/><GradientStop Color="#78ffd6" Offset="1.0"/></LinearGradientBrush></Setter.Value></Setter></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter></Style>
        -->
        <!-- Style for CheckBox with specific key-->
        <Style x:Key="CheckBoxStyle" TargetType="CheckBox">
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="Foreground" Value="Black"/>
        </Style>
        <!-- Style for Buttons with specific key-->
        <Style x:Key="GlobalButtons" TargetType="Button">
            <Setter Property="Background">
                <Setter.Value>
                    <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
                        <GradientStop Color="#AAFFA9" Offset="0.0"/>
                        <GradientStop Color="#AAFFA9" Offset="1.0"/>
                    </LinearGradientBrush>
                </Setter.Value>
            </Setter>
            <Setter Property="BorderBrush" Value="#FF003366"/>
            <Setter Property="BorderThickness" Value="0"/>
        </Style>
        <LinearGradientBrush x:Key="PinkGradient" EndPoint="0,1" StartPoint="0,0">
            <GradientStop Color="#ee9ca7" Offset="0"/>
            <GradientStop Color="#ffdde1" Offset="1"/>
        </LinearGradientBrush>
        <LinearGradientBrush x:Key="GradientBLK" EndPoint="0,1" StartPoint="1,1">
            <LinearGradientBrush.GradientStops>
                <GradientStop Color="#f953c6" Offset="0"/>
                <GradientStop Color="#b91d73" Offset="0.8"/>
            </LinearGradientBrush.GradientStops>
        </LinearGradientBrush>
    </Window.Resources>
    <!-- Grid for Online Mode Tab - Removing the white border with negative margins -->
    <Grid x:Name="ParentGrid" Margin="-2.3,-2.3,-2.3,-2.3">
        <!-- Row definitions for the grid -->
        <Grid.RowDefinitions>
            <!-- row 0 -->
            <RowDefinition Height="230"/>
            <!-- row 1 -->
            <RowDefinition Height="Auto"/>
            <!-- row 2 -->
            <RowDefinition Height="*"/>
            <!-- row 3 -->
            <RowDefinition Height="80"/>
        </Grid.RowDefinitions>
        <!-- Column definitions for the grid -->
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        <!-- Logging Area -->
        <ScrollViewer x:Name="ScrollerForOutputTextBlock" Grid.Row="0" Grid.ColumnSpan="2" HorizontalScrollBarVisibility="Disabled" VerticalScrollBarVisibility="Auto" Margin="10,15,10,10">
            <TextBox x:Name="OutputTextBlock" TextWrapping="Wrap" HorizontalAlignment="Stretch" VerticalAlignment="Stretch" Background="Transparent" BorderThickness="0" IsReadOnly="True" IsTabStop="False" Cursor="IBeam" MaxWidth="700" FontSize="14" FontWeight="Bold"/>
        </ScrollViewer>
        <!-- ToggleButton -->
        <ToggleButton x:Name="MainTabControlToggle" ToolTip="Enable logging" Foreground="White" Height="40" Width="170" FontSize="18" Grid.Row="1" Grid.ColumnSpan="2">
            <ToggleButton.Template>
                <ControlTemplate TargetType="ToggleButton">
                    <Border x:Name="Button1" Background="{StaticResource PinkGradient}" CornerRadius="20" Padding="1">
                        <Border x:Name="Button2" Background="{StaticResource GradientBLK}" Width="80" CornerRadius="20" HorizontalAlignment="Left">
                            <TextBlock x:Name="TextBlock1" Text="Online" HorizontalAlignment="Center" VerticalAlignment="Center" TextAlignment="Center"/>
                        </Border>
                    </Border>
                    <ControlTemplate.Triggers>
                        <Trigger Property="IsChecked" Value="True">
                            <Setter TargetName="Button2" Property="HorizontalAlignment" Value="Right"/>
                            <!-- The color can be changed to be different when the button is toggled vs when it's not -->
                            <Setter TargetName="Button1" Property="Background" Value="{StaticResource PinkGradient}"/>
                            <Setter TargetName="TextBlock1" Property="Text" Value="Offline"/>
                        </Trigger>
                    </ControlTemplate.Triggers>
                </ControlTemplate>
            </ToggleButton.Template>
        </ToggleButton>
        <!-- ContentControl to display content based on the ToggleButton's state -->
        <ContentControl Grid.Row="2" Grid.ColumnSpan="2" x:Name="MainContentControl">
            <ContentControl.Style>
                <Style TargetType="ContentControl" x:Name="MainContentControlStyle">
                    <Style.Triggers>
                        <DataTrigger Binding="{Binding ElementName=MainTabControlToggle, Path=IsChecked}" Value="False">
                            <Setter Property="Content">
                                <Setter.Value>
                                    <!-- Online Tab/Grid -->
                                    <Grid x:Name="Grid1" Margin="-2.3,-2.3,-2.3,-2.3">
                                        <!-- Row and Column definitions for the grid -->
                                        <Grid.RowDefinitions>
                                            <!-- This is for row 0 -->
                                            <RowDefinition Height="25"/>
                                            <!-- This is for row 1 -->
                                            <RowDefinition Height="4*" MaxHeight="215"/>
                                            <!-- This is for row 2 -->
                                            <RowDefinition Height="70"/>
                                            <!-- This is for row 3 -->
                                            <RowDefinition Height="30"/>
                                        </Grid.RowDefinitions>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="*"/>
                                            <ColumnDefinition Width="*"/>
                                        </Grid.ColumnDefinitions>
                                        <!-- Categories and Sub-Categories text blocks -->
                                        <TextBlock x:Name="TextBlockCategories" Grid.Row="0" Grid.Column="0" Grid.ColumnSpan="1" HorizontalAlignment="Center" VerticalAlignment="bottom" Text="Categories" Foreground="#FFFA00FF" FontSize="18">
                                            <TextBlock.Effect>
                                                <DropShadowEffect ShadowDepth="6" Direction="320" Color="#FFF485F0" Opacity="100" BlurRadius="10" RenderingBias="Quality"/>
                                            </TextBlock.Effect>
                                        </TextBlock>
                                        <TextBlock x:Name="TextBlockSubCategories" Grid.Row="0" Grid.Column="1" Grid.ColumnSpan="1" HorizontalAlignment="Center" VerticalAlignment="bottom" Text="Sub-Categories" Foreground="#FFFA00FF" FontSize="18">
                                            <TextBlock.Effect>
                                                <DropShadowEffect ShadowDepth="6" Direction="320" Color="#FFF485F0" Opacity="100" BlurRadius="10" RenderingBias="Quality"/>
                                            </TextBlock.Effect>
                                        </TextBlock>
                                        <Grid Name="InnerGrid1" Grid.Row="1" Grid.Column="0" Grid.ColumnSpan="1" Margin="10">
                                            <Grid.RowDefinitions>
                                                <RowDefinition Height="Auto"/>
                                                <RowDefinition Height="*"/>
                                            </Grid.RowDefinitions>
                                            <CheckBox Grid.Row="0" Grid.Column="0" Grid.ColumnSpan="1" Content="Select All" VerticalContentAlignment="Center" Margin="7,0,0,2" Padding="10,10,40,10" x:Name="SelectAllCategories" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                            <!-- ListViews for Categories -->
                                            <ListView x:Name="Categories" BorderThickness="0" ToolTip="Select the hardening categories to run" Grid.Row="1" Grid.Column="0" Grid.ColumnSpan="1">
                                                <!-- Background color for the ListView -->
                                                <ListView.Background>
                                                    <SolidColorBrush Color="transparent"/>
                                                </ListView.Background>
                                                <ListViewItem>
                                                    <CheckBox x:Name="MicrosoftSecurityBaselines" Content="Microsoft Security Baselines" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="Microsoft365AppsSecurityBaselines" Content="MSFT365 Apps Security Baselines" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="MicrosoftDefender" Content="Microsoft Defender" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="AttackSurfaceReductionRules" Content="Attack Surface Reduction Rules" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="BitLockerSettings" Content="BitLocker Settings" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="TLSSecurity" Content="TLS Security" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="LockScreen" Content="Lock Screen" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="UserAccountControl" Content="User Account Control" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="WindowsFirewall" Content="Windows Firewall" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="OptionalWindowsFeatures" Content="Optional Windows Features" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="WindowsNetworking" Content="Windows Networking" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="MiscellaneousConfigurations" Content="Miscellaneous Configurations" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="WindowsUpdateConfigurations" Content="Windows Update Configurations" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="EdgeBrowserConfigurations" Content="Edge Browser Configurations" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="CertificateCheckingCommands" Content="Certificate Checking Commands" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="CountryIPBlocking" Content="Country IP Blocking" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="DownloadsDefenseMeasures" Content="Downloads Defense Measures" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="NonAdminCommands" Content="Non-Admin Commands" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                            </ListView>
                                        </Grid>
                                        <Grid x:Name="InnerGrid2" Grid.Row="1" Grid.Column="1" Grid.ColumnSpan="1" Margin="10">
                                            <Grid.RowDefinitions>
                                                <RowDefinition Height="Auto"/>
                                                <RowDefinition Height="*"/>
                                            </Grid.RowDefinitions>
                                            <CheckBox Grid.Row="0" Grid.Column="0" Grid.ColumnSpan="1" Content="Select All" VerticalContentAlignment="Center" Margin="6,0,0,2" x:Name="SelectAllSubCategories" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                            <!-- ListViews for Sub-Categories -->
                                            <ListView x:Name="SubCategories" BorderThickness="0" ToolTip="Select sub-categories" Grid.Row="1" Grid.Column="0" Grid.ColumnSpan="1">
                                                <ListView.Background>
                                                    <SolidColorBrush Color="transparent"/>
                                                </ListView.Background>
                                                <ListViewItem>
                                                    <CheckBox x:Name="SecBaselines_NoOverrides" Content="Security Baselines No Overrides" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="MSFTDefender_SAC" Content="Smart App Control" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="MSFTDefender_NoDiagData" Content="Defender: No Diagnostics Data" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="MSFTDefender_NoScheduledTask" Content="Defender: No Scheduled Task" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="MSFTDefender_BetaChannels" Content="Defender: Use Beta Update Channels" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="LockScreen_CtrlAltDel" Content="Require CTRL + Alt + Del" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="LockScreen_NoLastSignedIn" Content="No Last Signed-In" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="UAC_NoFastSwitching" Content="No Fast User Switching" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="UAC_OnlyElevateSigned" Content="Only Elevated Signed" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                                <ListViewItem>
                                                    <CheckBox x:Name="CountryIPBlocking_OFAC" Content="Block OFAC Sanctions Countries" VerticalContentAlignment="Center" Padding="10,10,40,10" Template="{StaticResource CustomCheckBoxTemplate}"/>
                                                </ListViewItem>
                                            </ListView>
                                        </Grid>
                                        <!-- Enable Logging CheckBox -->
                                        <Viewbox x:Name="LoggingViewBox" Grid.Row="2" Grid.Column="0" Grid.ColumnSpan="1" HorizontalAlignment="Center" VerticalAlignment="Center" Margin="14">
                                            <ToggleButton x:Name="Log" ToolTip="Enable logging" Foreground="White" Height="40" Width="170" FontSize="16">
                                                <ToggleButton.Template>
                                                    <ControlTemplate TargetType="ToggleButton">
                                                        <Border x:Name="Button11" Background="LightGray" CornerRadius="10" Padding="3">
                                                            <Border x:Name="Button22" Background="Black" Width="100" CornerRadius="10" HorizontalAlignment="Left">
                                                                <TextBlock x:Name="TextBlock11" Text="Logging Off" HorizontalAlignment="Center" VerticalAlignment="Center" TextAlignment="Center"/>
                                                            </Border>
                                                        </Border>
                                                        <ControlTemplate.Triggers>
                                                            <Trigger Property="IsChecked" Value="True">
                                                                <Setter TargetName="Button22" Property="HorizontalAlignment" Value="Right"/>
                                                                <Setter TargetName="Button11" Property="Background" Value="#FFF485F0"/>
                                                                <Setter TargetName="TextBlock11" Property="Text" Value="Logging On"/>
                                                            </Trigger>
                                                        </ControlTemplate.Triggers>
                                                    </ControlTemplate>
                                                </ToggleButton.Template>
                                            </ToggleButton>
                                        </Viewbox>
                                        <!-- Log Path TextBox -->
                                        <Button x:Name="LogPath" Grid.Row="2" Grid.Column="1" Width="150" Height="40" FontSize="16" FontWeight="Bold" Background="{StaticResource PinkGradient}" ToolTip="The path to save the log file to">
                                            <Button.Template>
                                                <ControlTemplate TargetType="Button">
                                                    <Border x:Name="border" BorderThickness="3" Width="{TemplateBinding Width}" Height="{TemplateBinding Height}" Background="{TemplateBinding Background}" CornerRadius="6" BorderBrush="MediumPurple">
                                                        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                                                    </Border>
                                                    <ControlTemplate.Triggers>
                                                        <Trigger Property="IsMouseOver" Value="true">
                                                            <Trigger.EnterActions>
                                                                <BeginStoryboard>
                                                                    <Storyboard>
                                                                        <DoubleAnimation To="160" Storyboard.TargetProperty="Width" Duration="0:0:0.3"/>
                                                                        <DoubleAnimation To="45" Storyboard.TargetProperty="Height" Duration="0:0:0.3"/>
                                                                        <ColorAnimation To="Coral" Storyboard.TargetProperty="Background.(SolidColorBrush.Color)" Duration="0:0:0.3"/>
                                                                    </Storyboard>
                                                                </BeginStoryboard>
                                                            </Trigger.EnterActions>
                                                            <Trigger.ExitActions>
                                                                <BeginStoryboard>
                                                                    <Storyboard>
                                                                        <DoubleAnimation To="150" Storyboard.TargetProperty="Width" Duration="0:0:0.3"/>
                                                                        <DoubleAnimation To="40" Storyboard.TargetProperty="Height" Duration="0:0:0.3"/>
                                                                        <ColorAnimation To="White" Storyboard.TargetProperty="Background.(SolidColorBrush.Color)" Duration="0:0:0.3"/>
                                                                    </Storyboard>
                                                                </BeginStoryboard>
                                                            </Trigger.ExitActions>
                                                        </Trigger>
                                                        <Trigger Property="IsPressed" Value="true">
                                                            <Setter TargetName="border" Property="Background">
                                                                <Setter.Value>
                                                                    <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
                                                                        <GradientStop Color="#eaafc8" Offset="0.0"/>
                                                                        <GradientStop Color="#e1eec3" Offset="1.0"/>
                                                                    </LinearGradientBrush>
                                                                </Setter.Value>
                                                            </Setter>
                                                        </Trigger>
                                                    </ControlTemplate.Triggers>
                                                </ControlTemplate>
                                            </Button.Template>
                                            <StackPanel Orientation="Horizontal">
                                                <Image x:Name="LogButtonIcon" Width="40" Height="30"/>
                                                <TextBlock Text="Log Path" VerticalAlignment="Center"/>
                                            </StackPanel>
                                        </Button>
                                        <!-- File Path TextBox which is dynamic-->
                                        <TextBox x:Name="txtFilePath" Grid.Row="3" Grid.ColumnSpan="2" HorizontalAlignment="Stretch" VerticalAlignment="Stretch" Margin="30,0,30,0" BorderThickness="0" ToolTip="The selected log file path" MaxWidth="700">
                                            <TextBox.Style>
                                                <Style TargetType="{x:Type TextBox}">
                                                    <Setter Property="VerticalContentAlignment" Value="Center"/>
                                                    <Setter Property="Template">
                                                        <Setter.Value>
                                                            <ControlTemplate TargetType="{x:Type TextBox}">
                                                                <Border CornerRadius="10" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}">
                                                                    <ScrollViewer x:Name="PART_ContentHost" Margin="0"/>
                                                                </Border>
                                                            </ControlTemplate>
                                                        </Setter.Value>
                                                    </Setter>
                                                    <Setter Property="Effect">
                                                        <Setter.Value>
                                                            <DropShadowEffect ShadowDepth="0" Direction="0" Color="#FFF485F0" Opacity="1" BlurRadius="10" RenderingBias="Quality"/>
                                                        </Setter.Value>
                                                    </Setter>
                                                </Style>
                                            </TextBox.Style>
                                        </TextBox>
                                    </Grid>
                                </Setter.Value>
                            </Setter>
                        </DataTrigger>
                        <DataTrigger Binding="{Binding ElementName=MainTabControlToggle, Path=IsChecked}" Value="True">
                            <Setter Property="Content">
                                <Setter.Value>
                                    <!-- Offline Tab/Grid -->
                                    <Grid x:Name="Grid2" Margin="-2.3,-2.3,-2.3,-2.3">
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="*"/>
                                            <!-- Button column -->
                                            <ColumnDefinition Width="*"/>
                                            <!-- Text area column -->
                                        </Grid.ColumnDefinitions>
                                        <Grid.RowDefinitions>
                                            <!-- This is for row 0 -->
                                            <RowDefinition Height="60"/>
                                            <!-- This is for row 1 -->
                                            <RowDefinition Height="60"/>
                                            <!-- This is for row 2 -->
                                            <RowDefinition Height="60"/>
                                            <!-- This is for row 3 -->
                                            <RowDefinition Height="60"/>
                                        </Grid.RowDefinitions>
                                        <!-- Row 0 -->
                                        <!-- Enable Offline Mode CheckBox -->
                                        <Viewbox Grid.Row="0" Grid.ColumnSpan="2" HorizontalAlignment="Stretch" VerticalAlignment="Stretch" Margin="0,20,0,0">
                                            <ToggleButton x:Name="EnableOfflineMode" ToolTip="Enables Offline Mode and will use the selected files instead of downloading them from the Microsoft servers" Foreground="White" Height="40" Width="170" FontSize="16">
                                                <ToggleButton.Template>
                                                    <ControlTemplate TargetType="ToggleButton">
                                                        <Border x:Name="Button111" Background="LightGray" CornerRadius="10" Padding="3">
                                                            <Border x:Name="Button222" Background="Black" Width="100" CornerRadius="10" HorizontalAlignment="Left">
                                                                <TextBlock x:Name="TextBlock111" Text="Disabled" HorizontalAlignment="Center" VerticalAlignment="Center" TextAlignment="Center"/>
                                                            </Border>
                                                        </Border>
                                                        <ControlTemplate.Triggers>
                                                            <Trigger Property="IsChecked" Value="True">
                                                                <Setter TargetName="Button222" Property="HorizontalAlignment" Value="Right"/>
                                                                <Setter TargetName="Button111" Property="Background" Value="#04C8F9"/>
                                                                <Setter TargetName="TextBlock111" Property="Text" Value="Enabled"/>
                                                            </Trigger>
                                                        </ControlTemplate.Triggers>
                                                    </ControlTemplate>
                                                </ToggleButton.Template>
                                            </ToggleButton>
                                        </Viewbox>
                                        <!-- Row 1 -->
                                        <StackPanel Orientation="Horizontal" Grid.Row="1" Grid.ColumnSpan="2" HorizontalAlignment="Center" Margin="30,0,30,0">
                                            <!-- LGPO Button -->
                                            <Button x:Name="LGPOZipButton" Width="100" Height="40" FontSize="15" FontWeight="Bold" Background="{StaticResource PinkGradient}" Margin="0,0,0,0" ToolTip="Browse for the path to LGPO zip file">
                                                <Button.Template>
                                                    <ControlTemplate TargetType="Button">
                                                        <Border x:Name="border" BorderThickness="3" Width="{TemplateBinding Width}" Height="{TemplateBinding Height}" Background="{TemplateBinding Background}" CornerRadius="6" BorderBrush="MediumPurple">
                                                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                                                        </Border>
                                                        <ControlTemplate.Triggers>
                                                            <Trigger Property="IsMouseOver" Value="true">
                                                                <Trigger.EnterActions>
                                                                    <BeginStoryboard>
                                                                        <Storyboard>
                                                                            <DoubleAnimation To="115" Storyboard.TargetProperty="Width" Duration="0:0:0.3"/>
                                                                            <DoubleAnimation To="45" Storyboard.TargetProperty="Height" Duration="0:0:0.3"/>
                                                                            <ColorAnimation To="Coral" Storyboard.TargetProperty="Background.(SolidColorBrush.Color)" Duration="0:0:0.3"/>
                                                                        </Storyboard>
                                                                    </BeginStoryboard>
                                                                </Trigger.EnterActions>
                                                                <Trigger.ExitActions>
                                                                    <BeginStoryboard>
                                                                        <Storyboard>
                                                                            <DoubleAnimation To="100" Storyboard.TargetProperty="Width" Duration="0:0:0.3"/>
                                                                            <DoubleAnimation To="40" Storyboard.TargetProperty="Height" Duration="0:0:0.3"/>
                                                                            <ColorAnimation To="White" Storyboard.TargetProperty="Background.(SolidColorBrush.Color)" Duration="0:0:0.3"/>
                                                                        </Storyboard>
                                                                    </BeginStoryboard>
                                                                </Trigger.ExitActions>
                                                            </Trigger>
                                                            <Trigger Property="IsPressed" Value="true">
                                                                <Setter TargetName="border" Property="Background">
                                                                    <Setter.Value>
                                                                        <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
                                                                            <GradientStop Color="#eaafc8" Offset="0.0"/>
                                                                            <GradientStop Color="#e1eec3" Offset="1.0"/>
                                                                        </LinearGradientBrush>
                                                                    </Setter.Value>
                                                                </Setter>
                                                            </Trigger>
                                                        </ControlTemplate.Triggers>
                                                    </ControlTemplate>
                                                </Button.Template>
                                                <StackPanel Orientation="Horizontal">
                                                    <Image x:Name="PathIcon3" Width="40" Height="30"/>
                                                    <TextBlock Text="LGPO" VerticalAlignment="Center"/>
                                                </StackPanel>
                                            </Button>
                                            <!-- LGPO Path Text box -->
                                            <TextBox x:Name="LGPOZipTextBox" Height="40" Margin="20,0,0,0" ToolTip="Selected path for the LGPO zip file" MinWidth="210" MaxWidth="700">
                                                <TextBox.Style>
                                                    <Style TargetType="{x:Type TextBox}">
                                                        <Setter Property="VerticalContentAlignment" Value="Center"/>
                                                        <Setter Property="Foreground" Value="Black"/>
                                                        <Setter Property="Effect">
                                                            <Setter.Value>
                                                                <DropShadowEffect ShadowDepth="0" Direction="0" Color="#FFF485F0" Opacity="1" BlurRadius="10" RenderingBias="Quality"/>
                                                            </Setter.Value>
                                                        </Setter>
                                                        <Setter Property="Template">
                                                            <Setter.Value>
                                                                <ControlTemplate TargetType="{x:Type TextBox}">
                                                                    <Grid>
                                                                        <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}"/>
                                                                        <ScrollViewer x:Name="PART_ContentHost" Margin="5,0"/>
                                                                        <TextBlock x:Name="PART_Watermark" Text="Selected Path will be displayed here..." Foreground="Gray" IsHitTestVisible="False" Margin="5,0" VerticalAlignment="Center" Visibility="Collapsed"/>
                                                                    </Grid>
                                                                    <ControlTemplate.Triggers>
                                                                        <Trigger Property="Text" Value="">
                                                                            <Setter TargetName="PART_Watermark" Property="Visibility" Value="Visible"/>
                                                                        </Trigger>
                                                                        <Trigger Property="Text" Value="{x:Null}">
                                                                            <Setter TargetName="PART_Watermark" Property="Visibility" Value="Visible"/>
                                                                        </Trigger>
                                                                    </ControlTemplate.Triggers>
                                                                </ControlTemplate>
                                                            </Setter.Value>
                                                        </Setter>
                                                    </Style>
                                                </TextBox.Style>
                                            </TextBox>
                                        </StackPanel>
                                        <!-- Row 2 -->
                                        <StackPanel Orientation="Horizontal" Grid.Row="2" Grid.ColumnSpan="2" HorizontalAlignment="Center" Margin="30,0,30,0">
                                            <!-- Microsoft Security Baselines Button -->
                                            <Button x:Name="MicrosoftSecurityBaselineZipButton" Width="270" Height="40" FontSize="15" FontWeight="Bold" Background="{StaticResource PinkGradient}" Margin="0,0,0,0" ToolTip="Browse for the path to Microsoft Security Baseline zip file">
                                                <Button.Template>
                                                    <ControlTemplate TargetType="Button">
                                                        <Border x:Name="border" BorderThickness="3" Width="{TemplateBinding Width}" Height="{TemplateBinding Height}" Background="{TemplateBinding Background}" CornerRadius="6" BorderBrush="MediumPurple">
                                                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                                                        </Border>
                                                        <ControlTemplate.Triggers>
                                                            <Trigger Property="IsMouseOver" Value="true">
                                                                <Trigger.EnterActions>
                                                                    <BeginStoryboard>
                                                                        <Storyboard>
                                                                            <DoubleAnimation To="280" Storyboard.TargetProperty="Width" Duration="0:0:0.3"/>
                                                                            <DoubleAnimation To="45" Storyboard.TargetProperty="Height" Duration="0:0:0.3"/>
                                                                            <ColorAnimation To="Coral" Storyboard.TargetProperty="Background.(SolidColorBrush.Color)" Duration="0:0:0.3"/>
                                                                        </Storyboard>
                                                                    </BeginStoryboard>
                                                                </Trigger.EnterActions>
                                                                <Trigger.ExitActions>
                                                                    <BeginStoryboard>
                                                                        <Storyboard>
                                                                            <DoubleAnimation To="270" Storyboard.TargetProperty="Width" Duration="0:0:0.3"/>
                                                                            <DoubleAnimation To="40" Storyboard.TargetProperty="Height" Duration="0:0:0.3"/>
                                                                            <ColorAnimation To="White" Storyboard.TargetProperty="Background.(SolidColorBrush.Color)" Duration="0:0:0.3"/>
                                                                        </Storyboard>
                                                                    </BeginStoryboard>
                                                                </Trigger.ExitActions>
                                                            </Trigger>
                                                            <Trigger Property="IsPressed" Value="true">
                                                                <Setter TargetName="border" Property="Background">
                                                                    <Setter.Value>
                                                                        <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
                                                                            <GradientStop Color="#eaafc8" Offset="0.0"/>
                                                                            <GradientStop Color="#e1eec3" Offset="1.0"/>
                                                                        </LinearGradientBrush>
                                                                    </Setter.Value>
                                                                </Setter>
                                                            </Trigger>
                                                        </ControlTemplate.Triggers>
                                                    </ControlTemplate>
                                                </Button.Template>
                                                <StackPanel Orientation="Horizontal">
                                                    <Image x:Name="PathIcon1" Width="40" Height="30"/>
                                                    <TextBlock Text="Microsoft Security Baseline" VerticalAlignment="Center"/>
                                                </StackPanel>
                                            </Button>
                                            <!-- Microsoft Security Baselines Text block -->
                                            <TextBox x:Name="MicrosoftSecurityBaselineZipTextBox" Height="40" Margin="20,0,0,0" MinWidth="210" MaxWidth="700" ToolTip="Selected path for the Microsoft Security Baseline zip file" VerticalContentAlignment="Center">
                                                <TextBox.Style>
                                                    <Style TargetType="{x:Type TextBox}">
                                                        <Setter Property="Foreground" Value="Black"/>
                                                        <Setter Property="Effect">
                                                            <Setter.Value>
                                                                <DropShadowEffect ShadowDepth="0" Direction="0" Color="#FFF485F0" Opacity="1" BlurRadius="10" RenderingBias="Quality"/>
                                                            </Setter.Value>
                                                        </Setter>
                                                        <Setter Property="Template">
                                                            <Setter.Value>
                                                                <ControlTemplate TargetType="{x:Type TextBox}">
                                                                    <Grid>
                                                                        <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}"/>
                                                                        <!-- Adjust the ScrollViewer's VerticalAlignment to Center -->
                                                                        <ScrollViewer x:Name="PART_ContentHost" Margin="5,0" VerticalAlignment="Center"/>
                                                                        <TextBlock x:Name="PART_Watermark" Text="Selected Path will be displayed here..." Foreground="Gray" IsHitTestVisible="False" Margin="5,0" VerticalAlignment="Center" Visibility="Collapsed"/>
                                                                    </Grid>
                                                                    <ControlTemplate.Triggers>
                                                                        <Trigger Property="Text" Value="">
                                                                            <Setter TargetName="PART_Watermark" Property="Visibility" Value="Visible"/>
                                                                        </Trigger>
                                                                        <Trigger Property="Text" Value="{x:Null}">
                                                                            <Setter TargetName="PART_Watermark" Property="Visibility" Value="Visible"/>
                                                                        </Trigger>
                                                                    </ControlTemplate.Triggers>
                                                                </ControlTemplate>
                                                            </Setter.Value>
                                                        </Setter>
                                                    </Style>
                                                </TextBox.Style>
                                            </TextBox>
                                        </StackPanel>
                                        <!-- Row 3 -->
                                        <StackPanel Orientation="Horizontal" Grid.Row="3" Grid.ColumnSpan="2" HorizontalAlignment="Center" Margin="30,0,30,0">
                                            <!-- M365 apps security baselines button -->
                                            <Button x:Name="Microsoft365AppsSecurityBaselineZipButton" Width="320" Height="40" FontSize="15" FontWeight="Bold" Background="{StaticResource PinkGradient}" Margin="0,0,0,0" ToolTip="Browse for the path to Microsoft 365 Apps Security Baseline zip file">
                                                <Button.Template>
                                                    <ControlTemplate TargetType="Button">
                                                        <Border x:Name="border" BorderThickness="3" Width="{TemplateBinding Width}" Height="{TemplateBinding Height}" Background="{TemplateBinding Background}" CornerRadius="6" BorderBrush="MediumPurple">
                                                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                                                        </Border>
                                                        <ControlTemplate.Triggers>
                                                            <Trigger Property="IsMouseOver" Value="true">
                                                                <Trigger.EnterActions>
                                                                    <BeginStoryboard>
                                                                        <Storyboard>
                                                                            <DoubleAnimation To="345" Storyboard.TargetProperty="Width" Duration="0:0:0.3"/>
                                                                            <DoubleAnimation To="45" Storyboard.TargetProperty="Height" Duration="0:0:0.3"/>
                                                                            <ColorAnimation To="Coral" Storyboard.TargetProperty="Background.(SolidColorBrush.Color)" Duration="0:0:0.3"/>
                                                                        </Storyboard>
                                                                    </BeginStoryboard>
                                                                </Trigger.EnterActions>
                                                                <Trigger.ExitActions>
                                                                    <BeginStoryboard>
                                                                        <Storyboard>
                                                                            <DoubleAnimation To="320" Storyboard.TargetProperty="Width" Duration="0:0:0.3"/>
                                                                            <DoubleAnimation To="40" Storyboard.TargetProperty="Height" Duration="0:0:0.3"/>
                                                                            <ColorAnimation To="White" Storyboard.TargetProperty="Background.(SolidColorBrush.Color)" Duration="0:0:0.3"/>
                                                                        </Storyboard>
                                                                    </BeginStoryboard>
                                                                </Trigger.ExitActions>
                                                            </Trigger>
                                                            <Trigger Property="IsPressed" Value="true">
                                                                <Setter TargetName="border" Property="Background">
                                                                    <Setter.Value>
                                                                        <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
                                                                            <GradientStop Color="#eaafc8" Offset="0.0"/>
                                                                            <GradientStop Color="#e1eec3" Offset="1.0"/>
                                                                        </LinearGradientBrush>
                                                                    </Setter.Value>
                                                                </Setter>
                                                            </Trigger>
                                                        </ControlTemplate.Triggers>
                                                    </ControlTemplate>
                                                </Button.Template>
                                                <StackPanel Orientation="Horizontal">
                                                    <Image x:Name="PathIcon2" Width="40" Height="30"/>
                                                    <TextBlock Text="Microsoft 365 Apps Security Baseline" VerticalAlignment="Center"/>
                                                </StackPanel>
                                            </Button>
                                            <!-- M365 apps security baselines text block -->
                                            <TextBox x:Name="Microsoft365AppsSecurityBaselineZipTextBox" Height="40" Margin="20,0,0,0" MinWidth="210" MaxWidth="700" ToolTip="Selected path for the Microsoft 365 Apps Security Baseline zip file" VerticalContentAlignment="Center">
                                                <TextBox.Style>
                                                    <Style TargetType="{x:Type TextBox}">
                                                        <Setter Property="Foreground" Value="Black"/>
                                                        <Setter Property="Effect">
                                                            <Setter.Value>
                                                                <DropShadowEffect ShadowDepth="0" Direction="0" Color="#FFF485F0" Opacity="1" BlurRadius="10" RenderingBias="Quality"/>
                                                            </Setter.Value>
                                                        </Setter>
                                                        <Setter Property="Template">
                                                            <Setter.Value>
                                                                <ControlTemplate TargetType="{x:Type TextBox}">
                                                                    <Grid>
                                                                        <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}"/>
                                                                        <!-- Adjust the ScrollViewer's VerticalAlignment to Center -->
                                                                        <ScrollViewer x:Name="PART_ContentHost" Margin="5,0" VerticalAlignment="Center"/>
                                                                        <TextBlock x:Name="PART_Watermark" Text="Selected Path will be displayed here..." Foreground="Gray" IsHitTestVisible="False" Margin="5,0" VerticalAlignment="Center" Visibility="Collapsed"/>
                                                                    </Grid>
                                                                    <ControlTemplate.Triggers>
                                                                        <Trigger Property="Text" Value="">
                                                                            <Setter TargetName="PART_Watermark" Property="Visibility" Value="Visible"/>
                                                                        </Trigger>
                                                                        <Trigger Property="Text" Value="{x:Null}">
                                                                            <Setter TargetName="PART_Watermark" Property="Visibility" Value="Visible"/>
                                                                        </Trigger>
                                                                    </ControlTemplate.Triggers>
                                                                </ControlTemplate>
                                                            </Setter.Value>
                                                        </Setter>
                                                    </Style>
                                                </TextBox.Style>
                                            </TextBox>
                                        </StackPanel>
                                    </Grid>
                                </Setter.Value>
                            </Setter>
                        </DataTrigger>
                    </Style.Triggers>
                </Style>
            </ContentControl.Style>
        </ContentControl>
        <Button x:Name="Execute" Grid.Row="3" Grid.ColumnSpan="2" Width="120" Height="50" FontSize="16" FontWeight="Bold" Background="{StaticResource PinkGradient}">
            <Button.Template>
                <ControlTemplate TargetType="Button">
                    <Border x:Name="border" BorderThickness="3" Width="{TemplateBinding Width}" Height="{TemplateBinding Height}" Background="{TemplateBinding Background}" CornerRadius="6" BorderBrush="MediumPurple">
                        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <ControlTemplate.Triggers>
                        <Trigger Property="IsMouseOver" Value="true">
                            <Trigger.EnterActions>
                                <BeginStoryboard>
                                    <Storyboard>
                                        <DoubleAnimation To="140" Storyboard.TargetProperty="Width" Duration="0:0:0.3"/>
                                        <DoubleAnimation To="55" Storyboard.TargetProperty="Height" Duration="0:0:0.3"/>
                                        <ColorAnimation To="Coral" Storyboard.TargetProperty="Background.(SolidColorBrush.Color)" Duration="0:0:0.3"/>
                                    </Storyboard>
                                </BeginStoryboard>
                            </Trigger.EnterActions>
                            <Trigger.ExitActions>
                                <BeginStoryboard>
                                    <Storyboard>
                                        <DoubleAnimation To="120" Storyboard.TargetProperty="Width" Duration="0:0:0.3"/>
                                        <DoubleAnimation To="50" Storyboard.TargetProperty="Height" Duration="0:0:0.3"/>
                                        <ColorAnimation To="White" Storyboard.TargetProperty="Background.(SolidColorBrush.Color)" Duration="0:0:0.3"/>
                                    </Storyboard>
                                </BeginStoryboard>
                            </Trigger.ExitActions>
                        </Trigger>
                        <Trigger Property="IsPressed" Value="true">
                            <Setter TargetName="border" Property="Background">
                                <Setter.Value>
                                    <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
                                        <GradientStop Color="#eaafc8" Offset="0.0"/>
                                        <GradientStop Color="#e1eec3" Offset="1.0"/>
                                    </LinearGradientBrush>
                                </Setter.Value>
                            </Setter>
                        </Trigger>
                    </ControlTemplate.Triggers>
                </ControlTemplate>
            </Button.Template>
            <StackPanel Orientation="Horizontal">
                <Image x:Name="ExecuteButtonIcon" Width="40" Height="40"/>
                <TextBlock Text="Execute" VerticalAlignment="Center"/>
            </StackPanel>
        </Button>
    </Grid>
</Window>
'@
