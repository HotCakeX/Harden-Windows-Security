Function New-SupplementalWDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = 'Normal',
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    Param(
        # Main parameters for position 0
        [Alias('N')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')][System.Management.Automation.SwitchParameter]$Normal,
        [Alias('W')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Folder Path With WildCards')][System.Management.Automation.SwitchParameter]$PathWildCards,
        [Alias('P')]
        [parameter(mandatory = $false, ParameterSetName = 'Installed AppXPackages')][System.Management.Automation.SwitchParameter]$InstalledAppXPackages,

        [parameter(Mandatory = $true, ParameterSetName = 'Installed AppXPackages', ValueFromPipelineByPropertyName = $true)]
        [System.String]$PackageName,

        [ValidateScript({ Test-Path -Path $_ -PathType 'Container' }, ErrorMessage = 'The path you selected is not a folder path.')]
        [parameter(Mandatory = $true, ParameterSetName = 'Normal', ValueFromPipelineByPropertyName = $true)]
        [System.String]$ScanLocation,

        [ValidatePattern('\*', ErrorMessage = 'You did not supply a path that contains wildcard character (*) .')]
        [parameter(Mandatory = $true, ParameterSetName = 'Folder Path With WildCards', ValueFromPipelineByPropertyName = $true)]
        [System.String]$FolderPath,

        [ValidatePattern('^[a-zA-Z0-9 ]+$', ErrorMessage = 'The Supplemental Policy Name can only contain alphanumeric and space characters.')]
        [parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String]$SuppPolicyName,

        [ValidatePattern('\.xml$')]
        [ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' }, ErrorMessage = 'The path you selected is not a file path.')]
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [System.String]$PolicyPath,

        [parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$Deploy,

        [ValidateSet('OriginalFileName', 'InternalName', 'FileDescription', 'ProductName', 'PackageFamilyName', 'FilePath')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.String]$SpecificFileNameLevel,

        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.Management.Automation.SwitchParameter]$NoUserPEs,

        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.Management.Automation.SwitchParameter]$NoScript,

        [ValidateSet([Levelz])]
        [parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.String]$Level = 'FilePublisher',

        [ValidateSet([Fallbackz])]
        [parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.String[]]$Fallbacks = 'Hash',

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )

    begin {
        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null

        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Importing the required sub-modules
        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Update-self.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Write-ColorfulText.psm1" -Force

        # argument tab auto-completion and ValidateSet for Fallbacks
        Class Fallbackz : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $Fallbackz = ('Hash', 'FileName', 'SignedVersion', 'Publisher', 'FilePublisher', 'LeafCertificate', 'PcaCertificate', 'RootCertificate', 'WHQL', 'WHQLPublisher', 'WHQLFilePublisher', 'PFN', 'FilePath', 'None')
                return [System.String[]]$Fallbackz
            }
        }
        # argument tab auto-completion and ValidateSet for level
        Class Levelz : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $Levelz = ('Hash', 'FileName', 'SignedVersion', 'Publisher', 'FilePublisher', 'LeafCertificate', 'PcaCertificate', 'RootCertificate', 'WHQL', 'WHQLPublisher', 'WHQLFilePublisher', 'PFN', 'FilePath', 'None')
                return [System.String[]]$Levelz
            }
        }

        # if -SkipVersionCheck wasn't passed, run the updater
        # Redirecting the Update-Self function's information Stream to $null because Write-Host
        # Used by Write-ColorfulText outputs to both information stream and host console
        if (-NOT $SkipVersionCheck) { Update-self 6> $null }

        #region User-Configurations-Processing-Validation
        # If any of these parameters, that are mandatory for all of the position 0 parameters, isn't supplied by user
        if (!$PolicyPath) {
            # Read User configuration file if it exists
            $UserConfig = Get-Content -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json" -ErrorAction SilentlyContinue
            if ($UserConfig) {
                # Validate the Json file and read its content to make sure it's not corrupted
                try { $UserConfig = $UserConfig | ConvertFrom-Json }
                catch {
                    Write-Error -Message 'User Configuration Json file is corrupted, deleting it...' -ErrorAction Continue
                    # Calling this function with this parameter automatically does its job and breaks/stops the operation
                    Set-CommonWDACConfig -DeleteUserConfig
                }
            }
        }
        # If PolicyPaths has no values
        if (!$PolicyPath) {
            if ($UserConfig.UnsignedPolicyPath) {
                # validate each policyPath read from user config file
                if (Test-Path -Path $($UserConfig.UnsignedPolicyPath)) {
                    $PolicyPath = $UserConfig.UnsignedPolicyPath
                }
                else {
                    throw 'The currently saved value for UnsignedPolicyPath in user configurations is invalid.'
                }
            }
            else {
                throw 'PolicyPath parameter cannot be empty and no valid configuration was found for UnsignedPolicyPath.'
            }
        }
        #endregion User-Configurations-Processing-Validation

        # Ensure when user selects the -Deploy parameter, the base policy is not signed
        if ($Deploy) {
            $XmlTest = [System.Xml.XmlDocument](Get-Content -Path $PolicyPath)
            $RedFlag1 = $XmlTest.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
            $RedFlag2 = $XmlTest.SiPolicy.UpdatePolicySigners.UpdatePolicySigner.SignerId
            if ($RedFlag1 -or $RedFlag2) {
                Write-Error -Message 'You are using -Deploy parameter and the selected base policy is Signed. Please use Deploy-SignedWDACConfig to deploy it.'
            }
        }
    }

    process {

        if ($Normal) {

            # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
            [System.Collections.Hashtable]$PolicyMakerHashTable = @{
                FilePath               = "SupplementalPolicy $SuppPolicyName.xml"
                ScanPath               = $ScanLocation
                Level                  = $Level
                Fallback               = $Fallbacks
                MultiplePolicyFormat   = $true
                UserWriteablePaths     = $true
                AllowFileNameFallbacks = $true
            }
            # Assess user input parameters and add the required parameters to the hash table
            if ($SpecificFileNameLevel) { $PolicyMakerHashTable['SpecificFileNameLevel'] = $SpecificFileNameLevel }
            if ($NoScript) { $PolicyMakerHashTable['NoScript'] = $true }
            if (!$NoUserPEs) { $PolicyMakerHashTable['UserPEs'] = $true }

            Write-ColorfulText -Color HotPink -InputText "`nGenerating Supplemental policy with the following specifications:"
            $PolicyMakerHashTable
            Write-Host -Object "`n"
            # Create the supplemental policy via parameter splatting
            New-CIPolicy @PolicyMakerHashTable

            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath "SupplementalPolicy $SuppPolicyName.xml" -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath -PolicyName "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')"
            [System.String]$PolicyID = $PolicyID.Substring(11)
            Set-CIPolicyVersion -FilePath "SupplementalPolicy $SuppPolicyName.xml" -Version '1.0.0.0'
            # Make sure policy rule options that don't belong to a Supplemental policy don't exist
            @(0, 1, 2, 3, 4, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object -Process {
                Set-RuleOption -FilePath "SupplementalPolicy $SuppPolicyName.xml" -Option $_ -Delete }
            Set-HVCIOptions -Strict -FilePath "SupplementalPolicy $SuppPolicyName.xml"
            ConvertFrom-CIPolicy -XmlFilePath "SupplementalPolicy $SuppPolicyName.xml" -BinaryFilePath "$PolicyID.cip" | Out-Null

            Write-Output -InputObject "SupplementalPolicyFile = SupplementalPolicy $SuppPolicyName.xml"
            Write-Output -InputObject "SupplementalPolicyGUID = $PolicyID"

            if ($Deploy) {
                &'C:\Windows\System32\CiTool.exe' --update-policy "$PolicyID.cip" -json | Out-Null
                Write-ColorfulText -Color Pink -InputText "A Supplemental policy with the name $SuppPolicyName has been deployed."
                Remove-Item -Path "$PolicyID.cip" -Force
            }
        }

        if ($PathWildCards) {

            # Using Windows PowerShell to handle serialized data since PowerShell core throws an error
            # Creating the Supplemental policy file
            powershell.exe -Command {
                $RulesWildCards = New-CIPolicyRule -FilePathRule $args[0]
                New-CIPolicy -MultiplePolicyFormat -FilePath ".\SupplementalPolicy $($args[1]).xml" -Rules $RulesWildCards
            } -args $FolderPath, $SuppPolicyName

            # Giving the Supplemental policy the correct properties
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath ".\SupplementalPolicy $SuppPolicyName.xml" -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath -PolicyName "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')"
            [System.String]$PolicyID = $PolicyID.Substring(11)
            Set-CIPolicyVersion -FilePath ".\SupplementalPolicy $SuppPolicyName.xml" -Version '1.0.0.0'

            # Make sure policy rule options that don't belong to a Supplemental policy don't exist
            @(0, 1, 2, 3, 4, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object -Process {
                Set-RuleOption -FilePath ".\SupplementalPolicy $SuppPolicyName.xml" -Option $_ -Delete }

            # Adding policy rule option 18 Disabled:Runtime FilePath Rule Protection
            Set-RuleOption -FilePath ".\SupplementalPolicy $SuppPolicyName.xml" -Option 18

            Set-HVCIOptions -Strict -FilePath ".\SupplementalPolicy $SuppPolicyName.xml"
            ConvertFrom-CIPolicy -XmlFilePath ".\SupplementalPolicy $SuppPolicyName.xml" -BinaryFilePath "$PolicyID.cip" | Out-Null

            Write-Output -InputObject "SupplementalPolicyFile = SupplementalPolicy $SuppPolicyName.xml"
            Write-Output -InputObject "SupplementalPolicyGUID = $PolicyID"

            if ($Deploy) {
                &'C:\Windows\System32\CiTool.exe' --update-policy "$PolicyID.cip" -json | Out-Null
                Write-ColorfulText -Color Pink -InputText "A Supplemental policy with the name $SuppPolicyName has been deployed."
                Remove-Item -Path "$PolicyID.cip" -Force
            }
        }

        if ($InstalledAppXPackages) {
            do {
                Get-AppxPackage -Name $PackageName
                Write-Debug -Message "This is the Selected package name $PackageName"
                $Question = Read-Host -Prompt "`nIs this the intended results based on your Installed Appx packages? Enter 1 to continue, Enter 2 to exit"
            } until (
                (($Question -eq 1) -or ($Question -eq 2))
            )
            if ($Question -eq 2) { break }

            powershell.exe -Command {
                # Get all the packages based on the supplied name
                $Package = Get-AppxPackage -Name $args[0]
                # Get package dependencies if any
                $PackageDependencies = $Package.Dependencies

                # Create rules for each package
                foreach ($Item in $Package) {
                    $Rules += New-CIPolicyRule -Package $Item
                }

                # Create rules for each pacakge dependency, if any
                if ($PackageDependencies) {
                    foreach ($Item in $PackageDependencies) {
                        $Rules += New-CIPolicyRule -Package $Item
                    }
                }

                # Generate the supplemental policy xml file
                New-CIPolicy -MultiplePolicyFormat -FilePath ".\SupplementalPolicy $($args[1]).xml" -Rules $Rules
            } -args $PackageName, $SuppPolicyName


            # Giving the Supplemental policy the correct properties
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath ".\SupplementalPolicy $SuppPolicyName.xml" -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath -PolicyName "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')"
            [System.String]$PolicyID = $PolicyID.Substring(11)
            Set-CIPolicyVersion -FilePath ".\SupplementalPolicy $SuppPolicyName.xml" -Version '1.0.0.0'

            # Make sure policy rule options that don't belong to a Supplemental policy don't exist
            @(0, 1, 2, 3, 4, 9, 10, 11, 12, 15, 16, 17, 18, 19, 20) | ForEach-Object -Process {
                Set-RuleOption -FilePath ".\SupplementalPolicy $SuppPolicyName.xml" -Option $_ -Delete }

            Set-HVCIOptions -Strict -FilePath ".\SupplementalPolicy $SuppPolicyName.xml"
            ConvertFrom-CIPolicy -XmlFilePath ".\SupplementalPolicy $SuppPolicyName.xml" -BinaryFilePath "$PolicyID.cip" | Out-Null

            Write-Output -InputObject "SupplementalPolicyFile = SupplementalPolicy $SuppPolicyName.xml"
            Write-Output -InputObject "SupplementalPolicyGUID = $PolicyID"

            if ($Deploy) {
                &'C:\Windows\System32\CiTool.exe' --update-policy "$PolicyID.cip" -json | Out-Null
                Write-ColorfulText -Color Pink -InputText "A Supplemental policy with the name $SuppPolicyName has been deployed."
                Remove-Item -Path "$PolicyID.cip" -Force
            }
        }
    }

    <#
.SYNOPSIS
    Automate a lot of tasks related to WDAC (Windows Defender Application Control)
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-SupplementalWDACConfig
.DESCRIPTION
    Using official Microsoft methods, configure and use Windows Defender Application Control
.COMPONENT
    Windows Defender Application Control, ConfigCI PowerShell module
.FUNCTIONALITY
    Automate various tasks related to Windows Defender Application Control (WDAC)
.PARAMETER Normal
    Make a Supplemental policy by scanning a directory, you can optionally use other parameters too to fine tune the scan process
.PARAMETER PathWildCards
    Make a Supplemental policy by scanning a directory and creating a wildcard FilePath rules for all of the files inside that directory, recursively
.PARAMETER InstalledAppXPackages
    Make a Supplemental policy based on the Package Family Name of an installed Windows app (Appx)
.PARAMETER PackageName
    Enter the package name of an installed app. Supports wildcard * character. e.g., *Edge* or "*Microsoft*".
.PARAMETER ScanLocation
    The directory or drive that you want to scan for files that will be allowed to run by the Supplemental policy.
.PARAMETER FolderPath
    Path of a folder that you want to allow using wildcards *.
.PARAMETER SuppPolicyName
    Add a descriptive name for the Supplemental policy. Accepts only alphanumeric and space characters.
    It is used by the entire Cmdlet.
.PARAMETER PolicyPath
    Browse for the xml file of the Base policy this Supplemental policy is going to expand. Supports tab completion by showing only .xml files with Base Policy Type.
    It is used by the entire Cmdlet.
.PARAMETER Deploy
    Indicates that the module will automatically deploy the Supplemental policy after creation.
    It is used by the entire Cmdlet.
.PARAMETER SpecificFileNameLevel
    You can choose one of the following options: "OriginalFileName", "InternalName", "FileDescription", "ProductName", "PackageFamilyName", "FilePath"
.PARAMETER NoUserPEs
    By default the module includes user PEs in the scan, but when you use this switch parameter, they won't be included.
.PARAMETER NoScript
    Refer to this page for more info: https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-noscript
.PARAMETER Level
    The level that determines how the selected folder will be scanned.
    The default value for it is FilePublisher.
.PARAMETER Fallbacks
    The fallback level(s) that determine how the selected folder will be scanned.
    The default value for it is Hash.
.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases
.INPUTS
    System.String[]
    System.String
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
#>
}

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\Resources\ArgumentCompleters.ps1"
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'PolicyPath' -ScriptBlock $ArgumentCompleterPolicyPathsBasePoliciesOnly
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'PackageName' -ScriptBlock $ArgumentCompleterAppxPackageNames
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'ScanLocation' -ScriptBlock $ArgumentCompleterFolderPathsPicker
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'FolderPath' -ScriptBlock $ArgumentCompleterFolderPathsPickerWildCards
