Function New-SupplementalWDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = 'Folder Path With WildCards',
        PositionalBinding = $false,
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    Param(
        [Alias('W')][Parameter(Mandatory = $false, ParameterSetName = 'Folder Path With WildCards')][switch]$PathWildCards,
        [Alias('P')][parameter(mandatory = $false, ParameterSetName = 'Installed AppXPackages')][switch]$InstalledAppXPackages,
        [parameter(Mandatory = $true, ParameterSetName = 'Installed AppXPackages')][System.String]$PackageName,
        [ArgumentCompleter([WDACConfig.ArgCompleter.FolderPickerWithWildcard])]
        [ValidatePattern('\*', ErrorMessage = 'You did not supply a path that contains wildcard character (*) .')]
        [parameter(Mandatory = $true, ParameterSetName = 'Folder Path With WildCards', ValueFromPipelineByPropertyName = $true)]
        [System.IO.DirectoryInfo]$FolderPath,

        [ValidateCount(1, 232)]
        [ValidatePattern('^[a-zA-Z0-9 \-]+$', ErrorMessage = 'The policy name can only contain alphanumeric, space and dash (-) characters.')]
        [parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String]$SuppPolicyName,

        [ArgumentCompleter([WDACConfig.ArgCompleter.XmlFilePathsPicker])]
        [ValidateScript({ [WDACConfig.CiPolicyTest]::TestCiPolicy($_, $null) })]
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo]$PolicyPath,

        [parameter(Mandatory = $false)][switch]$Deploy,
        [Parameter(Mandatory = $false, ParameterSetName = 'Installed AppXPackages')][switch]$Force
    )
    Begin {
        [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)

        [System.IO.DirectoryInfo]$StagingArea = [WDACConfig.StagingArea]::NewStagingArea('New-SupplementalWDACConfig')

        #Region User-Configurations-Processing-Validation
        # If PolicyPath was not provided by user, check if a valid value exists in user configs, if so, use it, otherwise throw an error
        if (!$PolicyPath) {
            if ([System.IO.File]::Exists(([WDACConfig.UserConfiguration]::Get().UnsignedPolicyPath))) {
                $PolicyPath = [WDACConfig.UserConfiguration]::Get().UnsignedPolicyPath
            }
            else {
                throw 'PolicyPath parameter cannot be empty and no valid user configuration was found for UnsignedPolicyPath.'
            }
        }
        #Endregion User-Configurations-Processing-Validation

        # Ensure when user selects the -Deploy parameter, the base policy is not signed
        if ($Deploy) {
            if ([WDACConfig.PolicyFileSigningStatusDetection]::Check($PolicyPath) -eq [WDACConfig.PolicyFileSigningStatusDetection+SigningStatus]::Signed) {
                Throw 'You are using -Deploy parameter and the selected base policy is Signed. Please use Deploy-SignedWDACConfig to deploy it.'
            }
            # Send $true to set it as valid if no errors were thrown before
            $true
        }

        # Detecting if Confirm switch is used to bypass the confirmation prompts
        if ($Force -and -Not $Confirm) {
            $ConfirmPreference = 'None'
        }

        # Defining path for the final Supplemental policy XML and CIP files - used by the entire Cmdlet
        [System.IO.FileInfo]$FinalSupplementalPath = Join-Path -Path $StagingArea -ChildPath "SupplementalPolicy $SuppPolicyName.xml"
        [System.IO.FileInfo]$FinalSupplementalCIPPath = Join-Path -Path $StagingArea -ChildPath "SupplementalPolicy $SuppPolicyName.cip"

        # Flag indicating the final files should not be copied to the main user config directory
        [System.Boolean]$NoCopy = $false
    }

    process {

        try {
            if ($PSBoundParameters['PathWildCards']) {

                # The total number of the main steps for the progress bar to render
                $TotalSteps = $Deploy ? 2us : 1us
                $CurrentStep = 0us

                $CurrentStep++
                Write-Progress -Id 20 -Activity 'Creating the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Using Windows PowerShell to handle serialized data since PowerShell core throws an error
                [WDACConfig.Logger]::Write('Creating the Supplemental policy file')
                powershell.exe -NoProfile -Command {
                    $RulesWildCards = New-CIPolicyRule -FilePathRule $args[0]
                    New-CIPolicy -MultiplePolicyFormat -FilePath "$($args[2])\SupplementalPolicy $($args[1]).xml" -Rules $RulesWildCards
                } -args $FolderPath, $SuppPolicyName, $StagingArea

                [WDACConfig.Logger]::Write('Changing the policy type from base to Supplemental, assigning its name and resetting its policy ID')
                $null = [WDACConfig.SetCiPolicyInfo]::Set($FinalSupplementalPath, $true, "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')", $null, $PolicyPath)

                [WDACConfig.SetCiPolicyInfo]::Set($FinalSupplementalPath, ([version]'1.0.0.0'))

                [WDACConfig.CiRuleOptions]::Set($FinalSupplementalPath, [WDACConfig.CiRuleOptions+PolicyTemplate]::Supplemental, $null, $null, $null, $null, $null, $null, $null, $null, $null)

                [WDACConfig.Logger]::Write('Converting the Supplemental policy XML file to a CIP file')
                $null = ConvertFrom-CIPolicy -XmlFilePath $FinalSupplementalPath -BinaryFilePath $FinalSupplementalCIPPath

                if ($Deploy) {
                    $CurrentStep++
                    Write-Progress -Id 20 -Activity 'Deploying the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [WDACConfig.CiToolHelper]::UpdatePolicy($FinalSupplementalCIPPath)
                    Write-ColorfulTextWDACConfig -Color Pink -InputText "A Supplemental policy with the name '$SuppPolicyName' has been deployed."
                }
                Write-Progress -Id 20 -Activity 'Complete.' -Completed
            }
            if ($PSBoundParameters['InstalledAppXPackages']) {
                try {
                    # The total number of the main steps for the progress bar to render
                    $TotalSteps = $Deploy ? 3us : 2us
                    $CurrentStep = 0us

                    $CurrentStep++
                    Write-Progress -Id 21 -Activity 'Getting the Appx package' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    # Backing up PS Formatting Styles
                    [System.Collections.Hashtable]$OriginalStyle = @{}
                    $PSStyle.Formatting | Get-Member -MemberType Property | ForEach-Object -Process {
                        $OriginalStyle[$_.Name] = $PSStyle.Formatting.$($_.Name)
                    }

                    # Change the color for the list items to plum
                    $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(221,160,221))"

                    [WDACConfig.Logger]::Write('Displaying the installed Appx packages based on the supplied name')
                    Get-AppxPackage -Name $PackageName | Select-Object -Property Name, Publisher, version, PackageFamilyName, PackageFullName, InstallLocation, Dependencies, SignatureKind, Status

                    # Prompt for confirmation before proceeding
                    if ($PSCmdlet.ShouldProcess('', 'Select No to cancel and choose another name', 'Is this the intended results based on your Installed Appx packages?')) {

                        $CurrentStep++
                        Write-Progress -Id 21 -Activity 'Creating the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                        [WDACConfig.Logger]::Write('Creating a policy for the supplied Appx package name and its dependencies (if any)')
                        powershell.exe -NoProfile -Command {
                            # Get all the packages based on the supplied name
                            [Microsoft.Windows.Appx.PackageManager.Commands.AppxPackage[]]$Package = Get-AppxPackage -Name $args[0]

                            # Get package dependencies if any
                            $PackageDependencies = $Package.Dependencies

                            $Rules = @()

                            # Create rules for each package
                            foreach ($Item in $Package) {
                                $Rules += New-CIPolicyRule -Package $Item
                            }

                            # Create rules for each package dependency, if any
                            if ($PackageDependencies) {
                                foreach ($Item in $PackageDependencies) {
                                    $Rules += New-CIPolicyRule -Package $Item
                                }
                            }

                            # Generate the supplemental policy xml file
                            New-CIPolicy -MultiplePolicyFormat -FilePath "$($args[2])\SupplementalPolicy $($args[1]).xml" -Rules $Rules
                        } -args $PackageName, $SuppPolicyName, $StagingArea

                        [WDACConfig.Logger]::Write('Converting the policy type from base to Supplemental, assigning its name and resetting its policy ID')
                        $null = [WDACConfig.SetCiPolicyInfo]::Set($FinalSupplementalPath, $true, "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')", $null, $PolicyPath)

                        [WDACConfig.SetCiPolicyInfo]::Set($FinalSupplementalPath, ([version]'1.0.0.0'))

                        [WDACConfig.CiRuleOptions]::Set($FinalSupplementalPath, [WDACConfig.CiRuleOptions+PolicyTemplate]::Supplemental, $null, $null, $null, $null, $null, $null, $null, $null, $null)

                        [WDACConfig.Logger]::Write('Converting the Supplemental policy XML file to a CIP file')
                        $null = ConvertFrom-CIPolicy -XmlFilePath $FinalSupplementalPath -BinaryFilePath $FinalSupplementalCIPPath

                        if ($Deploy) {
                            $CurrentStep++
                            Write-Progress -Id 21 -Activity 'Deploying the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                            [WDACConfig.CiToolHelper]::UpdatePolicy($FinalSupplementalCIPPath)
                            Write-ColorfulTextWDACConfig -Color Pink -InputText "A Supplemental policy with the name '$SuppPolicyName' has been deployed."
                        }
                    }
                    else {
                        $NoCopy = $true
                    }
                }
                finally {
                    # Restore PS Formatting Styles
                    $OriginalStyle.Keys | ForEach-Object -Process {
                        $PSStyle.Formatting.$_ = $OriginalStyle[$_]
                    }
                    Write-Progress -Id 21 -Activity 'Complete.' -Completed
                }
            }
        }
        Catch {
            $NoCopy = $true
            Throw $_
        }
        finally {
            # Display the output
            if ($Deploy) {
                Write-FinalOutput -Paths $FinalSupplementalPath
            }
            else {
                Write-FinalOutput -Paths $FinalSupplementalPath, $FinalSupplementalCIPPath
            }

            # Copy the final files to the user config directory
            if (!$NoCopy) {
                Copy-Item -Path ($Deploy ? $FinalSupplementalPath : $FinalSupplementalPath, $FinalSupplementalCIPPath) -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force
            }
            if (![WDACConfig.GlobalVars]::DebugPreference) {
                Remove-Item -Path $StagingArea -Recurse -Force
            }
        }
    }

    <#
.SYNOPSIS
    Use this cmdlet to create Supplemental policies for your base policies using various methods.
    It can be used to create Supplemental policies based on directories, installed apps, and certificates.
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-SupplementalWDACConfig
.DESCRIPTION
    Using official Microsoft methods, configure and use App Control for Business
.PARAMETER Normal
    Make a Supplemental policy by scanning a directory, you can optionally use other parameters too to fine tune the scan process.
.PARAMETER PathWildCards
    This parameter allows you to select a folder and create a policy that will allow any files in that folder and its sub-folders to be allowed to run.
.PARAMETER InstalledAppXPackages
    Make a Supplemental policy based on the Package Family Name of an installed Windows app
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
    Browse for the xml file of the Base policy this Supplemental policy is going to expand. Supports file picker GUI by showing only .xml files.
    Press tab to open the GUI.
    It is used by the entire Cmdlet.
.PARAMETER Deploy
    Indicates that the module will automatically deploy the Supplemental policy after creation.
    It is used by the entire Cmdlet.
.PARAMETER Force
    It's used by the entire Cmdlet. Indicates that the confirmation prompts will be bypassed.
.INPUTS
    System.String[]
    System.String
    System.IO.DirectoryInfo
    System.IO.FileInfo
    System.IO.FileInfo[]
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
#>
}