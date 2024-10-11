Function New-SupplementalWDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = 'Normal',
        PositionalBinding = $false,
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    [OutputType([System.String])]
    Param(
        [Alias('N')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')][System.Management.Automation.SwitchParameter]$Normal,
        [Alias('W')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Folder Path With WildCards')][System.Management.Automation.SwitchParameter]$PathWildCards,
        [Alias('P')]
        [parameter(mandatory = $false, ParameterSetName = 'Installed AppXPackages')][System.Management.Automation.SwitchParameter]$InstalledAppXPackages,
        [Alias('C')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Certificate')][System.Management.Automation.SwitchParameter]$Certificates,

        [parameter(Mandatory = $true, ParameterSetName = 'Installed AppXPackages', ValueFromPipelineByPropertyName = $true)]
        [System.String]$PackageName,

        [ArgumentCompleter([WDACConfig.ArgCompleter.FolderPicker])]
        [ValidateScript({ [System.IO.Directory]::Exists($_) }, ErrorMessage = 'The path you selected is not a folder path.')]
        [parameter(Mandatory = $true, ParameterSetName = 'Normal', ValueFromPipelineByPropertyName = $true)]
        [System.IO.DirectoryInfo]$ScanLocation,

        [ArgumentCompleter([WDACConfig.ArgCompleter.FolderPickerWithWildcard])]
        [ValidatePattern('\*', ErrorMessage = 'You did not supply a path that contains wildcard character (*) .')]
        [parameter(Mandatory = $true, ParameterSetName = 'Folder Path With WildCards', ValueFromPipelineByPropertyName = $true)]
        [System.IO.DirectoryInfo]$FolderPath,

        [ArgumentCompleter([WDACConfig.ArgCompleter.MultipleCerFilePicker])]
        [ValidateScript({ [System.IO.File]::Exists($_) }, ErrorMessage = 'The path you selected is not a file path.')]
        [parameter(Mandatory = $true, ParameterSetName = 'Certificate', ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo[]]$CertificatePaths,

        [ValidateCount(1, 232)]
        [ValidatePattern('^[a-zA-Z0-9 \-]+$', ErrorMessage = 'The policy name can only contain alphanumeric, space and dash (-) characters.')]
        [parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String]$SuppPolicyName,

        [ArgumentCompleter([WDACConfig.ArgCompleter.XmlFilePathsPicker])]
        [ValidateScript({ [WDACConfig.CiPolicyTest]::TestCiPolicy($_, $null) })]
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo]$PolicyPath,

        [parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$Deploy,

        [ValidateSet('OriginalFileName', 'InternalName', 'FileDescription', 'ProductName', 'PackageFamilyName', 'FilePath')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.String]$SpecificFileNameLevel,

        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.Management.Automation.SwitchParameter]$NoUserPEs,

        [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.Management.Automation.SwitchParameter]$NoScript,

        [ArgumentCompleter({ [WDACConfig.ScanLevelz]::New().GetValidValues() })]
        [parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.String]$Level = 'WHQLFilePublisher',

        [ArgumentCompleter({ [WDACConfig.ScanLevelz]::New().GetValidValues() })]
        [parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.String[]]$Fallbacks = ('FilePublisher', 'Hash'),

        [Parameter(Mandatory = $false, ParameterSetName = 'Installed AppXPackages')]
        [System.Management.Automation.SwitchParameter]$Force,

        [ValidateSet('UserMode', 'KernelMode')]
        [parameter(Mandatory = $false, ParameterSetName = 'Certificate')]
        [System.String]$SigningScenario = 'UserMode',

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )
    Begin {
        [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)

        if ($PSBoundParameters['Certificates']) {
            Import-Module -Force -FullyQualifiedName @(
                "$([WDACConfig.GlobalVars]::ModuleRootPath)\XMLOps\New-CertificateSignerRules.psm1",
                "$([WDACConfig.GlobalVars]::ModuleRootPath)\XMLOps\Clear-CiPolicy_Semantic.psm1"
            )
        }

        if (-NOT $SkipVersionCheck) { Update-WDACConfigPSModule -InvocationStatement $MyInvocation.Statement }

        if ([WDACConfig.GlobalVars]::ConfigCIBootstrap -eq $false) {
            Invoke-MockConfigCIBootstrap
            [WDACConfig.GlobalVars]::ConfigCIBootstrap = $true
        }

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

            if ($PSBoundParameters['Normal']) {

                # The total number of the main steps for the progress bar to render
                $TotalSteps = $Deploy ? 3us : 2us
                $CurrentStep = 0us

                $CurrentStep++
                Write-Progress -Id 19 -Activity 'Processing user selected folders' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.Logger]::Write('Processing Program Folder From User input')
                # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
                [System.Collections.Hashtable]$PolicyMakerHashTable = @{
                    FilePath               = $FinalSupplementalPath
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

                Write-ColorfulTextWDACConfig -Color HotPink -InputText 'Generating Supplemental policy with the following specifications:'
                $PolicyMakerHashTable
                Write-Host -Object ''

                # Create the supplemental policy via parameter splatting
                New-CIPolicy @PolicyMakerHashTable

                $CurrentStep++
                Write-Progress -Id 19 -Activity 'Configuring the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.Logger]::Write('Changing the policy type from base to Supplemental, assigning its name and resetting its policy ID')
                $null = [WDACConfig.SetCiPolicyInfo]::Set($FinalSupplementalPath, $true, "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')", $null, $PolicyPath)

                [WDACConfig.SetCiPolicyInfo]::Set($FinalSupplementalPath, ([version]'1.0.0.0'))

                [WDACConfig.CiRuleOptions]::Set($FinalSupplementalPath, [WDACConfig.CiRuleOptions+PolicyTemplate]::Supplemental, $null, $null, $null, $null, $null, $null, $null, $null, $null)

                [WDACConfig.Logger]::Write('Converting the Supplemental policy XML file to a CIP file')
                $null = ConvertFrom-CIPolicy -XmlFilePath $FinalSupplementalPath -BinaryFilePath $FinalSupplementalCIPPath

                if ($Deploy) {
                    $CurrentStep++
                    Write-Progress -Id 19 -Activity 'Deploying the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [WDACConfig.CiToolHelper]::UpdatePolicy($FinalSupplementalCIPPath)
                    Write-ColorfulTextWDACConfig -Color Pink -InputText "A Supplemental policy with the name '$SuppPolicyName' has been deployed."
                }
                Write-Progress -Id 19 -Activity 'Complete.' -Completed
            }

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

            if ($PSBoundParameters['Certificates']) {

                # The total number of the main steps for the progress bar to render
                $TotalSteps = $Deploy ? 5us : 4us
                $CurrentStep = 0us

                $CurrentStep++
                Write-Progress -Id 33 -Activity 'Preparing the policy template' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.Logger]::Write('Copying the template policy to the staging area')
                Copy-Item -LiteralPath 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml' -Destination $FinalSupplementalPath -Force

                [WDACConfig.Logger]::Write('Emptying the policy file in preparation for the new data insertion')
                Clear-CiPolicy_Semantic -Path $FinalSupplementalPath

                $CurrentStep++
                Write-Progress -Id 33 -Activity 'Extracting details from the selected certificate files' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # a variable to hold the output signer data
                $OutputSignerData = New-Object -TypeName System.Collections.Generic.List[WDACConfig.CertificateSignerCreator]

                foreach ($CertPath in $CertificatePaths) {

                    # Create a certificate object from the .cer file
                    [System.Security.Cryptography.X509Certificates.X509Certificate2]$SignedFileSigDetails = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromSignedFile($CertPath)

                    # Create rule for the certificate based on the first element in its chain
                    $OutputSignerData.Add([WDACConfig.CertificateSignerCreator]::New(
                            [WDACConfig.CertificateHelper]::GetTBSCertificate($SignedFileSigDetails),
                            ([WDACConfig.CryptoAPI]::GetNameString($SignedFileSigDetails.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $false)),
                            ($SigningScenario -eq 'UserMode' ? '1' :  '0')
                        ))
                }

                $CurrentStep++
                Write-Progress -Id 33 -Activity 'Generating signer rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                if ($null -ne $OutputSignerData) {
                    New-CertificateSignerRules -SignerData $OutputSignerData -XmlFilePath $FinalSupplementalPath
                }

                $CurrentStep++
                Write-Progress -Id 33 -Activity 'Finalizing the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.Logger]::Write('Converting the policy type from base to Supplemental, assigning its name and resetting its policy ID')
                $null = [WDACConfig.SetCiPolicyInfo]::Set($FinalSupplementalPath, $true, "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')", $null, $PolicyPath)

                [WDACConfig.SetCiPolicyInfo]::Set($FinalSupplementalPath, ([version]'1.0.0.0'))

                [WDACConfig.CiRuleOptions]::Set($FinalSupplementalPath, [WDACConfig.CiRuleOptions+PolicyTemplate]::Supplemental, $null, $null, $null, $null, $null, $null, $null, $null, $null)

                [WDACConfig.Logger]::Write('Converting the Supplemental policy XML file to a CIP file')
                $null = ConvertFrom-CIPolicy -XmlFilePath $FinalSupplementalPath -BinaryFilePath $FinalSupplementalCIPPath

                if ($Deploy) {
                    $CurrentStep++
                    Write-Progress -Id 33 -Activity 'Deploying the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [WDACConfig.CiToolHelper]::UpdatePolicy($FinalSupplementalCIPPath)
                    Write-ColorfulTextWDACConfig -Color Pink -InputText "A Supplemental policy with the name '$SuppPolicyName' has been deployed."
                }

                Write-Progress -Id 33 -Activity 'Complete.' -Completed
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
.PARAMETER Certificates
    Make a Supplemental policy based on a certificate.
    If you select a root CA certificate, it will generate Signer rules based on RootCertificate level which contains TBS Hash only.
    If you select a non-root CA certificate such as Leaf Certificate or Intermediate certificate, it will generate Signer rules based on LeafCertificate level which contains TBS Hash as well as the subject name of the selected certificate.
.PARAMETER PolicyPath
    Browse for the xml file of the Base policy this Supplemental policy is going to expand. Supports file picker GUI by showing only .xml files.
    Press tab to open the GUI.
    It is used by the entire Cmdlet.
.PARAMETER CertificatePaths
    Browse for the certificate file(s) that you want to use to create the Supplemental policy. Supports file picker GUI by showing only .cer files.
.PARAMETER SigningScenario
    You can choose one of the following options: "UserMode", "KernelMode"
    It is available only when creating Supplemental policy based on certificates.
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
.PARAMETER Force
    It's used by the entire Cmdlet. Indicates that the confirmation prompts will be bypassed.
.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases
.PARAMETER Verbose
    It's used by the entire Cmdlet. Indicates that the verbose messages will be displayed.
.INPUTS
    System.String[]
    System.String
    System.IO.DirectoryInfo
    System.IO.FileInfo
    System.IO.FileInfo[]
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
.EXAMPLE
    New-SupplementalWDACConfig -Normal -SuppPolicyName 'MyPolicy' -PolicyPath 'C:\MyPolicy.xml' -ScanLocation 'C:\Program Files\MyApp' -Deploy

    This example will create a Supplemental policy named MyPolicy based on the Base policy located at C:\MyPolicy.xml and will scan the 'C:\Program Files\MyApp' folder for files that will be allowed to run by the Supplemental policy.
.EXAMPLE
    New-SupplementalWDACConfig -Certificates -CertificatePaths "certificate 1 .cer", "certificate 2 .cer" -Verbose -SuppPolicyName 'certs' -PolicyPath "C:\Program Files\WDACConfig\DefaultWindowsPlusBlockRules.xml"

    This example will create a Supplemental policy named certs based on the certificates located at "certificate 1 .cer" and "certificate 2 .cer" and the Base policy located at "C:\Program Files\WDACConfig\DefaultWindowsPlusBlockRules.xml".
#>
}
