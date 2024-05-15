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

        [ValidateScript({ Test-Path -Path $_ -PathType 'Container' }, ErrorMessage = 'The path you selected is not a folder path.')]
        [parameter(Mandatory = $true, ParameterSetName = 'Normal', ValueFromPipelineByPropertyName = $true)]
        [System.IO.DirectoryInfo]$ScanLocation,

        [ValidatePattern('\*', ErrorMessage = 'You did not supply a path that contains wildcard character (*) .')]
        [parameter(Mandatory = $true, ParameterSetName = 'Folder Path With WildCards', ValueFromPipelineByPropertyName = $true)]
        [System.IO.DirectoryInfo]$FolderPath,

        [ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' }, ErrorMessage = 'The path you selected is not a file path.')]
        [parameter(Mandatory = $true, ParameterSetName = 'Certificate', ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo[]]$CertificatePaths,

        [ValidateCount(1, 232)]
        [ValidatePattern('^[a-zA-Z0-9 \-]+$', ErrorMessage = 'The policy name can only contain alphanumeric, space and dash (-) characters.')]
        [parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String]$SuppPolicyName,

        [ValidateScript({ Test-CiPolicy -XmlFile $_ })]
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

        [ValidateSet([ScanLevelz])]
        [parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.String]$Level = 'WHQLFilePublisher',

        [ValidateSet([ScanLevelz])]
        [parameter(Mandatory = $false, ParameterSetName = 'Normal')]
        [System.String[]]$Fallbacks = ('FilePublisher', 'Hash'),

        [Parameter(Mandatory = $false, ParameterSetName = 'Installed AppXPackages')]
        [System.Management.Automation.SwitchParameter]$Force,

        [ValidateSet('UserMode', 'KernelMode')]
        [parameter(Mandatory = $false, ParameterSetName = 'Certificate')]
        [System.String]$SigningScenario = 'UserMode',

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )

    begin {
        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null
        # Detecting if Debug switch is used, will do debugging actions based on that
        $PSBoundParameters.Debug.IsPresent ? ([System.Boolean]$Debug = $true) : ([System.Boolean]$Debug = $false) | Out-Null

        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -Force -FullyQualifiedName (
            "$ModuleRootPath\Shared\Update-Self.psm1",
            "$ModuleRootPath\Shared\Write-ColorfulText.psm1",
            "$ModuleRootPath\Shared\New-StagingArea.psm1"
        )

        if ($PSBoundParameters['Certificates']) {
            Import-Module -Force -FullyQualifiedName (
                "$ModuleRootPath\WDACSimulation\Get-TBSCertificate.psm1",
                "$ModuleRootPath\WDACSimulation\Get-SignedFileCertificates.psm1",
                "$ModuleRootPath\WDACSimulation\Get-CertificateDetails.psm1",
                "$ModuleRootPath\XMLOps\New-RootAndLeafCertificateLevelRules.psm1",
                "$ModuleRootPath\XMLOps\Clear-CiPolicy_Semantic.psm1"
            )
        }

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-Self -InvocationStatement $MyInvocation.Statement }

        [System.IO.DirectoryInfo]$StagingArea = New-StagingArea -CmdletName 'New-SupplementalWDACConfig'

        #Region User-Configurations-Processing-Validation
        # If PolicyPath was not provided by user, check if a valid value exists in user configs, if so, use it, otherwise throw an error
        if (!$PolicyPath) {
            if (Test-Path -Path (Get-CommonWDACConfig -UnsignedPolicyPath)) {
                $PolicyPath = Get-CommonWDACConfig -UnsignedPolicyPath
            }
            else {
                throw 'PolicyPath parameter cannot be empty and no valid user configuration was found for UnsignedPolicyPath.'
            }
        }
        #Endregion User-Configurations-Processing-Validation

        # Ensure when user selects the -Deploy parameter, the base policy is not signed
        if ($Deploy) {
            $XmlTest = [System.Xml.XmlDocument](Get-Content -Path $PolicyPath)
            $RedFlag1 = $XmlTest.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
            $RedFlag2 = $XmlTest.SiPolicy.UpdatePolicySigners.UpdatePolicySigner.SignerId
            if ($RedFlag1 -or $RedFlag2) {
                Throw 'You are using -Deploy parameter and the selected base policy is Signed. Please use Deploy-SignedWDACConfig to deploy it.'
            }
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
                [System.Int16]$TotalSteps = $Deploy ? 3 : 2
                [System.Int16]$CurrentStep = 0

                $CurrentStep++
                Write-Progress -Id 19 -Activity 'Processing user selected folders' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Processing Program Folder From User input'
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

                Write-ColorfulText -Color HotPink -InputText 'Generating Supplemental policy with the following specifications:'
                $PolicyMakerHashTable
                Write-Host -Object ''

                # Create the supplemental policy via parameter splatting
                New-CIPolicy @PolicyMakerHashTable

                $CurrentStep++
                Write-Progress -Id 19 -Activity 'Configuring the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Changing the policy type from base to Supplemental, assigning its name and resetting its policy ID'
                Set-CIPolicyIdInfo -FilePath $FinalSupplementalPath -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath -PolicyName "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')" | Out-Null

                Write-Verbose -Message 'Setting the Supplemental policy version to 1.0.0.0'
                Set-CIPolicyVersion -FilePath $FinalSupplementalPath -Version '1.0.0.0'

                Set-CiRuleOptions -FilePath $FinalSupplementalPath -Template Supplemental

                Write-Verbose -Message 'Converting the Supplemental policy XML file to a CIP file'
                ConvertFrom-CIPolicy -XmlFilePath $FinalSupplementalPath -BinaryFilePath $FinalSupplementalCIPPath | Out-Null

                Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyFile = $FinalSupplementalPath"
                Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyGUID = $FinalSupplementalCIPPath"

                if ($Deploy) {
                    $CurrentStep++
                    Write-Progress -Id 19 -Activity 'Deploying the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Deploying the Supplemental policy'
                    &'C:\Windows\System32\CiTool.exe' --update-policy $FinalSupplementalCIPPath -json | Out-Null
                    Write-ColorfulText -Color Pink -InputText "A Supplemental policy with the name $SuppPolicyName has been deployed."
                }
                Write-Progress -Id 19 -Activity 'Complete.' -Completed
            }

            if ($PSBoundParameters['PathWildCards']) {

                # The total number of the main steps for the progress bar to render
                [System.Int16]$TotalSteps = $Deploy ? 2 : 1
                [System.Int16]$CurrentStep = 0

                $CurrentStep++
                Write-Progress -Id 20 -Activity 'Creating the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Using Windows PowerShell to handle serialized data since PowerShell core throws an error
                Write-Verbose -Message 'Creating the Supplemental policy file'
                powershell.exe -Command {
                    $RulesWildCards = New-CIPolicyRule -FilePathRule $args[0]
                    New-CIPolicy -MultiplePolicyFormat -FilePath "$($args[2])\SupplementalPolicy $($args[1]).xml" -Rules $RulesWildCards
                } -args $FolderPath, $SuppPolicyName, $StagingArea

                Write-Verbose -Message 'Changing the policy type from base to Supplemental, assigning its name and resetting its policy ID'
                Set-CIPolicyIdInfo -FilePath $FinalSupplementalPath -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath -PolicyName "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')" | Out-Null

                Write-Verbose -Message 'Setting the Supplemental policy version to 1.0.0.0'
                Set-CIPolicyVersion -FilePath $FinalSupplementalPath -Version '1.0.0.0'

                Set-CiRuleOptions -FilePath $FinalSupplementalPath -Template Supplemental

                Write-Verbose -Message 'Converting the Supplemental policy XML file to a CIP file'
                ConvertFrom-CIPolicy -XmlFilePath $FinalSupplementalPath -BinaryFilePath $FinalSupplementalCIPPath | Out-Null

                Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyFile = $FinalSupplementalPath"
                Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyGUID = $FinalSupplementalCIPPath"

                if ($Deploy) {
                    $CurrentStep++
                    Write-Progress -Id 20 -Activity 'Deploying the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Deploying the Supplemental policy'
                    &'C:\Windows\System32\CiTool.exe' --update-policy $FinalSupplementalCIPPath -json | Out-Null
                    Write-ColorfulText -Color Pink -InputText "A Supplemental policy with the name $SuppPolicyName has been deployed."
                }
                Write-Progress -Id 20 -Activity 'Complete.' -Completed
            }

            if ($PSBoundParameters['InstalledAppXPackages']) {
                try {
                    # The total number of the main steps for the progress bar to render
                    [System.Int16]$TotalSteps = $Deploy ? 3 : 2
                    [System.Int16]$CurrentStep = 0

                    $CurrentStep++
                    Write-Progress -Id 21 -Activity 'Getting the Appx package' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    # Backing up PS Formatting Styles
                    [System.Collections.Hashtable]$OriginalStyle = @{}
                    $PSStyle.Formatting | Get-Member -MemberType Property | ForEach-Object -Process {
                        $OriginalStyle[$_.Name] = $PSStyle.Formatting.$($_.Name)
                    }

                    # Change the color for the list items to plum
                    $PSStyle.Formatting.FormatAccent = "$($PSStyle.Foreground.FromRGB(221,160,221))"

                    Write-Verbose -Message 'Displaying the installed Appx packages based on the supplied name'
                    Get-AppxPackage -Name $PackageName | Select-Object -Property Name, Publisher, version, PackageFamilyName, PackageFullName, InstallLocation, Dependencies, SignatureKind, Status

                    # Prompt for confirmation before proceeding
                    if ($PSCmdlet.ShouldProcess('', 'Select No to cancel and choose another name', 'Is this the intended results based on your Installed Appx packages?')) {

                        $CurrentStep++
                        Write-Progress -Id 21 -Activity 'Creating the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                        Write-Verbose -Message 'Creating a policy for the supplied Appx package name and its dependencies (if any)'
                        powershell.exe -Command {
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

                        Write-Verbose -Message 'Converting the policy type from base to Supplemental, assigning its name and resetting its policy ID'
                        Set-CIPolicyIdInfo -FilePath $FinalSupplementalPath -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath -PolicyName "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')" | Out-Null

                        Write-Verbose -Message 'Setting the Supplemental policy version to 1.0.0.0'
                        Set-CIPolicyVersion -FilePath $FinalSupplementalPath -Version '1.0.0.0'

                        Set-CiRuleOptions -FilePath $FinalSupplementalPath -Template Supplemental

                        Write-Verbose -Message 'Converting the Supplemental policy XML file to a CIP file'
                        ConvertFrom-CIPolicy -XmlFilePath $FinalSupplementalPath -BinaryFilePath $FinalSupplementalCIPPath | Out-Null

                        Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyFile = $FinalSupplementalPath"
                        Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyGUID = $FinalSupplementalCIPPath"

                        if ($Deploy) {
                            $CurrentStep++
                            Write-Progress -Id 21 -Activity 'Deploying the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                            Write-Verbose -Message 'Deploying the Supplemental policy'
                            &'C:\Windows\System32\CiTool.exe' --update-policy $FinalSupplementalCIPPath -json | Out-Null
                            Write-ColorfulText -Color Pink -InputText "A Supplemental policy with the name $SuppPolicyName has been deployed."
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
                [System.Int16]$TotalSteps = $Deploy ? 5 : 4
                [System.Int16]$CurrentStep = 0

                $CurrentStep++
                Write-Progress -Id 33 -Activity 'Preparing the policy template' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Class RootAndLeafSignerCreator {
                    [System.String]$TBS
                    [System.String]$SignerName
                    [System.String]$CertPublisher
                    [System.Int32]$SiSigningScenario
                    [System.String]$SignerType
                }

                Write-Verbose -Message 'Copying the template policy to the staging area'
                Copy-Item -LiteralPath 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml' -Destination $FinalSupplementalPath -Force

                Write-Verbose -Message 'Emptying the policy file in preparation for the new data insertion'
                Clear-CiPolicy_Semantic -Path $FinalSupplementalPath

                $CurrentStep++
                Write-Progress -Id 33 -Activity 'Extracting details from the selected certificate files' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # a variable to hold the output signer data
                [RootAndLeafSignerCreator[]]$OutputSignerData = $null

                foreach ($CertPath in $CertificatePaths) {

                    # All certificates have this value, which will create signer rules with TBS Hash only and result in RootCertificate Level
                    $MainCertificateDetails = Get-SignedFileCertificates -FilePath "$CertPath"

                    # Only non-root certificates have this value, which will create signer rules with subject name and TBSHash and result in LeafCertificate Level
                    $LeafCertificateDetails = (Get-CertificateDetails -FilePath "$CertPath").LeafCertificate

                    # Translate the user-friendly strings to numbers
                    $SigningScenarioTranslated = $SigningScenario -eq 'UserMode' ? '1' :  '0'

                    # Create a new object to store the signer data for the current certificate in the loop
                    [RootAndLeafSignerCreator]$CurrentRootAndLeafSignerSigner = New-Object -TypeName RootAndLeafSignerCreator

                    # If the certificate has TBS value for the leaf certificate, then it's a leaf certificate
                    if ($null -ne $LeafCertificateDetails.TBSValue) {
                        Write-Verbose -Message "New-SupplementalWDACConfig: Leaf certificate signer is going to be created for the certificate located at $CertPath"

                        [System.String]$CurrentRootAndLeafSignerSigner.TBS = $LeafCertificateDetails.TBSValue
                        $CurrentRootAndLeafSignerSigner.SiSigningScenario = $SigningScenarioTranslated
                        $CurrentRootAndLeafSignerSigner.SignerName = $MainCertificateDetails.Subject
                        $CurrentRootAndLeafSignerSigner.SignerType = 'Leaf'
                        $CurrentRootAndLeafSignerSigner.CertPublisher = $LeafCertificateDetails.SubjectCN
                    }
                    # If the certificate does not have a leaf certificate TBS value, then it's a root certificate so only use its TBS value without the subject name (aka CertPublisher value for the Signer in the XML policy file)
                    else {
                        Write-Verbose -Message "New-SupplementalWDACConfig: Root certificate signer is going to be created for the certificate located at $CertPath"

                        # Get the TBS value of the certificate
                        $CurrentRootAndLeafSignerSigner.TBS = Get-TBSCertificate -Cert $MainCertificateDetails
                        $CurrentRootAndLeafSignerSigner.SiSigningScenario = $SigningScenarioTranslated
                        $CurrentRootAndLeafSignerSigner.SignerName = $MainCertificateDetails.Subject
                        $CurrentRootAndLeafSignerSigner.SignerType = 'Root'
                    }

                    # Add the current certificate's processed results to the output signer data
                    $OutputSignerData += $CurrentRootAndLeafSignerSigner
                }

                $CurrentStep++
                Write-Progress -Id 33 -Activity 'Generating signer rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                if ($null -ne $OutputSignerData) {
                    New-RootAndLeafCertificateLevelRules -SignerData $OutputSignerData -XmlFilePath $FinalSupplementalPath
                }

                $CurrentStep++
                Write-Progress -Id 33 -Activity 'Finalizing the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Converting the policy type from base to Supplemental, assigning its name and resetting its policy ID'
                Set-CIPolicyIdInfo -FilePath $FinalSupplementalPath -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath -PolicyName "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')" | Out-Null

                Write-Verbose -Message 'Setting the Supplemental policy version to 1.0.0.0'
                Set-CIPolicyVersion -FilePath $FinalSupplementalPath -Version '1.0.0.0'

                Set-CiRuleOptions -FilePath $FinalSupplementalPath -Template Supplemental

                Write-Verbose -Message 'Converting the Supplemental policy XML file to a CIP file'
                ConvertFrom-CIPolicy -XmlFilePath $FinalSupplementalPath -BinaryFilePath $FinalSupplementalCIPPath | Out-Null

                Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyFile = $FinalSupplementalPath"
                Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyGUID = $FinalSupplementalCIPPath"

                if ($Deploy) {
                    $CurrentStep++
                    Write-Progress -Id 33 -Activity 'Deploying the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Deploying the Supplemental policy'
                    &'C:\Windows\System32\CiTool.exe' --update-policy $FinalSupplementalCIPPath -json | Out-Null
                    Write-ColorfulText -Color Pink -InputText "A Supplemental policy with the name $SuppPolicyName has been deployed."
                }

                Write-Progress -Id 33 -Activity 'Complete.' -Completed
            }
        }
        Catch {
            $NoCopy = $true
            Throw $_
        }
        finally {
            # Copy the final files to the user config directory
            if (-NOT $NoCopy) {
                Copy-Item -Path ($Deploy ? $FinalSupplementalPath : $FinalSupplementalPath, $FinalSupplementalCIPPath) -Destination $UserConfigDir -Force
            }
            if (-NOT $Debug) {
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
    Using official Microsoft methods, configure and use Windows Defender Application Control
.COMPONENT
    Windows Defender Application Control, ConfigCI PowerShell module
.FUNCTIONALITY
    Automate various tasks related to Windows Defender Application Control (WDAC)
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

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\CoreExt\ArgumentCompleters.ps1"
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'PolicyPath' -ScriptBlock $ArgumentCompleterXmlFilePathsPicker
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'PackageName' -ScriptBlock $ArgumentCompleterAppxPackageNames
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'ScanLocation' -ScriptBlock $ArgumentCompleterFolderPathsPicker
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'FolderPath' -ScriptBlock $ArgumentCompleterFolderPathsPickerWildCards
Register-ArgumentCompleter -CommandName 'New-SupplementalWDACConfig' -ParameterName 'CertificatePaths' -ScriptBlock $ArgumentCompleterCerFilesPathsPicker

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBQ/E8kImcJUgMV
# F5zZzRiiwdTbP8rFG2cnvucx1KTtMaCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
# LDQz/68TAAAAAAAEMA0GCSqGSIb3DQEBDQUAME8xEzARBgoJkiaJk/IsZAEZFgNj
# b20xIjAgBgoJkiaJk/IsZAEZFhJIT1RDQUtFWC1DQS1Eb21haW4xFDASBgNVBAMT
# C0hPVENBS0VYLUNBMCAXDTIzMTIyNzExMjkyOVoYDzIyMDgxMTEyMTEyOTI5WjB5
# MQswCQYDVQQGEwJVSzEeMBwGA1UEAxMVSG90Q2FrZVggQ29kZSBTaWduaW5nMSMw
# IQYJKoZIhvcNAQkBFhRob3RjYWtleEBvdXRsb29rLmNvbTElMCMGCSqGSIb3DQEJ
# ARYWU3B5bmV0Z2lybEBvdXRsb29rLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAKb1BJzTrpu1ERiwr7ivp0UuJ1GmNmmZ65eckLpGSF+2r22+7Tgm
# pEifj9NhPw0X60F9HhdSM+2XeuikmaNMvq8XRDUFoenv9P1ZU1wli5WTKHJ5ayDW
# k2NP22G9IPRnIpizkHkQnCwctx0AFJx1qvvd+EFlG6ihM0fKGG+DwMaFqsKCGh+M
# rb1bKKtY7UEnEVAsVi7KYGkkH+ukhyFUAdUbh/3ZjO0xWPYpkf/1ldvGes6pjK6P
# US2PHbe6ukiupqYYG3I5Ad0e20uQfZbz9vMSTiwslLhmsST0XAesEvi+SJYz2xAQ
# x2O4n/PxMRxZ3m5Q0WQxLTGFGjB2Bl+B+QPBzbpwb9JC77zgA8J2ncP2biEguSRJ
# e56Ezx6YpSoRv4d1jS3tpRL+ZFm8yv6We+hodE++0tLsfpUq42Guy3MrGQ2kTIRo
# 7TGLOLpayR8tYmnF0XEHaBiVl7u/Szr7kmOe/CfRG8IZl6UX+/66OqZeyJ12Q3m2
# fe7ZWnpWT5sVp2sJmiuGb3atFXBWKcwNumNuy4JecjQE+7NF8rfIv94NxbBV/WSM
# pKf6Yv9OgzkjY1nRdIS1FBHa88RR55+7Ikh4FIGPBTAibiCEJMc79+b8cdsQGOo4
# ymgbKjGeoRNjtegZ7XE/3TUywBBFMf8NfcjF8REs/HIl7u2RHwRaUTJdAgMBAAGj
# ggJzMIICbzA8BgkrBgEEAYI3FQcELzAtBiUrBgEEAYI3FQiG7sUghM++I4HxhQSF
# hqV1htyhDXuG5sF2wOlDAgFkAgEIMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1Ud
# DwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYB
# BQUHAwMwHQYDVR0OBBYEFOlnnQDHNUpYoPqECFP6JAqGDFM6MB8GA1UdIwQYMBaA
# FICT0Mhz5MfqMIi7Xax90DRKYJLSMIHUBgNVHR8EgcwwgckwgcaggcOggcCGgb1s
# ZGFwOi8vL0NOPUhPVENBS0VYLUNBLENOPUhvdENha2VYLENOPUNEUCxDTj1QdWJs
# aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
# LERDPU5vbkV4aXN0ZW50RG9tYWluLERDPWNvbT9jZXJ0aWZpY2F0ZVJldm9jYXRp
# b25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwgccG
# CCsGAQUFBwEBBIG6MIG3MIG0BggrBgEFBQcwAoaBp2xkYXA6Ly8vQ049SE9UQ0FL
# RVgtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZp
# Y2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Tm9uRXhpc3RlbnREb21haW4sREM9Y29t
# P2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0
# aG9yaXR5MA0GCSqGSIb3DQEBDQUAA4ICAQA7JI76Ixy113wNjiJmJmPKfnn7brVI
# IyA3ZudXCheqWTYPyYnwzhCSzKJLejGNAsMlXwoYgXQBBmMiSI4Zv4UhTNc4Umqx
# pZSpqV+3FRFQHOG/X6NMHuFa2z7T2pdj+QJuH5TgPayKAJc+Kbg4C7edL6YoePRu
# HoEhoRffiabEP/yDtZWMa6WFqBsfgiLMlo7DfuhRJ0eRqvJ6+czOVU2bxvESMQVo
# bvFTNDlEcUzBM7QxbnsDyGpoJZTx6M3cUkEazuliPAw3IW1vJn8SR1jFBukKcjWn
# aau+/BE9w77GFz1RbIfH3hJ/CUA0wCavxWcbAHz1YoPTAz6EKjIc5PcHpDO+n8Fh
# t3ULwVjWPMoZzU589IXi+2Ol0IUWAdoQJr/Llhub3SNKZ3LlMUPNt+tXAs/vcUl0
# 7+Dp5FpUARE2gMYA/XxfU9T6Q3pX3/NRP/ojO9m0JrKv/KMc9sCGmV9sDygCOosU
# 5yGS4Ze/DJw6QR7xT9lMiWsfgL96Qcw4lfu1+5iLr0dnDFsGowGTKPGI0EvzK7H+
# DuFRg+Fyhn40dOUl8fVDqYHuZJRoWJxCsyobVkrX4rA6xUTswl7xYPYWz88WZDoY
# gI8AwuRkzJyUEA07IYtsbFCYrcUzIHME4uf8jsJhCmb0va1G2WrWuyasv3K/G8Nn
# f60MsDbDH1mLtzGCAxgwggMUAgEBMGYwTzETMBEGCgmSJomT8ixkARkWA2NvbTEi
# MCAGCgmSJomT8ixkARkWEkhPVENBS0VYLUNBLURvbWFpbjEUMBIGA1UEAxMLSE9U
# Q0FLRVgtQ0ECEx4AAAAEjzQsNDP/rxMAAAAAAAQwDQYJYIZIAWUDBAIBBQCggYQw
# GAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
# NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQx
# IgQggLkcGxcDnuPVrC8oUNcw7IKF9PPcT0ZFEF1YqBIlT2kwDQYJKoZIhvcNAQEB
# BQAEggIAjnijl0HuQRMxzmUrJdOXTP4i8nx5qx81QAg+SGQSYTXOmVACF3IkQjz6
# 8ciTAmG7C6yo3a6jjvAN7Gcok7LFEdo7K4IJOM0tN8JsTDIEgRHm5QyCkcvo9CWG
# omFNsmpw1PmM94p/D+fIQ4wnMyHMZxgnAkgg/ra9n8wEsi/83oMT5Mu+RuDQk3+s
# b3p3j92g2gD1mhGB4T1se0BqSFSmzbjpTz6qLef43Tjxol5BE86DpYASjeVhsUQ5
# SBlsxAhISECPbiS3a8SDLg+gRaAy8QwQDuXeu6M47CMz68eMPltbwMm4Bh9fSQ1g
# ZioRMm+W/HaMvJQEyfSZSXHpIe3IiP67/CBdgchxAlKNOJ/Biik/A35sk4waAZ9M
# 8IFUGVcLIcDcD9/5V2NFKd3+j8ypPvvldur6EBMmccxuEtmMceba5+EGwg/hU6nA
# tVVMhl10sPViE3t1NQdGCndoF7YJuSx1JZPmz7ndvDnnPN4O8KLeUB6FEMZD31Nc
# WYcvgRaa6ob6zcOC5k/9gEnuV/YwASPdF/gnr4F4GIaGPYja+IBjzAz/iac4/fr6
# 0ic/8JA/eGVkahu1W1dt87V9nG322JzpT71gOs/4cat53i64i1dBOEadUVT8H9zc
# ipxPklke01JcVJOS4RcuDcXDHRJggHX4n8PLHPXqa0YjDu6PPkg=
# SIG # End signature block
