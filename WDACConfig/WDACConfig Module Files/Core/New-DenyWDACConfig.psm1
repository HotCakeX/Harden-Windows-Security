Function New-DenyWDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = 'Drivers',
        PositionalBinding = $false,
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    Param(
        [Alias('D')][Parameter(Mandatory = $false, ParameterSetName = 'Drivers')][switch]$Drivers,
        [Alias('P')][parameter(mandatory = $false, ParameterSetName = 'Installed AppXPackages')][switch]$InstalledAppXPackages,
        [Alias('W')][Parameter(Mandatory = $false, ParameterSetName = 'Folder Path With WildCards')][switch]$PathWildCards,

        [parameter(Mandatory = $true, ParameterSetName = 'Installed AppXPackages', ValueFromPipelineByPropertyName = $true)]
        [System.String]$PackageName,

        [ValidateCount(1, 232)]
        [ValidatePattern('^[a-zA-Z0-9 \-]+$', ErrorMessage = 'The policy name can only contain alphanumeric, space and dash (-) characters.')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String]$PolicyName,

        [ArgumentCompleter([WDACConfig.ArgCompleter.FolderPickerWithWildcard])]
        [ValidatePattern('\*', ErrorMessage = 'You did not supply a path that contains wildcard character (*) .')]
        [parameter(Mandatory = $true, ParameterSetName = 'Folder Path With WildCards', ValueFromPipelineByPropertyName = $true)]
        [System.IO.DirectoryInfo]$FolderPath,

        [ArgumentCompleter([WDACConfig.ArgCompleter.FolderPicker])]
        [ValidateScript({ [System.IO.Directory]::Exists($_) }, ErrorMessage = 'One of the paths you selected is not a valid folder path.')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Drivers')]
        [System.IO.DirectoryInfo[]]$ScanLocations,

        [Parameter(Mandatory = $false)][switch]$Deploy,
        [Parameter(Mandatory = $false, ParameterSetName = 'Installed AppXPackages')][switch]$Force,
        [Parameter(Mandatory = $false, ParameterSetName = 'Folder Path With WildCards')][switch]$EmbeddedVerboseOutput
    )
    Begin {
        [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)

        [System.IO.DirectoryInfo]$StagingArea = [WDACConfig.StagingArea]::NewStagingArea('New-DenyWDACConfig')

        # Detecting if Confirm switch is used to bypass the confirmation prompts
        if ($Force -and -Not $Confirm) {
            $ConfirmPreference = 'None'
        }

        [System.IO.FileInfo]$FinalDenyPolicyPath = Join-Path -Path $StagingArea -ChildPath "DenyPolicy $PolicyName.xml"
        [System.IO.FileInfo]$FinalDenyPolicyCIPPath = Join-Path -Path $StagingArea -ChildPath "DenyPolicy $PolicyName.cip"

        # Due to the ACLs of the Windows directory, we make a copy of the AllowAll template policy in the Staging Area and then use it
        [System.IO.FileInfo]$AllowAllPolicyPath = Join-Path -Path $StagingArea -ChildPath 'AllowAllPolicy.xml'
        Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml' -Destination $AllowAllPolicyPath -Force

        [System.IO.FileInfo]$TempPolicyPath = Join-Path -Path $StagingArea -ChildPath 'DenyPolicy Temp.xml'

        # Flag indicating the final files should not be copied to the main user config directory
        [System.Boolean]$NoCopy = $false
    }
    process {
        Try {           
            # Create Deny base policy for Driver files
            if ($Drivers) {

                # The total number of the main steps for the progress bar to render
                $TotalSteps = $Deploy ? 4us : 3us
                $CurrentStep = 0us

                $CurrentStep++
                Write-Progress -Id 23 -Activity 'Processing user selected Folders' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.Logger]::Write('Looping through each user-selected folder paths, scanning them, creating a temp policy file based on them')
                powershell.exe -NoProfile -Command {

                    # Prep the environment as a workaround for the ConfigCI bug
                    if ([System.IO.Directory]::Exists('C:\Program Files\Windows Defender\Offline')) {
                        [System.String]$RandomGUID = [System.Guid]::NewGuid().ToString()
                        New-CIPolicy -UserPEs -ScanPath 'C:\Program Files\Windows Defender\Offline' -Level hash -FilePath ".\$RandomGUID.xml" -NoShadowCopy -PathToCatroot 'C:\Program Files\Windows Defender\Offline' -WarningAction SilentlyContinue
                        Remove-Item -LiteralPath ".\$RandomGUID.xml" -Force
                    }

                    [System.Collections.ArrayList]$DriverFilesObject = @()

                    # loop through each user-selected folder paths
                    foreach ($ScanLocation in $args[0]) {

                        # DriverFile object holds the full details of all of the scanned drivers - This scan is greedy, meaning it stores as much information as it can find
                        # about each driver file, any available info about digital signature, hash, FileName, Internal Name etc. of each driver is saved and nothing is left out
                        $DriverFilesObject += Get-SystemDriver -ScanPath $ScanLocation -UserPEs
                    }

                    [System.Collections.Hashtable]$PolicyMakerHashTable = @{
                        FilePath               = $args[1]
                        DriverFiles            = $DriverFilesObject
                        Level                  = 'WHQLFilePublisher'
                        Fallback               = 'None'
                        MultiplePolicyFormat   = $true
                        UserWriteablePaths     = $true
                        Deny                   = $true
                        AllowFileNameFallbacks = $true
                    }
                    # Creating a base policy using the DriverFile object and specifying which detail about each driver should be used in the policy file
                    New-CIPolicy @PolicyMakerHashTable

                } -args $ScanLocations, $TempPolicyPath

                $CurrentStep++
                Write-Progress -Id 23 -Activity 'Merging the policies' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Merging AllowAll default policy with our Deny temp policy
                [WDACConfig.Logger]::Write('Merging AllowAll default template policy with our Deny temp policy')
                $null = Merge-CIPolicy -PolicyPaths $AllowAllPolicyPath, $TempPolicyPath -OutputFilePath $FinalDenyPolicyPath

                $CurrentStep++
                Write-Progress -Id 23 -Activity 'Configuring the base policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.Logger]::Write('Assigning a name and resetting the policy ID')
                $null = [WDACConfig.SetCiPolicyInfo]::Set($FinalDenyPolicyPath, $true, $PolicyName, $null, $null)

                [WDACConfig.SetCiPolicyInfo]::Set($FinalDenyPolicyPath, ([version]'1.0.0.0'))

                [WDACConfig.CiRuleOptions]::Set($FinalDenyPolicyPath, [WDACConfig.CiRuleOptions+PolicyTemplate]::Base, $null, $null, $null, $null, $null, $null, $null, $null, $null)

                [WDACConfig.Logger]::Write('Converting the policy XML to .CIP')
                $null = ConvertFrom-CIPolicy -XmlFilePath $FinalDenyPolicyPath -BinaryFilePath $FinalDenyPolicyCIPPath

                if ($Deploy) {
                    $CurrentStep++
                    Write-Progress -Id 23 -Activity 'Deploying the base policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [WDACConfig.CiToolHelper]::UpdatePolicy($FinalDenyPolicyCIPPath)

                    Write-ColorfulTextWDACConfig -Color Pink -InputText "A Deny Base policy with the name '$PolicyName' has been deployed."
                }
                Write-Progress -Id 23 -Activity 'Complete.' -Completed
            }

            # Creating Deny rule for Appx Packages
            if ($InstalledAppXPackages) {

                try {
                    # The total number of the main steps for the progress bar to render
                    $TotalSteps = $Deploy ? 3us : 2us
                    $CurrentStep = 0us

                    $CurrentStep++
                    Write-Progress -Id 24 -Activity 'Getting the Appx package' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

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
                        Write-Progress -Id 24 -Activity 'Creating the base policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                        [WDACConfig.Logger]::Write('Creating a temporary Deny policy for the supplied Appx package name')
                        powershell.exe -NoProfile -Command {
                            # Get all the packages based on the supplied name
                            [Microsoft.Windows.Appx.PackageManager.Commands.AppxPackage[]]$Package = Get-AppxPackage -Name $args[0]

                            $Rules = @()

                            # Create rules for each package
                            foreach ($Item in $Package) {
                                $Rules += New-CIPolicyRule -Deny -Package $Item
                            }

                            # Generate the supplemental policy xml file
                            New-CIPolicy -MultiplePolicyFormat -FilePath $args[1] -Rules $Rules
                        } -args $PackageName, $TempPolicyPath

                        # Merging AllowAll default policy with our Deny temp policy
                        [WDACConfig.Logger]::Write('Merging AllowAll default template policy with our AppX Deny temp policy')
                        $null = Merge-CIPolicy -PolicyPaths $AllowAllPolicyPath, $TempPolicyPath -OutputFilePath $FinalDenyPolicyPath

                        [WDACConfig.Logger]::Write('Assigning a name and resetting the policy ID')
                        $null = [WDACConfig.SetCiPolicyInfo]::Set($FinalDenyPolicyPath, $true, $PolicyName, $null, $null)

                        [WDACConfig.SetCiPolicyInfo]::Set($FinalDenyPolicyPath, ([version]'1.0.0.0'))

                        [WDACConfig.CiRuleOptions]::Set($FinalDenyPolicyPath, [WDACConfig.CiRuleOptions+PolicyTemplate]::Base, $null, $null, $null, $null, $null, $null, $null, $null, $null)

                        [WDACConfig.Logger]::Write('Converting the policy XML to .CIP')
                        $null = ConvertFrom-CIPolicy -XmlFilePath $FinalDenyPolicyPath -BinaryFilePath $FinalDenyPolicyCIPPath

                        if ($Deploy) {
                            $CurrentStep++
                            Write-Progress -Id 24 -Activity 'Deploying the base policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                            [WDACConfig.CiToolHelper]::UpdatePolicy($FinalDenyPolicyCIPPath)

                            Write-ColorfulTextWDACConfig -Color Pink -InputText "A Deny Base policy with the name '$PolicyName' has been deployed."
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
                    Write-Progress -Id 24 -Activity 'Complete.' -Completed
                }
            }

            # Create Deny base policy for a folder with wildcards
            if ($PathWildCards) {

                # The total number of the main steps for the progress bar to render
                $TotalSteps = $Deploy ? 3us : 2us
                $CurrentStep = 0us

                $CurrentStep++
                Write-Progress -Id 29 -Activity 'Creating the wildcard deny policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Using Windows PowerShell to handle serialized data since PowerShell core throws an error
                [WDACConfig.Logger]::Write('Creating the deny policy file')
                powershell.exe -NoProfile -Command {
                    $RulesWildCards = New-CIPolicyRule -Deny -FilePathRule $args[0]
                    New-CIPolicy -MultiplePolicyFormat -FilePath $args[1] -Rules $RulesWildCards
                } -args $FolderPath, $TempPolicyPath

                # Merging AllowAll default policy with our Deny temp policy
                [WDACConfig.Logger]::Write('Merging AllowAll default template policy with our Wildcard Deny temp policy')
                $null = Merge-CIPolicy -PolicyPaths $AllowAllPolicyPath, $TempPolicyPath -OutputFilePath $FinalDenyPolicyPath

                $CurrentStep++
                Write-Progress -Id 29 -Activity 'Configuring the wildcard deny policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.Logger]::Write('Assigning a name and resetting the policy ID')
                $null = [WDACConfig.SetCiPolicyInfo]::Set($FinalDenyPolicyPath, $true, $PolicyName, $null, $null)

                [WDACConfig.SetCiPolicyInfo]::Set($FinalDenyPolicyPath, ([version]'1.0.0.0'))

                [WDACConfig.CiRuleOptions]::Set($FinalDenyPolicyPath, [WDACConfig.CiRuleOptions+PolicyTemplate]::Base, $null, $null, $null, $null, $null, $null, $null, $null, $null)

                [WDACConfig.Logger]::Write('Converting the policy XML to .CIP')
                $null = ConvertFrom-CIPolicy -XmlFilePath $FinalDenyPolicyPath -BinaryFilePath $FinalDenyPolicyCIPPath

                if ($Deploy) {
                    $CurrentStep++
                    Write-Progress -Id 29 -Activity 'Deploying the base policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [WDACConfig.CiToolHelper]::UpdatePolicy($FinalDenyPolicyCIPPath)

                    if ($EmbeddedVerboseOutput) {
                        [WDACConfig.Logger]::Write("A Deny Base policy with the name '$PolicyName' has been deployed.")
                    }
                    else {
                        Write-ColorfulTextWDACConfig -Color Pink -InputText "A Deny Base policy with the name '$PolicyName' has been deployed."
                    }
                }
                Write-Progress -Id 29 -Activity 'Complete.' -Completed
            }
        }
        Catch {
            $NoCopy = $true
            Throw $_
        }
        finally {
            # If the cmdlet is not running in embedded mode
            if (-NOT $EmbeddedVerboseOutput) {
                # If there was no error
                if (!$NoCopy) {
                    # Display the output
                    if ($Deploy) {
                        Write-FinalOutput -Paths $FinalDenyPolicyPath
                    }
                    else {
                        Write-FinalOutput -Paths $FinalDenyPolicyPath, $FinalDenyPolicyCIPPath
                    }
                }
            }

            # Copy the final policy files to the user config directory
            if (!$NoCopy) {
                Copy-Item -Path ($Deploy ? $FinalDenyPolicyPath : $FinalDenyPolicyPath, $FinalDenyPolicyCIPPath) -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force
            }
            if (![WDACConfig.GlobalVars]::DebugPreference) {
                Remove-Item -Path $StagingArea -Recurse -Force
            }
        }
    }
}