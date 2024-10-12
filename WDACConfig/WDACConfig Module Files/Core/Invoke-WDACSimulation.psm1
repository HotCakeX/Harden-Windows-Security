Function Invoke-WDACSimulation {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[WDACConfig.SimulationOutput]], [System.Boolean])]
    Param(
        [ArgumentCompleter([WDACConfig.ArgCompleter.XmlFilePathsPicker])]
        [Alias('X')]
        [ValidateScript({ [WDACConfig.CiPolicyTest]::TestCiPolicy($_, $null) })]
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath,

        [ArgumentCompleter([WDACConfig.ArgCompleter.FolderPicker])]
        [Alias('D')]
        [ValidateScript({ [System.IO.Directory]::Exists($_) }, ErrorMessage = 'The path you selected is not a valid folder path.')]
        [Parameter(Mandatory = $false)][System.IO.DirectoryInfo[]]$FolderPath,

        [ArgumentCompleter([WDACConfig.ArgCompleter.MultipleAnyFilePathsPicker])]
        [Alias('F')]
        [ValidateScript({ [System.IO.File]::Exists($_) }, ErrorMessage = 'The path you selected is not a file path.')]
        [Parameter(Mandatory = $false)][System.IO.FileInfo[]]$FilePath,

        [Alias('B')]
        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$BooleanOutput,

        [Alias('C')]
        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$CSVOutput,

        [Alias('L')]
        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$Log,

        [Alias('N')]
        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$NoCatalogScanning,

        [ArgumentCompleter([WDACConfig.ArgCompleter.FolderPicker])]
        [Alias('Cat')]
        [ValidateScript({ [System.IO.Directory]::Exists($_) }, ErrorMessage = 'The path you selected is not a valid folder path.')]
        [Parameter(Mandatory = $false)][System.IO.DirectoryInfo[]]$CatRootPath,

        [Alias('CPU')]
        [Parameter(Mandatory = $false)][System.UInt32]$ThreadsCount = 2,

        [Alias('S')]
        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )
    Begin {
        # Only initialize the logger if this function wasn't called from another function, indicating the Verbose Preferences etc. were already set
        if ($(Get-PSCallStack).Count -le 2) {
            [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)
        }
        else {
            [WDACConfig.LoggerInitializer]::Initialize($null, $null, $Host)
        }

        if (-NOT $SkipVersionCheck) { Update-WDACConfigPSModule -InvocationStatement $MyInvocation.Statement }

        # Validate the $ThreadsCount parameter
        if ($ThreadsCount -lt 1 -or $ThreadsCount -gt [System.Environment]::ProcessorCount) {

            [WDACConfig.Logger]::Write("The ThreadsCount parameter must be between 1 and $([System.Environment]::ProcessorCount), but you entered $ThreadsCount, setting it to $([System.Environment]::ProcessorCount)")
            $ThreadsCount = [System.Environment]::ProcessorCount
        }

        # The Concurrent Dictionary contains any and all of the Simulation results
        # Keys of it are the fil paths which aren't important, values are the important items needed at the end of the simulation
        $FinalSimulationResults = [System.Collections.Concurrent.ConcurrentDictionary[System.String, WDACConfig.SimulationOutput]]::new()

        # Start the transcript if the -Log switch is used and create a function to stop the transcript and the stopwatch at the end
        if ($Log) {
            Start-Transcript -IncludeInvocationHeader -LiteralPath (Join-Path -Path ([WDACConfig.GlobalVars]::UserConfigDir) -ChildPath "WDAC Simulation Log $(Get-Date -Format "MM-dd-yyyy 'at' HH-mm-ss").txt")

            # Create a new stopwatch object to measure the execution time
            [WDACConfig.Logger]::Write('Starting the stopwatch...')
            [System.Diagnostics.Stopwatch]$StopWatch = [Diagnostics.Stopwatch]::StartNew()
            Function Stop-Log {
                <#
                .SYNOPSIS
                    Stops the stopwatch and the transcription when the -Log switch is used with the Invoke-WDACSimulation cmdlet
                .Inputs
                    None
                .Outputs
                    System.Void
                #>
                [CmdletBinding()]
                [OutputType([System.Void])]
                param()

                [WDACConfig.Logger]::Write('Stopping the stopwatch')
                $StopWatch.Stop()
                [WDACConfig.Logger]::Write("WDAC Simulation for $TotalSubSteps files completed in $($StopWatch.Elapsed.Hours) Hours - $($StopWatch.Elapsed.Minutes) Minutes - $($StopWatch.Elapsed.Seconds) Seconds - $($StopWatch.Elapsed.Milliseconds) Milliseconds - $($StopWatch.Elapsed.Microseconds) Microseconds - $($StopWatch.Elapsed.Nanoseconds) Nanoseconds")

                [WDACConfig.Logger]::Write('Stopping the transcription')
                Stop-Transcript
            }
        }

        # The total number of the main steps for the progress bar to render
        $TotalSteps = 5us
        $CurrentStep = 0us

        # Make sure either -FolderPath or -FilePath is specified
        if (-not ($PSBoundParameters.ContainsKey('FolderPath') -or $PSBoundParameters.ContainsKey('FilePath'))) {
            # Write an error message
            Write-Error -Message 'You must specify either -FolderPath or -FilePath.' -Category InvalidArgument
        }

        # Check if the supplied XML file contains Allow all rule
        [System.Boolean]$HasAllowAllRule = $false

        # Get the content of the XML file
        [System.String]$XMLContent = Get-Content -LiteralPath $XmlFilePath -Raw

        #Region Making Sure No AllowAll Rule Exists

        # Using compiled regex for better performance
        $AllowAllRegex = [System.Text.RegularExpressions.Regex]::new('<Allow ID="ID_ALLOW_.*" FriendlyName=".*" FileName="\*".*/>', 'Compiled')
        if ($AllowAllRegex.IsMatch($XMLContent)) {
            [WDACConfig.Logger]::Write("The supplied XML file '$($XmlFilePath.Name)' contains a rule that allows all files.")


            [System.Void]$FinalSimulationResults.TryAdd([string]$CurrentFilePath, [WDACConfig.SimulationOutput]::New(
                    $null,
                    'AllowAllRule',
                    $true,
                    $null,
                    $null,
                    $null,
                    $null,
                    $null,
                    $null,
                    'Has AllowAll rule',
                    $null,
                    $null,
                    $null,
                    $null,
                    $null,
                    $null
                ))


            # Set a flag to exit the subsequent blocks
            $HasAllowAllRule = $true

            # Exit the Begin block
            Return
        }

        #Endregion Making Sure No AllowAll Rule Exists

        # Get the signer information from the XML
        [WDACConfig.Signer[]]$SignerInfo = [WDACConfig.GetSignerInfo]::Get([System.Xml.XmlDocument]$XMLContent)

        # Extensions that are not supported by Authenticode. So if these files are not allowed by hash, they are not allowed at all
        $UnsignedExtensions = [System.Collections.Generic.HashSet[System.String]]::new(
            [System.String[]] ('.ocx', '.bat', '.bin'),
            # Make it case-insensitive
            [System.StringComparer]::InvariantCultureIgnoreCase
        )

        #Region FilePath Rule Checking
        [WDACConfig.Logger]::Write('Checking see if the XML policy has any FilePath rules')
        $FilePathRules = [System.Collections.Generic.HashSet[System.String]]@([WDACConfig.XmlFilePathExtractor]::GetFilePaths($XmlFilePath))

        [System.Boolean]$HasFilePathRules = $false
        if ($FilePathRules.Count -gt 0) {
            $HasFilePathRules = $true
        }
        #Endregion FilePath Rule Checking
    }

    process {
        try {
            # Only proceed if the policy doesn't have AllowAll rule
            if (!$HasAllowAllRule) {

                $CurrentStep++
                Write-Progress -Id 0 -Activity 'Parsing the Security Catalogs on the system' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                if (!$NoCatalogScanning) {

                    # A dictionary where each key is a hash and value is the file path where that hash is found
                    $AllSecurityCatalogHashes = New-Object -TypeName 'System.Collections.Generic.Dictionary[String, String]'

                    # Loop through each .cat security catalog on the system - If user selected custom CatRoot folders then use them instead
                    foreach ($File in ([WDACConfig.FileUtility]::GetFilesFast(($CatRootPath ?? 'C:\Windows\System32\CatRoot'), $null, '.cat'))) {

                        # Get the hashes of the security catalog file
                        $CatHashes = [WDACConfig.MeowParser]::GetHashes($File)

                        # If the security catalog file has hashes, then add them to the dictionary
                        if ($CatHashes.Count -gt 0) {
                            foreach ($Hash in $CatHashes) {
                                [System.Void]$AllSecurityCatalogHashes.TryAdd($Hash, $File)
                            }
                        }
                    }
                }

                # Hash Sha256 values of all the file rules based on hash in the supplied xml policy file
                [WDACConfig.Logger]::Write('Getting the Sha256 Hash values of all the file rules based on hash in the supplied xml policy file')

                $CurrentStep++
                Write-Progress -Id 0 -Activity 'Getting the Sha256 Hash values from the XML file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                $SHA256HashesFromXML = [System.Collections.Generic.HashSet[System.String]]@(([WDACConfig.GetFileRuleOutput]::Get([System.Xml.XmlDocument]$XMLContent)).HashValue)

                # Get all of the file paths of the files that WDAC supports, from the user provided directory
                [WDACConfig.Logger]::Write('Getting all of the file paths of the files that WDAC supports, from the user provided directory')

                $CurrentStep++
                Write-Progress -Id 0 -Activity "Getting the supported files' paths" -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)
                $CollectedFiles = [System.Collections.Generic.HashSet[System.IO.FileInfo]]@([WDACConfig.FileUtility]::GetFilesFast($FolderPath, $FilePath, $null))

                # Make sure the selected directory contains files with the supported extensions
                if (!$CollectedFiles) { Throw 'There are no files in the selected directory that are supported by the WDAC engine.' }

                # Loop through each file
                [WDACConfig.Logger]::Write('Looping through each supported file')

                $CurrentStep++
                Write-Progress -Id 0 -Activity 'Looping through each supported file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # split the file paths by $ThreadsCount which by default is 2
                $SplitArrays = [System.Linq.Enumerable]::Chunk($CollectedFiles, [System.Math]::Ceiling($CollectedFiles.Count / $ThreadsCount))

                # Loop over each split array
                [System.Management.Automation.Job2[]]$Jobs = foreach ($Array in $SplitArrays) {

                    # Create a new ThreadJob for each array of the filepaths to be processed concurrently
                    Start-ThreadJob -ArgumentList @($FinalSimulationResults, $Array, $SignerInfo, $SHA256HashesFromXML, $FilePathRules, $HasFilePathRules, $UnsignedExtensions, $AllSecurityCatalogHashes) -StreamingHost $Host -ScriptBlock {
                        param ($FinalSimulationResults, $Array, $SignerInfo, $SHA256HashesFromXML, $FilePathRules, $HasFilePathRules, $UnsignedExtensions, $AllSecurityCatalogHashes)

                        try {

                            $ErrorActionPreference = 'stop'

                            # only importing the functions that are required in this script block
                            Import-Module -Force -FullyQualifiedName "$([WDACConfig.GlobalVars]::ModuleRootPath)\WDACSimulation\Compare-SignerAndCertificate.psm1"

                            [System.Drawing.Color]$CurrentColor = [System.Drawing.Color]::Violet
                            # Set the progress bar style to use violet color
                            $PSStyle.Progress.Style = "$($PSStyle.Foreground.FromRGB($CurrentColor.R, $CurrentColor.G, $CurrentColor.B))"

                            # The total number of the sub steps for the progress bar to render
                            [System.UInt64]$TotalSubSteps = $Array.Count
                            [System.UInt64]$CurrentSubStep = 0

                            foreach ($CurrentFilePath in $Array) {

                                $CurrentSubStep++
                                try {
                                    Write-Progress -Id ([runspace]::DefaultRunspace.Id) -Activity "Processing file $CurrentSubStep/$TotalSubSteps" -Status "$CurrentFilePath" -PercentComplete ($CurrentSubStep / $TotalSubSteps * 100)
                                }
                                catch {}

                                # Check see if the file's hash exists in the XML file regardless of whether it's signed or not
                                # This is because WDAC policies sometimes have hash rules for signed files too
                                # So here we prioritize being authorized by file hash over being authorized by Signature

                                # Since Get-AppLockerFileInformation doesn't support special characters such as [ and ], and it doesn't have -LiteralPath parameter, we need to escape them ourselves
                                # [System.String]$CurrentFilePathHash = (Get-AppLockerFileInformation -Path $($CurrentFilePath -match '\[|\]' ? ($CurrentFilePath -replace '(\[|\])', '`$1') : $CurrentFilePath) -ErrorAction Stop).hash -replace 'SHA256 0x', ''

                                if ($HasFilePathRules -and $FilePathRules.Contains($CurrentFilePath)) {

                                    [System.Void]$FinalSimulationResults.TryAdd([string]$CurrentFilePath, [WDACConfig.SimulationOutput]::New(
                                ([System.IO.Path]::GetFileName($CurrentFilePath)),
                                            'FilePath',
                                            $true,
                                            $null,
                                            $null,
                                            $null,
                                            $null,
                                            $null,
                                            $null,
                                            'Allowed By File Path',
                                            $null,
                                            $null,
                                            $null,
                                            $null,
                                            $null,
                                            $CurrentFilePath
                                        ))

                                    Continue
                                }

                                try {
                                    [WDACConfig.CodeIntegrityHashes]$CurrentFileHashResult = [WDACConfig.CiFileHash]::GetCiFileHashes($CurrentFilePath)
                                    [System.String]$CurrentFilePathHashSHA256 = $CurrentFileHashResult.SHA256Authenticode
                                    [System.String]$CurrentFilePathHashSHA1 = $CurrentFileHashResult.SHA1Authenticode
                                }
                                catch {

                                    [System.Void]$FinalSimulationResults.TryAdd([string]$CurrentFilePath, [WDACConfig.SimulationOutput]::New(
                                ([System.IO.Path]::GetFileName($CurrentFilePath)),
                                            'Signer',
                                            $false,
                                            $null,
                                            $null,
                                            $null,
                                            $null,
                                            $null,
                                            $null,
                                            'Not processed, Inaccessible file',
                                            $null,
                                            $null,
                                            $null,
                                            $null,
                                            $null,
                                            $CurrentFilePath
                                        ))
                                    Continue
                                }

                                # if the file's hash exists in the XML file then add the file's path to the allowed files and do not check anymore that whether the file is signed or not
                                if ($SHA256HashesFromXML.Contains($CurrentFilePathHashSHA256)) {

                                    [System.Void]$FinalSimulationResults.TryAdd([string]$CurrentFilePath, [WDACConfig.SimulationOutput]::New(
                                ([System.IO.Path]::GetFileName($CurrentFilePath)),
                                            'Hash',
                                            $true,
                                            $null,
                                            $null,
                                            $null,
                                            $null,
                                            $null,
                                            $null,
                                            'Hash Level',
                                            $null,
                                            $null,
                                            $null,
                                            $null,
                                            $null,
                                            $CurrentFilePath
                                        ))
                                }
                                # If the file's extension is not supported by Authenticode and it wasn't allowed by file hash then it's not allowed and no reason to check its signature
                                elseif ($UnsignedExtensions.Contains($CurrentFilePath.Extension)) {

                                    [System.Void]$FinalSimulationResults.TryAdd([string]$CurrentFilePath, [WDACConfig.SimulationOutput]::New(
                                ([System.IO.Path]::GetFileName($CurrentFilePath)),
                                            'Unsigned',
                                            $false,
                                            $null,
                                            $null,
                                            $null,
                                            $null,
                                            $null,
                                            $null,
                                            'Not Allowed',
                                            $null,
                                            $null,
                                            $null,
                                            $null,
                                            $null,
                                            $CurrentFilePath
                                        ))
                                }
                                # If the file's hash does not exist in the supplied XML file, then check its signature
                                else {

                                    try {
                                        [WDACConfig.AllFileSigners[]]$FileSignatureResults = [WDACConfig.AllCertificatesGrabber]::GetAllFileSigners($CurrentFilePath)

                                        # If there is no result then check if the file is allowed by a security catalog
                                        if ($FileSignatureResults.Count -eq 0) {

                                            if (!$NoCatalogScanning) {
                                                $MatchedHashResult = $AllSecurityCatalogHashes[$CurrentFilePathHashSHA1] ?? $AllSecurityCatalogHashes[$CurrentFilePathHashSHA256]
                                            }

                                            if (!$NoCatalogScanning -and $MatchedHashResult) {

                                                [WDACConfig.AllFileSigners]$CatalogSignerDits = ([WDACConfig.AllCertificatesGrabber]::GetAllFileSigners($MatchedHashResult))[0]

                                                # The file is authorized by a security catalog on the system
                                                [System.Void]$FinalSimulationResults.TryAdd([string]$CurrentFilePath, [WDACConfig.SimulationOutput]::New(
                                            ([System.IO.Path]::GetFileName($CurrentFilePath)),
                                                        'Catalog Signed',
                                                        $true,
                                                        $null,
                                                        $null,
                                                        $null,
                                                        $null,
                                                        $null,
                                                        $null,
                                                        'Catalog Hash',
                                                        $MatchedHashResult,
                                                        [WDACConfig.CryptoAPI]::GetNameString($CatalogSignerDits.Chain.ChainElements.Certificate[0].Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $false),
                                                        [WDACConfig.CryptoAPI]::GetNameString($CatalogSignerDits.Chain.ChainElements.Certificate[0].Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $true),
                                                        $CatalogSignerDits.Chain.ChainElements.Certificate[0].NotAfter,
                                                        [WDACConfig.CertificateHelper]::GetTBSCertificate($CatalogSignerDits.Chain.ChainElements.Certificate[0]),
                                                        $CurrentFilePath
                                                    ))
                                            }
                                            else {

                                                # The file is not signed and is not allowed by hash
                                                [System.Void]$FinalSimulationResults.TryAdd([string]$CurrentFilePath, [WDACConfig.SimulationOutput]::New(
                                            ([System.IO.Path]::GetFileName($CurrentFilePath)),
                                                        'Unsigned',
                                                        $false,
                                                        $null,
                                                        $null,
                                                        $null,
                                                        $null,
                                                        $null,
                                                        $null,
                                                        'Not Allowed',
                                                        $null,
                                                        $null,
                                                        $null,
                                                        $null,
                                                        $null,
                                                        $CurrentFilePath
                                                    ))
                                            }
                                        }
                                        else {
                                            # Use the Compare-SignerAndCertificate function to process it
                                            $ComparisonResult = Compare-SignerAndCertificate -SimulationInput ([WDACConfig.SimulationInput]::New(
                                                    $CurrentFilePath, # Path of the signed file
                                                    [WDACConfig.GetCertificateDetails]::Get($FileSignatureResults), # Get all of the details of all certificates of the signed file
                                                    $SignerInfo, # The entire Signer Info of the WDAC Policy file
                                                    $FileSignatureResults.Signer.SignerInfos.Certificate.EnhancedKeyUsageList.ObjectId # The EKU OIDs of the primary signer of the file, just like the output of the Get-AuthenticodeSignature cmdlet, the ones that WDAC policy uses for EKU-based authorization
                                                ))

                                            [System.Void]$FinalSimulationResults.TryAdd($CurrentFilePath, $ComparisonResult)
                                        }
                                    }
                                    # Handle the HashMismatch situations
                                    catch [WDACConfig.ExceptionHashMismatchInCertificate] {

                                        [System.Void]$FinalSimulationResults.TryAdd([string]$CurrentFilePath, [WDACConfig.SimulationOutput]::New(
                                    ([System.IO.Path]::GetFileName($CurrentFilePath)),
                                                'Signer',
                                                $false,
                                                $null,
                                                $null,
                                                $null,
                                                $null,
                                                $null,
                                                $null,
                                                'Hash Mismatch',
                                                $null,
                                                $null,
                                                $null,
                                                $null,
                                                $null,
                                                $CurrentFilePath
                                            ))
                                    }
                                    # Handle any other error by storing the file path and the reason for the error to display to the user

                                    catch {
                                        # If the file is signed but has unknown signature status
                                        [System.Void]$FinalSimulationResults.TryAdd([string]$CurrentFilePath, [WDACConfig.SimulationOutput]::New(
                                    ([System.IO.Path]::GetFileName($CurrentFilePath)),
                                                'Signer',
                                                $false,
                                                $null,
                                                $null,
                                                $null,
                                                $null,
                                                $null,
                                                $null,
                                                "UnknownError: $_",
                                                $null,
                                                $null,
                                                $null,
                                                $null,
                                                $null,
                                                $CurrentFilePath
                                            ))
                                    }
                                }
                            }
                        }
                        catch {
                            throw $_
                        }
                        finally {
                            try {
                                # Complete the nested progress bar whether there was an error or not
                                Write-Progress -Id ([runspace]::DefaultRunspace.Id) -Activity 'All of the files have been processed.' -Completed
                            }
                            catch {}
                        }
                    } -ThrottleLimit $ThreadsCount
                }

                # Wait for all jobs, grab any error that might've ocurred in them and then remove them
                if ($Jobs.count -gt 0) {
                    $null = Wait-Job -Job $Jobs
                    Receive-Job -Job $Jobs
                    Remove-Job -Job $Jobs
                }

            }

            $CurrentStep++
            Write-Progress -Id 0 -Activity 'Preparing the output' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            # If the user selected the -BooleanOutput switch, then return a boolean value and don't display any more output
            if ($BooleanOutput) {

                # Get all of the allowed files
                $AllAllowedRules = $FinalSimulationResults.Values.Where({ $_.IsAuthorized -eq $true })
                # Get all of the blocked files
                $BlockedRules = $FinalSimulationResults.Values.Where({ $_.IsAuthorized -eq $false })

                [WDACConfig.Logger]::Write("Allowed files: $($AllAllowedRules.count)")
                [WDACConfig.Logger]::Write("Blocked files: $($BlockedRules.count)")

                # If the array of allowed files is not empty
                if (-NOT ([System.String]::IsNullOrWhiteSpace($AllAllowedRules))) {

                    # If the array of blocked files is empty
                    if ([System.String]::IsNullOrWhiteSpace($BlockedRules)) {
                        Return $true
                    }
                    else {
                        Return $false
                    }
                }
                else {
                    Return $false
                }
            }

            # Export the output as CSV
            if ($CSVOutput) {
                $FinalSimulationResults.Values | Sort-Object -Property IsAuthorized -Descending | Export-Csv -LiteralPath (Join-Path -Path ([WDACConfig.GlobalVars]::UserConfigDir) -ChildPath "WDAC Simulation Output $(Get-Date -Format "MM-dd-yyyy 'at' HH-mm-ss").csv") -Force
            }

            # Change the color of the Table header to SkyBlue
            $PSStyle.Formatting.TableHeader = "$($PSStyle.Foreground.FromRGB(135,206,235))"

            if ($FinalSimulationResults.Count -gt 10000) {
                # If the result is too big and the user forgot to use CSV Output then output everything to CSV instead of trying to display on the console
                if (!$CSVOutput) {
                    $FinalSimulationResults.Values | Sort-Object -Property IsAuthorized -Descending | Export-Csv -LiteralPath (Join-Path -Path ([WDACConfig.GlobalVars]::UserConfigDir) -ChildPath "WDAC Simulation Output $(Get-Date -Format "MM-dd-yyyy 'at' HH-mm-ss").csv") -Force
                }
                Return "The number of files is too many to display on the console. Saving the results in a CSV file in '$((Join-Path -Path ([WDACConfig.GlobalVars]::UserConfigDir) -ChildPath "WDAC Simulation Output $(Get-Date -Format "MM-dd-yyyy 'at' HH-mm-ss").csv"))'"
            }

            # Return the final main output array as a table
            Return $FinalSimulationResults.Values | Select-Object -Property 'Path',
            @{
                Label      = 'Source'
                Expression =
                { switch ($_.Source) {
                        { $_ -eq 'Signer' } { $Color = "$($PSStyle.Foreground.FromRGB(152,255,152))" }
                        { $_ -eq 'Hash' } { $Color = "$($PSStyle.Foreground.FromRGB(255,255,49))" }
                        { $_ -eq 'Unsigned' } { $Color = "$($PSStyle.Foreground.FromRGB(255,20,147))" }
                    }
                    "$Color$($_.Source)$($PSStyle.Reset)" # Use PSStyle to reset the color
                }
            },
            @{
                Label      = 'IsAuthorized'
                Expression =
                {
                    switch ($_.IsAuthorized) {
                        { $_ -eq $true } { $Color = "$($PSStyle.Foreground.FromRGB(255,0,255))"; break }
                        { $_ -eq $false } { $Color = "$($PSStyle.Foreground.FromRGB(255,165,0))$($PSStyle.Blink)"; break }
                    }
                    "$Color$($_.IsAuthorized)$($PSStyle.Reset)" # Use PSStyle to reset the color
                }
            },
            @{
                Label      = 'MatchCriteria'
                Expression = {
                    # If the MatchCriteria starts with 'UnknownError', truncate it to 50 characters. The full string will be displayed in the CSV output file. If it does not then just display it as it is
                    $_.MatchCriteria -match 'UnknownError' ? $_.MatchCriteria.Substring(0, 50) + '...' : "$($_.MatchCriteria)"
                }
            },
            @{
                Label      = 'SpecificFileName'
                Expression = {
                    $_.SpecificFileNameLevelMatchCriteria
                }
            } | Sort-Object -Property IsAuthorized | Format-Table

        }
        catch {
            throw $_
        }
        finally {
            Write-Progress -Id 0 -Activity 'WDAC Simulation completed.' -Completed
            # If the -Log switch is used, then stop the stopwatch and the transcription
            if ($Log) { Stop-Log }
        }
    }

    <#
.SYNOPSIS
    Simulates the deployment of the WDAC policy. It can produce a very detailed CSV file that contains the output of the simulation.
    On the console, it can display a table that shows the file path, source, MatchCriteria, and whether the file is allowed or not.
    The console results are color coded for easier reading.

    Properties explanation:

    FilePath:       The name of the file gathered from its full path. (the actual long path of the file is not displayed in the console output, only in the CSV file)
    Source:         The source of the file's MatchCriteria, e.g., 'Signer' (For signed files only), 'Hash' (For signed and unsigned files), 'Unsigned' (For unsigned files only)
    MatchCriteria:  The reason the file is allowed or not. For files authorized by FilePublisher level, it will show the specific file name level that the file is authorized by. (https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#table-3--specificfilenamelevel-options)
    IsAuthorized:   A boolean value that indicates whether the file is allowed or not.
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Invoke-WDACSimulation
.DESCRIPTION
    Simulates the deployment of the WDAC policy by analyzing a folder (recursively) or files and checking which of the detected files are allowed by a user selected policy xml file
.PARAMETER FolderPath
    Provide path to a folders that you want WDAC simulation to run against

    Takes the paths of the folders literally as typed including Special characters such as [ and ]

    Does not support wildcards
.PARAMETER FilePath
    Provide path to files that you want WDAC simulation to run against

    Takes the paths of the files literally as typed including Special characters such as [ and ]

    Does not support wildcards
.PARAMETER XmlFilePath
    Provide path to a policy xml file that you want the cmdlet to simulate its deployment and running files against it

    Takes the paths of the files literally as typed including Special characters such as [ and ]

    Does not support wildcards
.PARAMETER Log
    Use this switch to start a transcript of the WDAC simulation and log everything displayed on the screen.
    Use -Verbose parameter to produce more output on the console during the simulation operation.
    The log file is saved in the WDACConfig folder: C:\Program Files\WDACConfig
.PARAMETER NoCatalogScanning
    Bypass the scanning of the security catalogs on the system
.PARAMETER CatRootPath
    Provide path(s) to directories where security catalog .cat files are located. If not provided, the default path is C:\Windows\System32\CatRoot
.PARAMETER CSVOutput
    Exports the output to a CSV file. The CSV output is saved in the WDACConfig folder: C:\Program Files\WDACConfig
.PARAMETER ThreadsCount
    The number of the concurrent/parallel tasks to use when performing WDAC Simulation.
    By default it uses 2 parallel tasks.
    Max is the number of your system's CPU cores.
    Min is 1.
    If you enter a number higher than your system's CPU cores, it will be set to your system's CPU cores count.
.PARAMETER Verbose
    Shows verbose output
.PARAMETER BooleanOutput
    Returns a boolean value instead of displaying the object output
.PARAMETER SkipVersionCheck
    Bypass the online version check - only to be used in rare cases
.INPUTS
    System.IO.FileInfo[]
    System.IO.DirectoryInfo[]
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.Collections.Generic.List[WDACConfig.SimulationOutput]
    System.Boolean
.EXAMPLE
    Invoke-WDACSimulation -FolderPath 'C:\Windows\System32' -XmlFilePath 'C:\Users\HotCakeX\Desktop\Policy.xml'
    This example will simulate the deployment of the policy.xml file against the C:\Windows\System32 folder
.NOTES
    WDAC templates such as 'Default Windows' and 'Allow Microsoft' don't have CertPublisher element in their Signers because they don't target a leaf certificate,
    thus they weren't created using FilePublisher level, they were created using Publisher or Root certificate levels to allow Microsoft's wellknown certificates.
#>
}
