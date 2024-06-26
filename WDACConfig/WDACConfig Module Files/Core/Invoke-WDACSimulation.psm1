Function Invoke-WDACSimulation {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[WDACConfig.SimulationOutput]], [System.Boolean])]
    Param(
        [Alias('X')]
        [ValidateScript({ Test-CiPolicy -XmlFile $_ })]
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath,

        [Alias('D')]
        [ValidateScript({ [System.IO.Directory]::Exists($_) }, ErrorMessage = 'The path you selected is not a valid folder path.')]
        [Parameter(Mandatory = $false)][System.IO.DirectoryInfo[]]$FolderPath,

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

        [Alias('Cat')]
        [ValidateScript({ [System.IO.Directory]::Exists($_) }, ErrorMessage = 'The path you selected is not a valid folder path.')]
        [Parameter(Mandatory = $false)][System.IO.DirectoryInfo[]]$CatRootPath,

        [Alias('S')]
        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )
    Begin {
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false
        [System.Boolean]$Debug = $PSBoundParameters.Debug.IsPresent ? $true : $false
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -Force -FullyQualifiedName @(
            "$ModuleRootPath\Shared\Update-Self.psm1",
            "$ModuleRootPath\Shared\Write-ColorfulText.psm1",
            "$ModuleRootPath\WDACSimulation\Compare-SignerAndCertificate.psm1",
            "$ModuleRootPath\WDACSimulation\Get-FileRuleOutput.psm1",
            "$ModuleRootPath\WDACSimulation\Get-SignerInfo.psm1",
            "$ModuleRootPath\WDACSimulation\Get-CertificateDetails.psm1"
        )

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-Self -InvocationStatement $MyInvocation.Statement }

        # Start the transcript if the -Log switch is used and create a function to stop the transcript and the stopwatch at the end
        if ($Log) {
            Start-Transcript -IncludeInvocationHeader -LiteralPath (Join-Path -Path $UserConfigDir -ChildPath "WDAC Simulation Log $(Get-Date -Format "MM-dd-yyyy 'at' HH-mm-ss").txt")

            # Create a new stopwatch object to measure the execution time
            Write-Verbose -Message 'Starting the stopwatch...'
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

                Write-Verbose -Message 'Stopping the stopwatch'
                $StopWatch.Stop()
                Write-Verbose -Message "WDAC Simulation for $TotalSubSteps files completed in $($StopWatch.Elapsed.Hours) Hours - $($StopWatch.Elapsed.Minutes) Minutes - $($StopWatch.Elapsed.Seconds) Seconds - $($StopWatch.Elapsed.Milliseconds) Milliseconds - $($StopWatch.Elapsed.Microseconds) Microseconds - $($StopWatch.Elapsed.Nanoseconds) Nanoseconds"

                Write-Verbose -Message 'Stopping the transcription'
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
        [System.Boolean]$ShouldExit = $false

        # Get the content of the XML file
        [System.String]$XMLContent = Get-Content -LiteralPath $XmlFilePath -Raw

        #Region Making Sure No AllowAll Rule Exists

        if ($XMLContent -match '<Allow ID="ID_ALLOW_.*" FriendlyName=".*" FileName="\*".*/>') {
            Write-Verbose -Message "The supplied XML file '$($XmlFilePath.Name)' contains a rule that allows all files."

            # Set a flag to exit the subsequent blocks
            $ShouldExit = $true

            # Exit the Begin block
            Return
        }

        #Endregion Making Sure No AllowAll Rule Exists

        # Get the signer information from the XML
        [WDACConfig.Signer[]]$SignerInfo = Get-SignerInfo -XML ([System.Xml.XmlDocument]$XMLContent)

        # The list that contains any and all of the Simulation results
        $FinalSimulationResults = New-Object -TypeName 'System.Collections.Generic.List[WDACConfig.SimulationOutput]'

        # Extensions that are not supported by Authenticode. So if these files are not allowed by hash, they are not allowed at all
        $UnsignedExtensions = [System.Collections.Generic.HashSet[System.String]]::new(
            [System.String[]] ('.ocx', '.bat', '.bin'),
            # Make it case-insensitive
            [System.StringComparer]::InvariantCultureIgnoreCase
        )

        #Region FilePath Rule Checking
        Write-Verbose -Message 'Checking see if the XML policy has any FilePath rules'
        $FilePathRules = [System.Collections.Generic.HashSet[System.String]]@([WDACConfig.XmlFilePathExtractor]::GetFilePaths($XmlFilePath))

        [System.Boolean]$HasFilePathRules = $false
        if ($FilePathRules.Count -gt 0) {
            $HasFilePathRules = $true
        }
        #Endregion FilePath Rule Checking
    }

    process {
        try {
            # Exit the Process block
            if ($ShouldExit) { Return }

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
            Write-Verbose -Message 'Getting the Sha256 Hash values of all the file rules based on hash in the supplied xml policy file'

            $CurrentStep++
            Write-Progress -Id 0 -Activity 'Getting the Sha256 Hash values from the XML file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            $SHA256HashesFromXML = [System.Collections.Generic.HashSet[System.String]]@((Get-FileRuleOutput -Xml ([System.Xml.XmlDocument]$XMLContent)).HashValue)

            # Get all of the file paths of the files that WDAC supports, from the user provided directory
            Write-Verbose -Message 'Getting all of the file paths of the files that WDAC supports, from the user provided directory'

            $CurrentStep++
            Write-Progress -Id 0 -Activity "Getting the supported files' paths" -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)
            $CollectedFiles = [System.Collections.Generic.HashSet[System.IO.FileInfo]]@([WDACConfig.FileUtility]::GetFilesFast($FolderPath, $FilePath, $null))

            # Make sure the selected directory contains files with the supported extensions
            if (!$CollectedFiles) { Throw 'There are no files in the selected directory that are supported by the WDAC engine.' }

            try {

                #Region Cyan/Violet Progress Bar

                # Backing up PS Formatting Styles
                [System.Collections.Hashtable]$OriginalStyle = @{}
                $PSStyle.Progress | Get-Member -MemberType Property | ForEach-Object -Process {
                    $OriginalStyle[$_.Name] = $PSStyle.Progress.$($_.Name)
                }

                # Define a global variable to store the current color index
                [System.UInt16]$Global:ColorIndex = 0

                # Create a timer object that fires every 3 seconds
                [System.Timers.Timer]$RainbowTimer = New-Object System.Timers.Timer
                $RainbowTimer.Interval = 3000 # milliseconds
                $RainbowTimer.AutoReset = $true # repeat until stopped

                # Register an event handler that changes Write-Progress' style every time the timer elapses
                [System.Management.Automation.PSEventJob]$EventHandler = Register-ObjectEvent -InputObject $RainbowTimer -EventName Elapsed -Action {

                    # An array of colors
                    [System.Drawing.Color[]]$Colors = @(
                        [System.Drawing.Color]::Cyan
                        [System.Drawing.Color]::Violet
                    )

                    $Global:ColorIndex++
                    if ($Global:ColorIndex -ge $Colors.Length) {
                        $Global:ColorIndex = 0
                    }

                    # Get the current color from the array
                    [System.Drawing.Color]$CurrentColor = $Colors[$Global:ColorIndex]
                    # Set the progress bar style to use the current color
                    $PSStyle.Progress.Style = "$($PSStyle.Foreground.FromRGB($CurrentColor.R, $CurrentColor.G, $CurrentColor.B))"
                }

                # Start the timer
                $RainbowTimer.Start()

                #Endregion Cyan/Violet Progress Bar

                # Loop through each file
                Write-Verbose -Message 'Looping through each supported file'

                $CurrentStep++
                Write-Progress -Id 0 -Activity 'Looping through each supported file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # The total number of the sub steps for the progress bar to render
                [System.UInt64]$TotalSubSteps = $CollectedFiles.Count
                [System.UInt64]$CurrentSubStep = 0

                foreach ($CurrentFilePath in $CollectedFiles) {

                    Write-Verbose -Message "Processing file: $CurrentFilePath"

                    $CurrentSubStep++
                    Write-Progress -Id 1 -ParentId 0 -Activity "Processing file $CurrentSubStep/$TotalSubSteps" -Status "$CurrentFilePath" -PercentComplete ($CurrentSubStep / $TotalSubSteps * 100)

                    # Check see if the file's hash exists in the XML file regardless of whether it's signed or not
                    # This is because WDAC policies sometimes have hash rules for signed files too
                    # So here we prioritize being authorized by file hash over being authorized by Signature

                    # Since Get-AppLockerFileInformation doesn't support special characters such as [ and ], and it doesn't have -LiteralPath parameter, we need to escape them ourselves
                    # [System.String]$CurrentFilePathHash = (Get-AppLockerFileInformation -Path $($CurrentFilePath -match '\[|\]' ? ($CurrentFilePath -replace '(\[|\])', '`$1') : $CurrentFilePath) -ErrorAction Stop).hash -replace 'SHA256 0x', ''

                    if ($HasFilePathRules -and $FilePathRules.Contains($CurrentFilePath)) {

                        $FinalSimulationResults.Add([WDACConfig.SimulationOutput]::New(
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

                    Write-Verbose -Message 'Calculating the file hashes'
                    # Get-CiFileHashes is faster, natively supports -LiteralPath for special characters in file path, and also supports non-conformant files by automatically getting their flat hashes
                    try {
                        $CurrentFileHashResult = Get-CiFileHashes -FilePath $CurrentFilePath -SkipVersionCheck
                        [System.String]$CurrentFilePathHashSHA256 = $CurrentFileHashResult.SHA256Authenticode
                        [System.String]$CurrentFilePathHashSHA1 = $CurrentFileHashResult.SHA1Authenticode
                    }
                    catch {

                        $FinalSimulationResults.Add([WDACConfig.SimulationOutput]::New(
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
                        Write-Verbose -Message 'Hash of the file exists in the supplied XML file'

                        $FinalSimulationResults.Add([WDACConfig.SimulationOutput]::New(
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
                        Write-Verbose -Message 'The file is not signed and is not allowed by hash'

                        $FinalSimulationResults.Add([WDACConfig.SimulationOutput]::New(
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
                            [WDACConfig.AllCertificatesGrabber.AllFileSigners[]]$FileSignatureResults = [WDACConfig.AllCertificatesGrabber.WinTrust]::GetAllFileSigners($CurrentFilePath)

                            # If there is no result then check if the file is allowed by a security catalog
                            if ($FileSignatureResults.Count -eq 0) {

                                if (!$NoCatalogScanning) {
                                    $MatchedHashResult = $AllSecurityCatalogHashes[$CurrentFilePathHashSHA1] ?? $AllSecurityCatalogHashes[$CurrentFilePathHashSHA256]
                                }

                                if (!$NoCatalogScanning -and $MatchedHashResult) {

                                    [WDACConfig.AllCertificatesGrabber.AllFileSigners]$CatalogSignerDits = ([WDACConfig.AllCertificatesGrabber.WinTrust]::GetAllFileSigners($MatchedHashResult))[0]

                                    Write-Verbose -Message 'The file is authorized by a security catalog on the system'

                                    $FinalSimulationResults.Add([WDACConfig.SimulationOutput]::New(
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

                                    Write-Verbose -Message 'The file is not signed and is not allowed by hash'

                                    $FinalSimulationResults.Add([WDACConfig.SimulationOutput]::New(
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
                                    (Get-CertificateDetails -CompleteSignatureResult $FileSignatureResults), # Get all of the details of all certificates of the signed file
                                        $SignerInfo, # The entire Signer Info of the WDAC Policy file
                                        $FileSignatureResults.Signer.SignerInfos.Certificate.EnhancedKeyUsageList.ObjectId # The EKU OIDs of the primary signer of the file, just like the output of the Get-AuthenticodeSignature cmdlet, the ones that WDAC policy uses for EKU-based authorization
                                    ))

                                $FinalSimulationResults.Add($ComparisonResult)
                            }
                        }
                        # Handle the HashMismatch situations
                        catch [WDACConfig.AllCertificatesGrabber.ExceptionHashMismatchInCertificate] {
                            Write-Warning -Message "The file: $CurrentFilePath has hash mismatch, it is most likely tampered."

                            $FinalSimulationResults.Add([WDACConfig.SimulationOutput]::New(
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
                            Write-Verbose -Message 'The file has unknown signature status'

                            $FinalSimulationResults.Add([WDACConfig.SimulationOutput]::New(
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
                # If the -Log switch is used, then stop the stopwatch and the transcription
                if ($Log) { Stop-Log }

                # Throw whatever error that was encountered
                throw $_
            }
            finally {
                # Complete the nested progress bar whether there was an error or not
                Write-Progress -Id 1 -Activity 'All of the files have been processed.' -Completed

                # Stop the timer for progress bar color
                $RainbowTimer.Stop()

                # Unregister the event handler for progress bar color
                Unregister-Event -SourceIdentifier $EventHandler.Name -Force

                # Remove the event handler's job
                Remove-Job -Job $EventHandler -Force

                # Restore PS Formatting Styles for progress bar
                $OriginalStyle.Keys | ForEach-Object -Process {
                    $PSStyle.Progress.$_ = $OriginalStyle[$_]
                }
            }

            $CurrentStep++
            Write-Progress -Id 0 -Activity 'Preparing the output' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            # If the user selected the -BooleanOutput switch, then return a boolean value and don't display any more output
            if ($BooleanOutput) {

                # Get all of the allowed files
                $AllAllowedRules = $FinalSimulationResults.Where({ $_.IsAuthorized -eq $true })
                # Get all of the blocked files
                $BlockedRules = $FinalSimulationResults.Where({ $_.IsAuthorized -eq $false })

                Write-Verbose -Message "Allowed files: $($AllAllowedRules.count)"
                Write-Verbose -Message "Blocked files: $($BlockedRules.count)"

                # If the array of allowed files is not empty
                if (-NOT ([System.String]::IsNullOrWhiteSpace($AllAllowedRules))) {

                    # If the array of blocked files is empty
                    if ([System.String]::IsNullOrWhiteSpace($BlockedRules)) {

                        # If the -Log switch is used, then stop the stopwatch and the transcription
                        if ($Log) { Stop-Log }

                        Return $true
                    }
                    else {
                        # If the -Log switch is used, then stop the stopwatch and the transcription
                        if ($Log) { Stop-Log }

                        Return $false
                    }
                }
                else {
                    # If the -Log switch is used, then stop the stopwatch and the transcription
                    if ($Log) { Stop-Log }

                    Return $false
                }
            }

            # Export the output as CSV
            if ($CSVOutput) {
                $FinalSimulationResults | Sort-Object -Property IsAuthorized -Descending | Export-Csv -LiteralPath (Join-Path -Path $UserConfigDir -ChildPath "WDAC Simulation Output $(Get-Date -Format "MM-dd-yyyy 'at' HH-mm-ss").csv") -Force
            }

            # Change the color of the Table header to SkyBlue
            $PSStyle.Formatting.TableHeader = "$($PSStyle.Foreground.FromRGB(135,206,235))"

            # If the -Log switch is used, then stop the stopwatch and the transcription
            if ($Log) { Stop-Log }

            # Return the final main output array as a table
            Return $FinalSimulationResults | Select-Object -Property 'Path',
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
        finally {
            Write-Progress -Id 0 -Activity 'WDAC Simulation completed.' -Completed
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
    MatchCriteria:  The reason the file is allowed or not. For files authorized by FilePublisher level, it will show the specific file name level that the file is authorized by. (https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create#table-3--specificfilenamelevel-options)
    IsAuthorized:   A boolean value that indicates whether the file is allowed or not.
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Invoke-WDACSimulation
.DESCRIPTION
    Simulates the deployment of the WDAC policy by analyzing a folder (recursively) or files and checking which of the detected files are allowed by a user selected policy xml file
.COMPONENT
    Windows Defender Application Control
    WDACConfig
.FUNCTIONALITY
    Simulates the deployment of the WDAC policy
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

Register-ArgumentCompleter -CommandName 'Invoke-WDACSimulation' -ParameterName 'FolderPath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterMultipleFolderPathsPicker)
Register-ArgumentCompleter -CommandName 'Invoke-WDACSimulation' -ParameterName 'CatRootPath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterMultipleFolderPathsPicker)
Register-ArgumentCompleter -CommandName 'Invoke-WDACSimulation' -ParameterName 'XmlFilePath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterXmlFilePathsPicker)
Register-ArgumentCompleter -CommandName 'Invoke-WDACSimulation' -ParameterName 'FilePath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterMultipleAnyFilePathsPicker)

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD1MU2Kcdljjc5a
# qffc3oA3Qz4Wt4Ex01QHNh3vWh5y8aCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgZsNWsQaxJrE4u9f3liaRJbc9MslhY9a7OSomKlpqKHswDQYJKoZIhvcNAQEB
# BQAEggIAaUnB2iHzqjdqRSMCUt+d3GE/lUEGkN8hkgiar6R/zWdd8LTBRjwQyDGy
# T6fX5XVVGloN5HFgA7W04oC/fTAyoAMbKAM/fH9BuMlmH/sjGxFP+rN2hgB076Wt
# Yrj0urzaUjsDs9F/x0bZ7PLSixKYgtNjurd38FX72YuvVGGuvSwrYFZhMOoSOIrK
# O6ki1ha7///GUUTXOzqQcFb84+YE0cTANtRXwhxgkuRtiNfSknS47gNMsVn16hy0
# Mv1PzFTMjErmTiUctYs6PsEC/AeKXNcbIwIGxL2JeapFKfi/qjqdMz2sF6hMMW7/
# UzmXf5z2Dd3UEWM92PUBphirJOU0o5BPLTg3BYYzd7gK4LpLDKJIoJ6yHOs2Ih+/
# Rwt9gojZeJpyvfTSm06pJB2lDTZzILoxHbQ0og9FOASkblrP4Lxz6k7BpfZ9R4Ah
# 6dwOC3k+7Qq/xGK3+6I+/Xf35ApQBzGj5c1dvfWGWYUmOaICP/vv5my8CZzQ/y9c
# qVzzqM1TAvd/l8xo5I5M4ahFRGDwTemniKMb9kODODRy0cKw5mFSXDMIGWOHSWye
# Ad/sdOR719ooaX71LbjEu9P+U/2R15kP4soBEAccVuOFQz4WTV3SXZWiziKKvgM0
# sQKdIwezhfC2VXj7y8Ff6OntqEn3WlPJbRqbghy18CIlgiLi9iU=
# SIG # End signature block
