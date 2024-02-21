Function ConvertTo-WDACPolicy {
    [CmdletBinding(
        DefaultParameterSetName = 'In-Place Upgrade'
    )]
    param(
        [ValidateScript({ Test-CiPolicy -XmlFile $_ })]
        [Parameter(Mandatory = $false, ParameterSetName = 'In-Place Upgrade')]
        [System.IO.FileInfo]$PolicyToAddLogsTo,

        [ValidateScript({ Test-CiPolicy -XmlFile $_ })]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy File Association')]
        [System.IO.FileInfo]$BasePolicyFile,

        [ArgumentCompleter({
                param($CommandName, $parameterName, $wordToComplete, $CommandAst, $fakeBoundParameters)

                [System.String[]]$PolicyGUIDs = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { ($_.IsSystemPolicy -ne 'True') -and ($_.PolicyID -eq $_.BasePolicyID) }).PolicyID

                $Existing = $CommandAst.FindAll({
                        $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    }, $false).Value

                $PolicyGUIDs | Where-Object -FilterScript { $_ -notin $Existing } | ForEach-Object -Process { "'{0}'" -f $_ }
            })]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy GUID Association')]
        [System.Guid]$BasePolicyGUID,

        [ArgumentCompleter({
                param($CommandName, $parameterName, $wordToComplete, $CommandAst, $fakeBoundParameters)

                [System.String[]]$Policies = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { ($_.FriendlyName) -and ($_.PolicyID -eq $_.BasePolicyID) }).FriendlyName

                $Existing = $CommandAst.FindAll({
                        $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    }, $false).Value

                $Policies | Where-Object -FilterScript { $_ -notin $Existing } | ForEach-Object -Process { "'{0}'" -f $_ }
            })]
        [Parameter(Mandatory = $false, ParameterSetName = 'In-Place Upgrade')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy GUID Association')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy File Association')]
        [System.String[]]$FilterByPolicyNames,

        [Parameter(Mandatory = $false, ParameterSetName = 'In-Place Upgrade')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy GUID Association')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy File Association')]
        [System.UInt64]$MinutesAgo,

        [Parameter(Mandatory = $false, ParameterSetName = 'In-Place Upgrade')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy GUID Association')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy File Association')]
        [System.UInt64]$HoursAgo,

        [Parameter(Mandatory = $false, ParameterSetName = 'In-Place Upgrade')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy GUID Association')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy File Association')]
        [System.UInt64]$DaysAgo,

        [Parameter(Mandatory = $false, ParameterSetName = 'In-Place Upgrade')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy GUID Association')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy File Association')]
        [System.Management.Automation.SwitchParameter]$KernelModeOnly,

        [ValidateSet('Audit', 'Blocked')]
        [Parameter(Mandatory = $false, ParameterSetName = 'In-Place Upgrade')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy GUID Association')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy File Association')]
        [System.String]$LogType = 'Audit',

        [Parameter(Mandatory = $false, ParameterSetName = 'In-Place Upgrade')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy GUID Association')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy File Association')]
        [System.Management.Automation.SwitchParameter]$Deploy,

        [Parameter(Mandatory = $false, ParameterSetName = 'In-Place Upgrade')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy GUID Association')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy File Association')]
        [System.Management.Automation.SwitchParameter]$ExtremeVisibility,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )

    begin {
        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null

        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Importing the required sub-modules
        Write-Verbose -Message 'ConvertTo-WDACPolicy: Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Update-self.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Write-ColorfulText.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Receive-CodeIntegrityLogs.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Edit-CiPolicyRuleOptions.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\New-AppxPackageCiPolicy.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\New-EmptyPolicy.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-RuleRefs.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-FileRules.psm1" -Force

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-self -InvocationStatement $MyInvocation.Statement }

        if ($MinutesAgo -or $HoursAgo -or $DaysAgo) {
            # Convert MinutesAgo, HoursAgo, and DaysAgo to DateTime objects
            [System.DateTime]$CurrentDateTime = Get-Date
            [System.DateTime]$StartTime = $CurrentDateTime.AddMinutes(-$MinutesAgo) -as [System.DateTime]
            [System.DateTime]$StartTime = $StartTime.AddHours(-$HoursAgo) -as [System.DateTime]
            [System.DateTime]$StartTime = $StartTime.AddDays(-$DaysAgo) -as [System.DateTime]
        }

        # To store the logs that user selects using GUI
        [PSCustomObject[]]$SelectedLogs = @()

        # The paths to the policy files to be merged together to produce the final Supplemental policy
        [System.String[]]$PolicyFilesToMerge = @()

        # Initializing some flags
        [System.Boolean]$HasKernelFiles = $false
        [System.Boolean]$HasNormalFiles = $false

        # Save the current date in a variable as string
        [System.String]$CurrentDate = $(Get-Date -Format "MM-dd-yyyy 'at' HH-mm-ss")

        # Initialize the flag indicating whether the cmdlet should exit
        [System.Boolean]$ShouldExit = $false
    }

    Process {

        [PSCustomObject[]]$EventsToDisplay = Receive-CodeIntegrityLogs -PostProcessing OnlyExisting -PolicyName:$FilterByPolicyNames -Date:$StartTime -Type:$LogType |
        Select-Object -Property @{
            Label      = 'File Name'
            Expression = {
                # Can't use Get-Item or Get-ChildItem because the file might not exist on the disk
                # Can't use Split-Path -LiteralPath with -Leaf parameter because not supported
                [System.String]$TempPath = Split-Path -LiteralPath $_.'File Name'
                $_.'File Name'.Replace($TempPath, '').TrimStart('\')
            }
        },
        'TimeCreated',
        'PolicyName',
        'ProductName',
        'FileVersion',
        'OriginalFileName',
        'FileDescription',
        'InternalName',
        'PackageFamilyName',
        @{
            Label      = 'Full Path'
            Expression = { $_.'File Name' }
        },
        'Validated Signing Level',
        'Requested Signing Level',
        'SI Signing Scenario',
        'UserId',
        'Publishers',
        'SHA256 Hash',
        'SHA256 Flat Hash',
        'SHA1 Hash',
        'SHA1 Flat Hash',
        'PolicyGUID',
        'PolicyHash',
        'ActivityId',
        'Process Name',
        'UserWriteable',
        'PolicyID',
        'Status',
        'USN',
        'SignerInfo'

        # If the KernelModeOnly switch is used, then filter the events by the 'Requested Signing Level' property
        if ($KernelModeOnly) {
            $EventsToDisplay = $EventsToDisplay | Where-Object -FilterScript { $_.'SI Signing Scenario' -eq 'Kernel-Mode' }
        }

        # Sort the events by TimeCreated in descending order
        [PSCustomObject[]]$EventsToDisplay = $EventsToDisplay | Sort-Object -Property TimeCreated -Descending

        if (($null -eq $EventsToDisplay) -and ($EventsToDisplay.Count -eq 0)) {
            Write-ColorfulText -Color HotPink -InputText 'No logs were found to display. Exiting...'

            $ShouldExit = $true
            return
        }

        #Region Out-GridView properties visibility settings

        # If the ExtremeVisibility switch is used, then display all the properties of the logs without any filtering
        if (-NOT $ExtremeVisibility) {

            [System.String[]]$PropertiesToDisplay = @('File Name', 'TimeCreated', 'PolicyName', 'ProductName', 'FileVersion', 'OriginalFileName', 'FileDescription', 'InternalName', 'PackageFamilyName', 'Full Path', 'SI Signing Scenario', 'UserId', 'Publishers')

            # Create a PSPropertySet object that contains the names of the properties to be visible
            # Used for Out-GridView display
            # https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.pspropertyset
            # https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-pscustomobject#using-defaultpropertyset-the-long-way
            $Visible = [System.Management.Automation.PSPropertySet]::new(
                'DefaultDisplayPropertySet', # the name of the property set
                $PropertiesToDisplay # the names of the properties to be visible
            )

            # Add the PSPropertySet object to the PSStandardMembers member set of each element of the $EventsToDisplay array
            foreach ($Element in $EventsToDisplay) {
                $Element | Add-Member -MemberType 'MemberSet' -Name 'PSStandardMembers' -Value $Visible
            }
        }

        #Endregion Out-GridView properties visibility settings

        <#
        Will enable this section once this issue has been fixed: https://github.com/PowerShell/GraphicalTools/issues/235

        if ($AlternateDisplay) {

            if (-NOT (Get-InstalledModule -Name Microsoft.PowerShell.ConsoleGuiTools -ErrorAction SilentlyContinue)) {
                Write-Verbose -Message 'ConvertTo-WDACPolicy: Installing the Microsoft.PowerShell.ConsoleGuiTools module'
                Install-Module -Name Microsoft.PowerShell.ConsoleGuiTools -Force
            }

            # Display the logs in a console grid view using outside module
            $SelectedLogs = $EventsToDisplay | Out-ConsoleGridView -Title "$($EventsToDisplay.count) $LogType Code Integrity Logs" -OutputMode Multiple
        }
        #>

        # Display the logs in a grid view using the build-in cmdlet
        $SelectedLogs = $EventsToDisplay | Out-GridView -OutputMode Multiple -Title "$($EventsToDisplay.count) $LogType Code Integrity Logs"

        Write-Verbose -Message "ConvertTo-WDACPolicy: Selected logs count: $($SelectedLogs.count)"

        if (!$BasePolicyGUID -and !$BasePolicyFile -and !$PolicyToAddLogsTo) {
            Write-ColorfulText -Color HotPink -InputText 'A more specific parameter was not provided to define what to do with the selected logs. Exiting...'

            $ShouldExit = $true
            return
        }

        # If the user has selected any logs, then create a WDAC policy for them, otherwise return
        if ($null -eq $SelectedLogs) {
            $ShouldExit = $true
            return
        }

        Write-Verbose -Message 'ConvertTo-WDACPolicy: Creating a temporary folder to store the symbolic links to the files and WDAC polices'
        [System.IO.DirectoryInfo]$SymLinksStorage = New-Item -Path ($UserTempDirectoryPath + 'SymLinkStorage' + $(New-Guid)) -ItemType Directory -Force

        # The path to the TEMP Supplemental WDAC Policy file
        [System.IO.FileInfo]$WDACPolicyPathTemp = (Join-Path -Path $SymLinksStorage -ChildPath 'TEMP CiPolicy From Logs.xml')

        # The path to the final Supplemental WDAC Policy file
        [System.IO.FileInfo]$WDACPolicyPath = (Join-Path -Path $SymLinksStorage -ChildPath "CiPolicy From Logs $CurrentDate.xml")

        # The path to the Kernel protected file hashes WDAC Policy file
        [System.IO.FileInfo]$WDACPolicyKernelProtectedPath = (Join-Path -Path $SymLinksStorage -ChildPath "Kernel Protected Files Hashes $CurrentDate.xml")

        #Region Kernel-protected-files-automatic-detection-and-allow-rule-creation
        # This part takes care of Kernel protected files such as the main executable of the games installed through Xbox app
        # For these files, only Kernel can get their hashes, it passes them to event viewer and we take them from event viewer logs
        # Any other attempts such as "Get-FileHash" or "Get-AuthenticodeSignature" fail and ConfigCI Module cmdlets totally ignore these files and do not create allow rules for them

        Write-Verbose -Message 'ConvertTo-WDACPolicy: Checking for Kernel protected files in the selected logs'

        # Storing the logs of the kernel protected files
        [PSCustomObject[]]$KernelProtectedFileLogs = @()

        # Looping through every file with .exe and .dll extensions to check if they are kernel protected regardless of whether the file exists or not
        foreach ($Log in $SelectedLogs | Where-Object -FilterScript { [System.IO.Path]::GetExtension($_.'Full Path') -in @('.exe', '.dll') }) {

            try {
                # Testing each file to find the protected ones
                Get-FileHash -Path $Log.'Full Path' -ErrorAction Stop | Out-Null
            }
            # If the file is protected, it will throw an exception and the module will continue to the next one
            # Making sure only the right file is captured by narrowing down the error type.
            # E.g., when get-filehash can't get a file's hash because its open by another program, the exception is different: System.IO.IOException
            catch [System.UnauthorizedAccessException] {
                $KernelProtectedFileLogs += $Log
            }
            catch {
                Write-Verbose -Message "ConvertTo-WDACPolicy: An unexpected error occurred while checking the file: $($Log.'Full Path')"
            }
        }

        # Only proceed if any kernel protected file(s) were found in any of the selected logs
        if (($null -ne $KernelProtectedFileLogs) -and ($KernelProtectedFileLogs.count -gt 0)) {

            Write-Verbose -Message 'ConvertTo-WDACPolicy: The following Kernel protected files were detected, creating allow rules for them:'
            $KernelProtectedFileLogs | ForEach-Object -Process { Write-Verbose -Message $($_.'File Name') }

            # Check if any of the kernel-protected files can be allowed by FamilyPackageName
            [PSCustomObject]$AppxOutput = New-AppxPackageCiPolicy -Logs $KernelProtectedFileLogs -directoryPath $SymLinksStorage

            if ($null -ne $AppxOutput.PolicyPath) {
                # Add the path of the Appx package policy file to the array of policy files to merge
                $PolicyFilesToMerge += $AppxOutput.PolicyPath

                # Set the flag indicating that there are kernel-protected files in the selected logs
                [System.Boolean]$HasKernelFiles = $true
            }

            # If the New-AppxPackageCiPolicy function returned remaining logs then create allow rules for them using Hash level
            if (($null -ne $AppxOutput.RemainingLogs) -and ($AppxOutput.RemainingLogs.count -gt 0)) {

                # Put the Rules and RulesRefs in an empty policy file by extracting the hashes from the logs
                Write-Verbose -Message "ConvertTo-WDACPolicy: $($AppxOutput.RemainingLogs.count) Kernel protected files were found in the selected logs that did not have the PackageFamilyName property or the app is not installed on the system, creating allow rules for them using Hash level"

                New-EmptyPolicy -RulesContent (Get-FileRules -HashesArray $AppxOutput.RemainingLogs) -RuleRefsContent (Get-RuleRefs -HashesArray $AppxOutput.RemainingLogs) | Out-File -FilePath $WDACPolicyKernelProtectedPath -Force

                # Add the path of the Kernel protected files Hashes policy file to the array of policy files to merge
                $PolicyFilesToMerge += $WDACPolicyKernelProtectedPath

                # Set the flag indicating that there are kernel-protected files in the selected logs
                [System.Boolean]$HasKernelFiles = $true
            }
            else {
                Write-Verbose -Message 'ConvertTo-WDACPolicy: All kernel protected files were allowed using their PackageFamilyName property'
            }
        }
        else {
            Write-Verbose -Message 'ConvertTo-WDACPolicy: No Kernel protected files were found in any of the selected logs'
        }

        [System.UInt64]$LogCountBeforeRemovingKernelProtectedFiles = $SelectedLogs.Count

        # Remove the logs of the Kernel protected files from the selected logs since they cannot be scanned with New-CIPolicy cmdlet
        [PSCustomObject[]]$SelectedLogs = $SelectedLogs | Where-Object -FilterScript { $KernelProtectedFileLogs -notcontains $_ }

        Write-Verbose -Message "ConvertTo-WDACPolicy: The number of logs before removing the Kernel protected files: $LogCountBeforeRemovingKernelProtectedFiles and after: $($SelectedLogs.Count). There were $($KernelProtectedFileLogs.Count) Kernel protected files."
        #Endregion Kernel-protected-files-automatic-detection-and-allow-rule-creation

        # If there are still logs after removing the kernel protected files, then scan them
        if (($null -ne $SelectedLogs) -and ($SelectedLogs.Count -gt 0)) {

            #Region Main Policy Creation

            Write-Verbose -Message 'ConvertTo-WDACPolicy: Creating symbolic links to the non-kernel-protected files in the logs'
            Foreach ($File in $SelectedLogs) {
                New-Item -ItemType SymbolicLink -Path "$SymLinksStorage\$($File.'File Name')" -Target $File.'Full Path' -Force | Out-Null
            }

            # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
            [System.Collections.Hashtable]$CiPolicyScanHashTable = @{
                FilePath               = $WDACPolicyPathTemp
                ScanPath               = $SymLinksStorage
                Level                  = 'WHQLFilePublisher'
                MultiplePolicyFormat   = $true
                UserWriteablePaths     = $true
                AllowFileNameFallbacks = $true
            }
            # Only scan UserPEs if the KernelModeOnly switch is not used
            if (!$KernelModeOnly) { $CiPolicyScanHashTable['UserPEs'] = $true }

            # Set the Fallback property to 'None' if the KernelModeOnly switch is used, otherwise set it to 'FilePublisher' and 'Hash'
            $CiPolicyScanHashTable['Fallback'] = $KernelModeOnly ? 'None' : ('FilePublisher', 'Hash')

            Write-Verbose -Message 'ConvertTo-WDACPolicy: Scanning the files in the selected event logs with the following parameters:'
            if ($Verbose) { $CiPolicyScanHashTable }

            New-CIPolicy @CiPolicyScanHashTable

            # Add the path of the TEMP WDAC Policy file as the 1st element to the policy files to merge array
            [System.String[]]$PolicyFilesToMerge = @($WDACPolicyPathTemp) + $PolicyFilesToMerge

            # Set the flag indicating that there are normal files in the selected logs
            [System.Boolean]$HasNormalFiles = $true

            #Endregion Main Policy Creation
        }

        # If there are only kernel-protected files in the selected logs
        if (($HasKernelFiles -eq $true) -and ($HasNormalFiles -eq $false)) {
            Write-Verbose -Message 'ConvertTo-WDACPolicy: There are only kernel-protected files in the selected logs'
            Merge-CIPolicy -PolicyPaths $PolicyFilesToMerge -OutputFilePath $WDACPolicyPath | Out-Null
        }
        # If there are only normal files in the selected logs
        elseif (($HasKernelFiles -eq $false) -and ($HasNormalFiles -eq $true)) {
            Write-Verbose -Message 'ConvertTo-WDACPolicy: There are only normal files in the selected logs'

            # Using merge on a single policy takes care of any possible orphaned rules or file attributes
            Merge-CIPolicy -PolicyPaths $WDACPolicyPathTemp -OutputFilePath $WDACPolicyPath | Out-Null
        }
        # If there are both kernel-protected and normal files in the selected logs
        elseif (($HasKernelFiles -eq $true) -and ($HasNormalFiles -eq $true)) {
            Write-Verbose -Message 'ConvertTo-WDACPolicy: There are both kernel-protected and normal files in the selected logs'
            Merge-CIPolicy -PolicyPaths $PolicyFilesToMerge -OutputFilePath $WDACPolicyPath | Out-Null
        }
        # If there are no files in the selected logs
        else {
            Write-ColorfulText -Color HotPink -InputText 'No logs were selected to create a WDAC policy from. Exiting...'

            $ShouldExit = $true
            return
        }

        #Region Base To Supplemental Policy Association and Deployment

        # If -BasePolicyFile parameter was used then associate the supplemental policy with the user input base policy
        if ($null -ne $BasePolicyFile) {

            # Objectify the user input base policy file to extract its Base policy ID
            $InputXMLObj = [System.Xml.XmlDocument](Get-Content -Path $BasePolicyFile)

            [System.String]$SupplementalPolicyID = Set-CIPolicyIdInfo -FilePath $WDACPolicyPath -PolicyName "Supplemental Policy from event logs - $(Get-Date -Format 'MM-dd-yyyy')" -SupplementsBasePolicyID $InputXMLObj.SiPolicy.BasePolicyID -ResetPolicyID
            [System.String]$SupplementalPolicyID = $SupplementalPolicyID.Substring(11)

            # Configure policy rule options
            Edit-CiPolicyRuleOptions -Action Supplemental -XMLFile $WDACPolicyPath

            Write-Verbose -Message 'ConvertTo-WDACPolicy: Copying the policy file to the current directory'
            Copy-Item -Path $WDACPolicyPath -Destination '.\' -Force

            if ($Deploy) {
                ConvertFrom-CIPolicy -XmlFilePath $WDACPolicyPath -BinaryFilePath "$SupplementalPolicyID.cip" | Out-Null

                Write-Verbose -Message 'ConvertTo-WDACPolicy: Deploying the Supplemental policy'

                &'C:\Windows\System32\CiTool.exe' --update-policy "$SupplementalPolicyID.cip" -json | Out-Null
            }
        }
        # If -BasePolicyGUID parameter was used then use it by setting it as the Base policy ID in the supplemental policy
        elseif ($null -ne $BasePolicyGUID) {
            [System.String]$SupplementalPolicyID = Set-CIPolicyIdInfo -FilePath $WDACPolicyPath -PolicyName "Supplemental Policy from event logs - $(Get-Date -Format 'MM-dd-yyyy')" -SupplementsBasePolicyID $BasePolicyGUID -ResetPolicyID
            [System.String]$SupplementalPolicyID = $SupplementalPolicyID.Substring(11)

            # Configure policy rule options
            Edit-CiPolicyRuleOptions -Action Supplemental -XMLFile $WDACPolicyPath

            Write-Verbose -Message 'ConvertTo-WDACPolicy: Copying the policy file to the current directory'
            Copy-Item -Path $WDACPolicyPath -Destination '.\' -Force

            if ($Deploy) {
                ConvertFrom-CIPolicy -XmlFilePath $WDACPolicyPath -BinaryFilePath "$SupplementalPolicyID.cip" | Out-Null

                Write-Verbose -Message 'ConvertTo-WDACPolicy: Deploying the Supplemental policy'

                &'C:\Windows\System32\CiTool.exe' --update-policy "$SupplementalPolicyID.cip" -json | Out-Null
            }
        }
        # If -PolicyToAddLogsTo parameter was used then merge the supplemental policy with the user input policy
        elseif ($null -ne $PolicyToAddLogsTo) {

            # Objectify the user input policy file to extract its policy ID
            $InputXMLObj = [System.Xml.XmlDocument](Get-Content -Path $PolicyToAddLogsTo)

            Set-CIPolicyIdInfo -FilePath $WDACPolicyPath -PolicyName "Supplemental Policy from event logs - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID | Out-Null

            # Remove all policy rule option prior to merging the policies since we don't need to add/remove any policy rule options to/from the user input policy
            Edit-CiPolicyRuleOptions -Action RemoveAll -XMLFile $WDACPolicyPath

            Merge-CIPolicy -PolicyPaths "$PolicyToAddLogsTo", "$WDACPolicyPath" -OutputFilePath "$PolicyToAddLogsTo" | Out-Null

            # Set HVCI to Strict
            Set-HVCIOptions -Strict -FilePath "$PolicyToAddLogsTo"

            if ($Deploy) {
                ConvertFrom-CIPolicy -XmlFilePath $PolicyToAddLogsTo -BinaryFilePath "$($InputXMLObj.SiPolicy.PolicyID).cip" | Out-Null

                Write-Verbose -Message 'ConvertTo-WDACPolicy: Deploying the policy that user selected to add the logs to'

                &'C:\Windows\System32\CiTool.exe' --update-policy "$($InputXMLObj.SiPolicy.PolicyID).cip" -json | Out-Null
            }
        }

        #Endregion Base To Supplemental Policy Association and Deployment
    }

    End {
        if ($ShouldExit -eq $true) { return }

        Write-Verbose -Message 'ConvertTo-WDACPolicy: Removing the temporary folder and its content'
        Remove-Item -Path $SymLinksStorage -Recurse -Force
    }

    <#
.SYNOPSIS
    Displays the Code Integrity logs in a GUI and allows the user to select the logs to convert to a Supplemental WDAC policy
    It's a multi-purpose cmdlet that offers a wide range of functionalities that can either be used separately or mixed together for very detailed and specific tasks
.DESCRIPTION
    You can filter the logs by the policy name and the time
    You can add the logs to an existing WDAC policy or create a new one
.PARAMETER FilterByPolicyNames
   The names of the policies to filter the logs by.
   Supports auto-completion, press TAB key to view the list of the deployed base policy names to choose from.
   It will not display the policies that are already selected on the command line.
   You can manually enter the name of the policies that are no longer available on the system.
.PARAMETER PolicyToAddLogsTo
    The policy to add the selected logs to, it can either be a base or supplemental policy.
.PARAMETER BasePolicyFile
    The base policy file to associate the supplemental policy with
.PARAMETER BasePolicyGUID
    The GUID of the base policy to associate the supplemental policy with
.PARAMETER MinutesAgo
    The number of minutes ago from the current time to filter the logs by
.PARAMETER HoursAgo
    The number of hours ago from the current time to filter the logs by
.PARAMETER DaysAgo
    The number of days ago from the current time to filter the logs by
.PARAMETER KernelModeOnly
    If used, will filter the logs by including only the Kernel-Mode logs
.PARAMETER LogType
    The type of logs to display: Audit or Blocked
.PARAMETER Deploy
    If used, will deploy the policy on the system
.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases
.NOTES
    The biggest specified time unit is used for filtering the logs if more than one time unit is specified.
.EXAMPLE
    ConvertTo-WDACPolicy -PolicyToAddLogsTo "C:\Users\Admin\AllowMicrosoftPlusBlockRules.xml" -Verbose

    This example will display the Code Integrity logs in a GUI and allow the user to select the logs to add to the specified policy file.
.EXAMPLE
    ConvertTo-WDACPolicy -Verbose -BasePolicyGUID '{ACE9058C-8A24-47F4-86F0-A33FAB5073E3}'

    This example will display the Code Integrity logs in a GUI and allow the user to select the logs to create a new supplemental policy and associate it with the specified base policy GUID.
.EXAMPLE
    ConvertTo-WDACPolicy -BasePolicyFile "C:\Users\Admin\AllowMicrosoftPlusBlockRules.xml"

    This example will display the Code Integrity logs in a GUI and allow the user to select the logs to create a new supplemental policy and associate it with the specified base policy file.
.EXAMPLE
    ConvertTo-WDACPolicy

    This example will display the Code Integrity logs in a GUI and takes no further action.
.EXAMPLE
    ConvertTo-WDACPolicy -FilterByPolicyNames 'VerifiedAndReputableDesktopFlightSupplemental','WindowsE_Lockdown_Flight_Policy_Supplemental' -Verbose

    This example will filter the Code Integrity logs by the specified policy names and display them in a GUI. It will also display verbose messages on the console.
.EXAMPLE
    ConvertTo-WDACPolicy -FilterByPolicyNames 'Microsoft Windows Driver Policy - Enforced' -MinutesAgo 10

    This example will filter the Code Integrity logs by the specified policy name and the number of minutes ago from the current time and display them in a GUI.
    So, it will display the logs that are 10 minutes old and are associated with the specified policy name.
#>

}
# Importing argument completer ScriptBlocks
. "$ModuleRootPath\Resources\ArgumentCompleters.ps1"

Register-ArgumentCompleter -CommandName 'ConvertTo-WDACPolicy' -ParameterName 'PolicyToAddLogsTo' -ScriptBlock $ArgumentCompleterXmlFilePathsPicker
Register-ArgumentCompleter -CommandName 'ConvertTo-WDACPolicy' -ParameterName 'BasePolicyFile' -ScriptBlock $ArgumentCompleterXmlFilePathsPicker
