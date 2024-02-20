Function New-AppxPackageCiPolicy {
    <#
    .SYNOPSIS
        Creates a WDAC policy file for Appx packages
    .DESCRIPTION
        This function creates a WDAC policy file for Appx packages based on the logs that contain the PackageFamilyName property
        It needs to receive Code Integrity Operational logs as input
        It then checks whether any of the logs contain the PackageFamilyName property and if so, it creates a policy file for each unique PackageFamilyName
    .NOTES
        The function that calls this function should be able to handle the output object
        By checking whether the PolicyPath property is null or not, meaning the policy could not be created because no PackageFamilyName property was found in any of the logs
        or the PackageFamilyName property was found but the app is not installed on the system and as a result the version could not be detected

        The calling function should also be able to handle the RemainingLogs property which contains the logs that were not used in the policy file
        And create hash rules for them since they are kernel protected files.
    .PARAMETER Logs
        The event logs to create the policy file from
    .PARAMETER DirectoryPath
        The path to the directory to store the policy file
    .INPUTS
        PSCustomObject[]
    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$Logs,

        [Parameter(Mandatory = $true)]
        [System.IO.DirectoryInfo]$DirectoryPath
    )
    Begin {
        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Importing the required sub-modules
        Write-Verbose -Message 'New-AppxPackageCiPolicy: Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\New-EmptyPolicy.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-RuleRefs.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-FileRules.psm1" -Force

        # The object to return
        $OutputObject = [PSCustomObject]@{
            PolicyPath    = $null
            RemainingLogs = $null
        }

        # The path to the Appx package WDAC Policy file
        [System.IO.FileInfo]$AppxKernelProtectedPolicyPath = (Join-Path -Path $DirectoryPath -ChildPath "AppxPackageKernelCiPolicy $(Get-Date -Format "MM-dd-yyyy 'at' HH-mm-ss").xml")
    }
    Process {
        # Only select the logs that have the PackageFamilyName property
        [PSCustomObject[]]$LogsWithAppxPackages = $Logs | Where-Object -FilterScript { $null -ne $_.'PackageFamilyName' }

        if ($null -eq $LogsWithAppxPackages) {
            Write-Verbose -Message 'New-AppxPackageCiPolicy: No PackageFamilyName property were found in any of the logs'
            return $OutputObject
        }

        # Get the unique PackageFamilyName values since only one rule is needed for each Appx Package (aka game, app etc.)
        [PSCustomObject[]]$LogsWithAppxPackagesUnique = $LogsWithAppxPackages | Group-Object -Property PackageFamilyName | ForEach-Object -Process { $_.Group[0] }

        # Replace the version for the Appx package in the log with the correct version that is available for the installed app on the system
        # If the app is not installed on the system then assign the version to Null and do not create rules for it
        foreach ($Appx in $LogsWithAppxPackagesUnique) {

            $PossibleVersion = [System.Version](Get-AppxPackage | Where-Object { $_.PackageFamilyName -eq $Appx.PackageFamilyName }).Version

            # If the version is not null, empty or whitespace then assign it to the FileVersion property of the Appx package
            if (-NOT [System.String]::IsNullOrWhiteSpace($PossibleVersion)) {
                $Appx.FileVersion = [System.Version]$PossibleVersion
                Write-Verbose -Message "New-AppxPackageCiPolicy: The version of the Appx package $($Appx.PackageFamilyName) is $($Appx.FileVersion) and will be used in the policy file"
            }
            # Otherwise, assign the version to Null
            else {
                $Appx.FileVersion = $null
                Write-Verbose -Message "New-AppxPackageCiPolicy: The Appx package $($Appx.PackageFamilyName) is not installed on the system"
            }
        }

        # Define 2 arrays that hold File rules and RuleRefs for use in the empty policy to generate the Appx package policy file
        [System.String[]]$FileAttribArray = @()
        [System.String[]]$RuleRefsArray = @()

        # Create the File rules and RuleRefs for each Appx package
        $LogsWithAppxPackagesUnique | Where-Object -FilterScript { $null -ne $_.FileVersion } | ForEach-Object -Begin { $i = 1 } -Process {
            $FileAttribArray += Write-Output -InputObject "`n<Allow ID=`"ID_ALLOW_A_$i`" FriendlyName=`"$($_.'PackageFamilyName') Filerule`" MinimumFileVersion=`"0.0.0.0`" PackageFamilyName=`"$($_.PackageFamilyName)`" PackageVersion=`"$([System.String]$_.FileVersion)`" />"
            $RuleRefsArray += Write-Output -InputObject "`n<FileRuleRef RuleID=`"ID_ALLOW_A_$i`" />"
            $i++
        }

        # Create the Appx package policy file
        New-EmptyPolicy -RulesContent $FileAttribArray -RuleRefsContent $RuleRefsArray | Out-File -FilePath $AppxKernelProtectedPolicyPath -Force

        # Assign the path of the Appx package policy file to the PolicyPath property of the output object
        $OutputObject.PolicyPath = $AppxKernelProtectedPolicyPath

        # Check if there are any logs left that are not used in the policy file
        # These logs either did not have the PackageFamilyName property
        # or the app is not installed on the system and as a result the version was set to null
        $OutputObject.RemainingLogs = $Logs | Where-Object -FilterScript { ($LogsWithAppxPackages -notcontains $_) -and ($null -eq $_.FileVersion) }
    }
    End {
        Return $OutputObject
    }
}
Export-ModuleMember -Function 'New-AppxPackageCiPolicy'
