Function Get-SignTool {
    <#
    .SYNOPSIS
        Gets the path to SignTool.exe and verifies it to make sure it's not tampered
        If the SignTool.exe path is not provided by parameter, it will try to detect it automatically, either by checking if Windows SDK is installed or by reading the user configs (this part actually happens in the main cmdlet that calls Get-SignTool function)
        If the SignTool.exe path is not provided by parameter and it could not be detected automatically, it will ask the user to try to download it from NuGet
    .PARAMETER SignToolExePathInput
        Path to the SignTool.exe
        It's optional
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.IO.FileInfo
    #>
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo])]
    param(
        [parameter(Mandatory = $false)][System.IO.FileInfo]$SignToolExePathInput
    )
    Begin {
        [System.IO.DirectoryInfo]$StagingArea = [WDACConfig.StagingArea]::NewStagingArea('Get-SignTool')
    }

    Process {

        Try {

            # If Sign tool path wasn't provided by parameter, try to detect it automatically
            if (!$SignToolExePathInput) {

                [WDACConfig.Logger]::Write('SignTool.exe path was not provided by parameter, trying to detect it automatically')

                try {
                    if ($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64') {
                        if ( Test-Path -Path 'C:\Program Files (x86)\Windows Kits\*\bin\*\x64\signtool.exe') {
                            $SignToolExePathOutput = 'C:\Program Files (x86)\Windows Kits\*\bin\*\x64\signtool.exe'
                        }
                        else {
                            Throw [System.IO.FileNotFoundException] 'signtool.exe could not be found'
                        }
                    }
                    elseif ($Env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
                        if (Test-Path -Path 'C:\Program Files (x86)\Windows Kits\*\bin\*\arm64\signtool.exe') {
                            $SignToolExePathOutput = 'C:\Program Files (x86)\Windows Kits\*\bin\*\arm64\signtool.exe'
                        }
                        else {
                            Throw [System.IO.FileNotFoundException] 'signtool.exe could not be found'
                        }
                    }
                }
                catch [System.IO.FileNotFoundException] {

                    # If Sign tool path wasn't provided by parameter and couldn't be detected automatically, try to download it from NuGet, if fails or user declines this, stop the operation

                    if ($PSCmdlet.ShouldContinue('Would you like to try to download it from the official Microsoft server? It will be saved in the WDACConfig directory in Program Files.', 'SignTool.exe path was not provided, it could not be automatically detected on the system, nor could it be found in the common WDAC user configurations.')) {

                        if (-NOT (Get-PackageSource | Where-Object -FilterScript { $_.Name -ieq 'nuget.org' })) {
                            [WDACConfig.Logger]::Write('Registering the nuget.org package source because it was not found in the system.')
                            $null = Register-PackageSource -Name 'nuget.org' -ProviderName 'NuGet' -Location 'https://api.nuget.org/v3/index.json'
                        }

                        [WDACConfig.Logger]::Write('Finding the latest version of the Microsoft.Windows.SDK.BuildTools package from NuGet')

                        # Use a script block to convert the Version property to a semantic version object for proper sorting based on the version number
                        [Microsoft.PackageManagement.Packaging.SoftwareIdentity[]]$Package = Find-Package -Name 'Microsoft.Windows.SDK.BuildTools' -Source 'nuget.org' -AllVersions -Force -MinimumVersion '10.0.22621.3233'

                        [Microsoft.PackageManagement.Packaging.SoftwareIdentity]$Package = $Package | Sort-Object -Property { [System.Version]$_.Version } -Descending | Select-Object -First 1

                        [WDACConfig.Logger]::Write('Downloading SignTool.exe from NuGet...')
                        $null = Save-Package -InputObject $Package -Path $StagingArea -Force

                        [WDACConfig.Logger]::Write('Extracting the nupkg')
                        Expand-Archive -Path "$StagingArea\*.nupkg" -DestinationPath $StagingArea -Force

                        [WDACConfig.Logger]::Write('Detecting the CPU Arch')
                        switch ($Env:PROCESSOR_ARCHITECTURE) {
                            'AMD64' { [System.String]$CPUArch = 'x64' }
                            'ARM64' { [System.String]$CPUArch = 'arm64' }
                            default { Throw [System.PlatformNotSupportedException] 'Only AMD64 and ARM64 architectures are supported.' }
                        }
                        # Defining the final path to return for SignTool.exe
                        [System.IO.FileInfo]$SignToolExePathOutput = Join-Path -Path ([WDACConfig.GlobalVars]::UserConfigDir) -ChildPath 'SignTool.exe'

                        # Move the SignTool.exe from the temp directory to the User Config directory
                        Move-Item -Path "$StagingArea\bin\*\$CPUArch\signtool.exe" -Destination $SignToolExePathOutput -Force
                    }
                    else {
                        Throw [System.IO.FileNotFoundException] 'signtool.exe could not be found and an attempt to download it was declined.'
                    }
                }
            }
            # If Sign tool path was provided by parameter, use it
            else {
                [WDACConfig.Logger]::Write('SignTool.exe path was provided by parameter')
                $SignToolExePathOutput = $SignToolExePathInput
            }

            # Since WDAC Simulation doesn't support path with wildcards and accepts them literally, doing this to make sure the path is valid when automatically detected from Windows SDK installations which is a wildcard path
            [System.IO.FileInfo]$SignToolExePathOutput = (Resolve-Path -Path $SignToolExePathOutput).Path

            # At this point the SignTool.exe path was either provided by user, was found in the user configs, was detected automatically or was downloaded from NuGet
            try {
                # Validate the SignTool executable
                [WDACConfig.Logger]::Write("Validating the SignTool executable: $SignToolExePathOutput")
                # Setting the minimum version of SignTool that is allowed to be executed
                [System.Version]$WindowsSdkVersion = '10.0.22621.2428'
                [System.Boolean]$GreenFlag1 = (((Get-Item -Path $SignToolExePathOutput).VersionInfo).ProductVersionRaw -ge $WindowsSdkVersion)
                [System.Boolean]$GreenFlag2 = (((Get-Item -Path $SignToolExePathOutput).VersionInfo).FileVersionRaw -ge $WindowsSdkVersion)
                [System.Boolean]$GreenFlag3 = ((Get-Item -Path $SignToolExePathOutput).VersionInfo).CompanyName -eq 'Microsoft Corporation'
                [System.Boolean]$GreenFlag4 = ((Get-AuthenticodeSignature -FilePath $SignToolExePathOutput).Status -eq 'Valid')
                [System.Boolean]$GreenFlag5 = ((Get-AuthenticodeSignature -FilePath $SignToolExePathOutput).StatusMessage -eq 'Signature verified.')
            }
            catch {
                # Display an extra error message to provide more information to the user
                if ($SignToolExePathInput) {
                    Write-Error -Message 'The SignTool.exe path that was provided by parameter or found in user configuration could not be validated.' -ErrorAction Continue
                }
                Throw $_
            }
            # If any of the 5 checks above fails, the operation stops
            if (!$GreenFlag1 -or !$GreenFlag2 -or !$GreenFlag3 -or !$GreenFlag4 -or !$GreenFlag5) {
                Throw [System.Security.VerificationException] 'The SignTool executable was found but could not be verified. Please download the latest Windows SDK to get the newest SignTool executable. Official download link: http://aka.ms/WinSDK'
            }
            else {
                [WDACConfig.Logger]::Write('SignTool executable was found and verified successfully.')

                [WDACConfig.Logger]::Write('Setting the SignTool path in the common WDAC user configurations')
                $null = [WDACConfig.UserConfiguration]::Set($null, $null, $SignToolExePathOutput, $null, $null, $null, $null, $null , $null)

                return $SignToolExePathOutput
            }
        }
        Finally {
            Remove-Item -Path $StagingArea -Recurse -Force
        }
    }
}
Export-ModuleMember -Function 'Get-SignTool'
