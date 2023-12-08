Function Get-SignTool {
    <#
    .SYNOPSIS
        Gets the path to SignTool.exe and verifies it to make sure it's not tampered
    .PARAMETER SignToolExePath
        Path to the SignTool.exe
    .INPUTS
        System.String
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $false)][System.String]$SignToolExePath
    )
    # Importing the $PSDefaultParameterValues to the current session, prior to everything else
    . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

    # If Sign tool path wasn't provided by parameter, try to detect it automatically, if fails, stop the operation
    if (!$SignToolExePath) {
        if ($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64') {
            if ( Test-Path -Path 'C:\Program Files (x86)\Windows Kits\*\bin\*\x64\signtool.exe') {
                $SignToolExePath = 'C:\Program Files (x86)\Windows Kits\*\bin\*\x64\signtool.exe'
            }
            else {
                Throw [System.IO.FileNotFoundException] 'signtool.exe could not be found'
            }
        }
        elseif ($Env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
            if (Test-Path -Path 'C:\Program Files (x86)\Windows Kits\*\bin\*\arm64\signtool.exe') {
                $SignToolExePath = 'C:\Program Files (x86)\Windows Kits\*\bin\*\arm64\signtool.exe'
            }
            else {
                Throw [System.IO.FileNotFoundException] 'signtool.exe could not be found'
            }
        }
    }
    try {
        # Validate the SignTool executable
        [System.Version]$WindowsSdkVersion = '10.0.22621.755' # Setting the minimum version of SignTool that is allowed to be executed
        [System.Boolean]$GreenFlag1 = (((Get-Item -Path $SignToolExePath).VersionInfo).ProductVersionRaw -ge $WindowsSdkVersion)
        [System.Boolean]$GreenFlag2 = (((Get-Item -Path $SignToolExePath).VersionInfo).FileVersionRaw -ge $WindowsSdkVersion)
        [System.Boolean]$GreenFlag3 = ((Get-Item -Path $SignToolExePath).VersionInfo).CompanyName -eq 'Microsoft Corporation'
        [System.Boolean]$GreenFlag4 = ((Get-AuthenticodeSignature -FilePath $SignToolExePath).Status -eq 'Valid')
        [System.Boolean]$GreenFlag5 = ((Get-AuthenticodeSignature -FilePath $SignToolExePath).StatusMessage -eq 'Signature verified.')
    }
    catch {
        Throw [System.Security.VerificationException] 'SignTool executable could not be verified.'
    }
    # If any of the 5 checks above fails, the operation stops
    if (!$GreenFlag1 -or !$GreenFlag2 -or !$GreenFlag3 -or !$GreenFlag4 -or !$GreenFlag5) {
        Throw [System.Security.VerificationException] 'The SignTool executable was found but could not be verified. Please download the latest Windows SDK to get the newest SignTool executable. Official download link: http://aka.ms/WinSDK'
    }
    else {
        return $SignToolExePath
    }
}

# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'Get-SignTool'
