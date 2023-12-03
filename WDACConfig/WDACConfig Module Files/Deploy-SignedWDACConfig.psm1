function Deploy-SignedWDACConfig {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    Param(
        [ValidatePattern('\.xml$')]
        [ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' }, ErrorMessage = 'The path you selected is not a file path.')]
        [parameter(Mandatory = $true)][System.String[]]$PolicyPaths,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$Deploy,

        [ValidatePattern('\.cer$')]
        [ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' }, ErrorMessage = 'The path you selected is not a file path.')]
        [parameter(Mandatory = $false)][System.String]$CertPath,

        [ValidateScript({
            [System.String[]]$Certificates = foreach ($Cert in (Get-ChildItem -Path 'Cert:\CurrentUser\my')) {
                (($Cert.Subject -split ',' | Select-Object -First 1) -replace 'CN=', '').Trim()
                }
                $Certificates -contains $_
            }, ErrorMessage = "A certificate with the provided common name doesn't exist in the personal store of the user certificates." )]
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)][System.String]$CertCN,

        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [System.String]$SignToolPath,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )

    begin {
        # Importing resources such as functions by dot-sourcing so that they will run in the same scope and their variables will be usable
        . "$psscriptroot\Resources.ps1"

        # Stop operation as soon as there is an error anywhere, unless explicitly specified otherwise
        $ErrorActionPreference = 'Stop'
        if (-NOT $SkipVersionCheck) { . Update-self }

        # Detecting if Debug switch is used, will do debugging actions based on that
        $Debug = $PSBoundParameters.Debug.IsPresent

        # Fetch User account directory path
        [System.String]$global:UserAccountDirectoryPath = (Get-CimInstance Win32_UserProfile -Filter "SID = '$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)'").LocalPath

        #region User-Configurations-Processing-Validation
        # If any of these parameters, that are mandatory for all of the position 0 parameters, isn't supplied by user
        if (!$SignToolPath -or !$CertPath -or !$CertCN) {
            # Read User configuration file if it exists
            $UserConfig = Get-Content -Path "$global:UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json" -ErrorAction SilentlyContinue
            if ($UserConfig) {
                # Validate the Json file and read its content to make sure it's not corrupted
                try { $UserConfig = $UserConfig | ConvertFrom-Json }
                catch {
                    Write-Error -Message 'User Configuration Json file is corrupted, deleting it...' -ErrorAction Continue
                    # Calling this function with this parameter automatically does its job and breaks/stops the operation
                    Set-CommonWDACConfig -DeleteUserConfig
                }
            }
        }

        # Get SignToolPath from user parameter or user config file or auto-detect it
        if ($SignToolPath) {
            $SignToolPathFinal = Get-SignTool -SignToolExePath $SignToolPath
        } # If it is null, then Get-SignTool will behave the same as if it was called without any arguments.
        else {
            $SignToolPathFinal = Get-SignTool -SignToolExePath ($UserConfig.SignToolCustomPath ?? $null)
        }

        # If CertPath parameter wasn't provided by user
        if (!$CertPath) {
            if ($UserConfig.CertificatePath) {
                # validate user config values for Certificate Path
                if (Test-Path -Path $($UserConfig.CertificatePath)) {
                    # If the user config values are correct then use them
                    $CertPath = $UserConfig.CertificatePath
                }
                else {
                    throw 'The currently saved value for CertPath in user configurations is invalid.'
                }
            }
            else {
                throw "CertPath parameter can't be empty and no valid configuration was found for it."
            }
        }

        # If CertCN was not provided by user
        if (!$CertCN) {
            if ($UserConfig.CertificateCommonName) {
                # Check if the value in the User configuration file exists and is valid
                if (Confirm-CertCN -CN $($UserConfig.CertificateCommonName)) {
                    # if it's valid then use it
                    $CertCN = $UserConfig.CertificateCommonName
                }
                else {
                    throw 'The currently saved value for CertCN in user configurations is invalid.'
                }
            }
            else {
                throw "CertCN parameter can't be empty and no valid configuration was found for it."
            }
        }
        #endregion User-Configurations-Processing-Validation
    }

    process {
        foreach ($PolicyPath in $PolicyPaths) {

            # Gather policy details
            $xml = [System.Xml.XmlDocument](Get-Content -Path $PolicyPath)
            [System.String]$PolicyType = $xml.SiPolicy.PolicyType
            [System.String]$PolicyID = $xml.SiPolicy.PolicyID
            [System.String]$PolicyName = ($xml.SiPolicy.Settings.Setting | Where-Object -FilterScript { $_.provider -eq 'PolicyInfo' -and $_.valuename -eq 'Name' -and $_.key -eq 'Information' }).value.string
            [System.String[]]$PolicyRuleOptions = $xml.SiPolicy.Rules.Rule.Option

            # Remove the .CIP file of the same policy being signed and deployed if any in the current working directory
            Remove-Item -Path ".\$PolicyID.cip" -ErrorAction SilentlyContinue

            # Ensure -Supplemental is not used when the policy type is supplemental
            if ($PolicyType -eq 'Supplemental Policy') {
                # Make sure -User is not added if the UMCI policy rule option doesn't exist in the policy, typically for Strict kernel mode policies
                if ('Enabled:UMCI' -in $PolicyRuleOptions) {
                    Add-SignerRule -FilePath $PolicyPath -CertificatePath $CertPath -Update -User -Kernel
                }
                else {
                    Add-SignerRule -FilePath $PolicyPath -CertificatePath $CertPath -Update -Kernel
                }
            }
            else {
                # Make sure -User is not added if the UMCI policy rule option doesn't exist in the policy, typically for Strict kernel mode policies
                if ('Enabled:UMCI' -in $PolicyRuleOptions) {
                    Add-SignerRule -FilePath $PolicyPath -CertificatePath $CertPath -Update -User -Kernel -Supplemental
                }
                else {
                    Add-SignerRule -FilePath $PolicyPath -CertificatePath $CertPath -Update -Kernel -Supplemental
                }
            }
            Set-HVCIOptions -Strict -FilePath $PolicyPath
            Set-RuleOption -FilePath $PolicyPath -Option 6 -Delete
            ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath "$PolicyID.cip" | Out-Null

            # Configure the parameter splat
            $ProcessParams = @{
                'ArgumentList' = 'sign', '/v' , '/n', "`"$CertCN`"", '/p7', '.', '/p7co', '1.3.6.1.4.1.311.79.1', '/fd', 'certHash', ".\$PolicyID.cip"
                'FilePath'     = $SignToolPathFinal
                'NoNewWindow'  = $true
                'Wait'         = $true
                'ErrorAction'  = 'Stop'
            }
            # Hide the SignTool.exe's normal output unless -Debug parameter was used
            if (!$Debug) { $ProcessParams['RedirectStandardOutput'] = 'NUL' }
            # Sign the files with the specified cert
            Start-Process @ProcessParams

            Remove-Item -Path ".\$PolicyID.cip" -Force
            Rename-Item -Path "$PolicyID.cip.p7" -NewName "$PolicyID.cip" -Force

            if ($Deploy) {

                CiTool --update-policy ".\$PolicyID.cip" -json | Out-Null
                Write-Host -Object "`npolicy with the following details has been Signed and Deployed in Enforced Mode:" -ForegroundColor Green
                Write-Output -InputObject "PolicyName = $PolicyName"
                Write-Output -InputObject "PolicyGUID = $PolicyID`n"
                Remove-Item -Path ".\$PolicyID.cip" -Force

                #region Detecting Strict Kernel mode policy and removing it from User Configs
                if ('Enabled:UMCI' -notin $PolicyRuleOptions) {

                    [System.String]$StrictKernelPolicyGUID = Get-CommonWDACConfig -StrictKernelPolicyGUID
                    [System.String]$StrictKernelNoFlightRootsPolicyGUID = Get-CommonWDACConfig -StrictKernelNoFlightRootsPolicyGUID

                    if (($PolicyName -like '*Strict Kernel mode policy Enforced*')) {
                        if ($StrictKernelPolicyGUID) {
                            if ($($PolicyID.TrimStart('{').TrimEnd('}')) -eq $StrictKernelPolicyGUID) {
                                Remove-CommonWDACConfig -StrictKernelPolicyGUID | Out-Null
                            }
                        }
                    }

                    elseif (($PolicyName -like '*Strict Kernel No Flights mode policy Enforced*')) {
                        if ($StrictKernelNoFlightRootsPolicyGUID) {
                            if ($($PolicyID.TrimStart('{').TrimEnd('}')) -eq $StrictKernelNoFlightRootsPolicyGUID) {
                                Remove-CommonWDACConfig -StrictKernelNoFlightRootsPolicyGUID | Out-Null
                            }
                        }
                    }
                }
                #endregion Detecting Strict Kernel mode policy and removing it from User Configs

                # Show the question only for base policies. Don't show it for Strict kernel mode policies
                if (($PolicyType -ne 'Supplemental Policy') -and ($PolicyName -notlike '*Strict Kernel*')) {

                    # Ask user question about whether or not to add the Signed policy xml file to the User Config Json for easier usage later
                    $userInput = ''
                    while ($userInput -notin 1, 2) {
                        $userInput = $(Write-Host -Object 'Add the Signed policy xml file path just created to the User Configurations? Please enter 1 to Confirm or 2 to Skip.' -ForegroundColor Cyan ; Read-Host)
                        if ($userInput -eq 1) {
                            Set-CommonWDACConfig -SignedPolicyPath $PolicyPath
                            &$WriteHotPink "Added $PolicyPath to the User Configuration file."
                        }
                        elseif ($userInput -eq 2) {
                            &$WritePink 'Skipping...'
                        }
                        else {
                            Write-Warning 'Invalid input. Please enter 1 or 2 only.'
                        }
                    }
                }
            }

            else {
                Write-Host -Object "`npolicy with the following details has been Signed and is ready for deployment:" -ForegroundColor Green
                Write-Output -InputObject "PolicyName = $PolicyName"
                Write-Output -InputObject "PolicyGUID = $PolicyID`n"
            }
        }
    }

    <#
.SYNOPSIS
    Signs and Deploys WDAC policies, accepts signed or unsigned policies and deploys them

.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-SignedWDACConfig

.DESCRIPTION
    Using official Microsoft methods, Signs and Deploys WDAC policies, accepts signed or unsigned policies and deploys them (Windows Defender Application Control)

.COMPONENT
    Windows Defender Application Control, ConfigCI PowerShell module

.FUNCTIONALITY
    Using official Microsoft methods, Signs and Deploys WDAC policies, accepts signed or unsigned policies and deploys them (Windows Defender Application Control)

.PARAMETER CertPath
    Path to the certificate .cer file

.PARAMETER PolicyPaths
    Path to the policy xml files that are going to be signed

.PARAMETER CertCN
    Certificate common name

.PARAMETER SignToolPath
    Path to the SignTool.exe - optional parameter

.PARAMETER Deploy
    Indicates that the cmdlet will deploy the signed policy on the current system

.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases

#>
}

# Importing argument completer ScriptBlocks
. "$psscriptroot\ArgumentCompleters.ps1"
# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
Register-ArgumentCompleter -CommandName 'Deploy-SignedWDACConfig' -ParameterName 'CertCN' -ScriptBlock $ArgumentCompleterCertificateCN
Register-ArgumentCompleter -CommandName 'Deploy-SignedWDACConfig' -ParameterName 'PolicyPaths' -ScriptBlock $ArgumentCompleterPolicyPaths
Register-ArgumentCompleter -CommandName 'Deploy-SignedWDACConfig' -ParameterName 'CertPath' -ScriptBlock $ArgumentCompleterCerFilePathsPicker
Register-ArgumentCompleter -CommandName 'Deploy-SignedWDACConfig' -ParameterName 'SignToolPath' -ScriptBlock $ArgumentCompleterExeFilePathsPicker
