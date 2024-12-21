Function Remove-WDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = 'Signed Base',
        SupportsShouldProcess = $true,
        PositionalBinding = $False,
        ConfirmImpact = 'High'
    )]
    Param(
        [ArgumentCompleter([WDACConfig.ArgCompleter.XmlFileMultiSelectPicker])]
        [ValidateScript({
                $_ | ForEach-Object -Process {
                    [WDACConfig.PolicyFileSigningStatusDetection]::Check($_) -eq [WDACConfig.PolicyFileSigningStatusDetection+SigningStatus]::Signed ? $true : $false
                }
            }, ErrorMessage = 'One of the selected XML policy files is unsigned. Please use Remove-WDACConfig cmdlet with -UnsignedOrSupplemental parameter instead.')]
        [parameter(Mandatory = $true)]
        [System.IO.FileInfo[]]$PolicyPaths,

        [ArgumentCompleter({
                foreach ($Item in [WDACConfig.CertCNz]::new().GetValidValues()) {
                    if ($Item.Contains(' ')) {
                        "'$Item'"
                    }
                }
            })]
        [parameter(Mandatory = $False)]
        [System.String]$CertCN,

        [ArgumentCompleter([WDACConfig.ArgCompleter.ExeFilePathsPicker])]
        [parameter(Mandatory = $False, ParameterSetName = 'Signed Base', ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo]$SignToolPath,

        [Parameter(Mandatory = $False)][switch]$Force
    )
    Begin {
        [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)

        [System.IO.DirectoryInfo]$StagingArea = [WDACConfig.StagingArea]::NewStagingArea('Remove-WDACConfig')

        #Region User-Configurations-Processing-Validation
        [WDACConfig.Logger]::Write('Validating and processing user configurations')

        # Get SignToolPath from user parameter or user config file or auto-detect it
        [System.IO.FileInfo]$SignToolPathFinal = [WDACConfig.SignToolHelper]::GetSignToolPath($SignToolPath ?? ([WDACConfig.UserConfiguration]::Get().SignToolCustomPath))

        # If CertCN was not provided by user, check if a valid value exists in user configs, if so, use it, otherwise throw an error
        if (!$CertCN) {
            if ([WDACConfig.CertCNz]::new().GetValidValues() -contains ([WDACConfig.UserConfiguration]::Get().CertificateCommonName)) {
                [System.String]$CertCN = [WDACConfig.UserConfiguration]::Get().CertificateCommonName
            }
            else {
                throw 'CertCN parameter cannot be empty and no valid user configuration was found for it.'
            }
        }
        else {
            if ([WDACConfig.CertCNz]::new().GetValidValues() -notcontains $CertCN) {
                throw "$CertCN does not belong to a subject CN of any of the deployed certificates"
            }
        }

        #Endregion User-Configurations-Processing-Validation

        # Detecting if Confirm switch is used to bypass the confirmation prompts
        if ($Force -and -Not $Confirm) {
            $ConfirmPreference = 'None'
        }
    }
    process {

        Try {

            [WDACConfig.Logger]::Write('Looping over each selected policy XML file')
            foreach ($PolicyPath in $PolicyPaths) {

                # The total number of the main steps for the progress bar to render
                $TotalSteps = 3us
                $CurrentStep = 0us

                $CurrentStep++
                Write-Progress -Id 18 -Activity 'Parsing the XML Policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.Logger]::Write('Converting the XML file to an XML object')
                [System.Xml.XmlDocument]$Xml = Get-Content -Path $PolicyPath

                [WDACConfig.Logger]::Write('Extracting the Policy ID from the XML object')
                [System.String]$PolicyID = $Xml.SiPolicy.PolicyID
                [WDACConfig.Logger]::Write("The policy ID of the currently processing xml file is $PolicyID")

                # Extracting the policy name from the selected XML policy file
                [System.String]$PolicyName = foreach ($Item in $Xml.SiPolicy.Settings.Setting) {
                    if ($Item.Provider -eq 'PolicyInfo' -and $Item.ValueName -eq 'Name' -and $Item.Key -eq 'Information') {
                        $Item.Value.String
                    }
                }

                # Prevent users from accidentally attempting to remove policies that aren't even deployed on the system
                [WDACConfig.Logger]::Write('Making sure the selected XML policy is deployed on the system')

                Try {
                    [System.Guid[]]$CurrentPolicyIDs = foreach ($Item in [WDACConfig.CiToolHelper]::GetPolicies($false, $true, $true)) {
                        if ($Item.IsSystemPolicy -ne 'True') {
                            "{$($Item.PolicyID)}"
                        }
                    }
                }
                catch {
                    Throw 'No policy is deployed on the system.'
                }

                if ($CurrentPolicyIDs -notcontains $PolicyID) {
                    Throw 'The selected policy file is not deployed on the system.'
                }

                $CurrentStep++
                Write-Progress -Id 18 -Activity 'Processing the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.Logger]::Write('Making sure SupplementalPolicySigners do not exist in the XML policy')
                [WDACConfig.CiPolicyHandler]::RemoveSupplementalSigners($PolicyPath.FullName)

                [WDACConfig.CiRuleOptions]::Set($PolicyPath, $null, [WDACConfig.CiRuleOptions+PolicyRuleOptions]::EnabledUnsignedSystemIntegrityPolicy, $null, $null, $null, $null, $null, $null, $null, $null)

                [System.IO.FileInfo]$PolicyCIPPath = Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip"

                # Converting the Policy XML file to CIP binary file
                $null = ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath $PolicyCIPPath

                $CurrentStep++
                Write-Progress -Id 18 -Activity 'Signing the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.SignToolHelper]::Sign($PolicyCIPPath, $SignToolPathFinal, $CertCN)

                # Fixing the extension name of the newly signed CIP file
                Move-Item -Path (Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip.p7") -Destination $PolicyCIPPath -Force

                # Deploying the newly signed CIP file

                # Prompt for confirmation before proceeding
                if ($PSCmdlet.ShouldProcess('This PC', 'Deploying the signed policy')) {

                    [WDACConfig.CiToolHelper]::UpdatePolicy($PolicyCIPPath)

                    Write-ColorfulTextWDACConfig -Color Lavender -InputText "Policy with the following details has been Re-signed and Re-deployed in Unsigned mode.`nPlease restart your system."
                    Write-ColorfulTextWDACConfig -Color MintGreen -InputText "PolicyName = $PolicyName"
                    Write-ColorfulTextWDACConfig -Color MintGreen -InputText "PolicyGUID = $PolicyID"
                }
                Write-Progress -Id 18 -Activity 'Complete.' -Completed
            }
        }
        catch {
            throw $_
        }
        Finally {
            # Clean up the staging area
            Remove-Item -Path $StagingArea -Recurse -Force
        }
    }
    <#
.SYNOPSIS
    Removes Signed deployed App Control for Business policies
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Remove-WDACConfig
.PARAMETER PolicyPaths
    Path to the XML policy file(s) of the deployed policies to be removed
.PARAMETER CertCN
    Certificate common name to be used to sign the policy file(s) that are going to be removed in unsigned mode
.PARAMETER SignToolPath
    Path to the SignTool.exe
.PARAMETER Force
    Bypasses the confirmation prompt
.INPUTS
    System.String
    System.String[]
    System.IO.FileInfo
    System.IO.FileInfo[]
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
#>
}