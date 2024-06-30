Function Get-SignerInfo {
    <#
    .SYNOPSIS
        Function that takes an XML policy content as input and returns an array of Signer objects
        The output contains as much info as possible about each signer
    .INPUTS
        System.Xml.XmlDocument
    .OUTPUTS
        WDACConfig.Signer[]
    .PARAMETER XML
        The the WDAC policy XML content
    #>
    [CmdletBinding()]
    [OutputType([WDACConfig.Signer[]])]
    param(
        [System.Xml.XmlDocument]$XML
    )
    begin {
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false

        # Get User Mode Signers IDs
        $AllowedUMCISigners = [System.Collections.Generic.HashSet[System.String]]@(($XML.SiPolicy.SigningScenarios.SigningScenario.Where({ $_.value -eq '12' })).ProductSigners.AllowedSigners.AllowedSigner.SignerId)
        $DeniedUMCISigners = [System.Collections.Generic.HashSet[System.String]]@(($XML.SiPolicy.SigningScenarios.SigningScenario.Where({ $_.value -eq '12' })).ProductSigners.DeniedSigners.DeniedSigner.SignerId)

        # Get Kernel Mode Signers IDs
        $AllowedKMCISigners = [System.Collections.Generic.HashSet[System.String]]@(($XML.SiPolicy.SigningScenarios.SigningScenario.Where({ $_.value -eq '131' })).ProductSigners.AllowedSigners.AllowedSigner.SignerId)
        $DeniedKMCISigners = [System.Collections.Generic.HashSet[System.String]]@(($XML.SiPolicy.SigningScenarios.SigningScenario.Where({ $_.value -eq '131' })).ProductSigners.DeniedSigners.DeniedSigner.SignerId)

        # Unique IDs of all Allowed Signers
        $AllAllowedSigners = [System.Collections.Generic.HashSet[System.String]]@($AllowedUMCISigners.Clone())
        if ($null -ne $AllAllowedSigners -and $AllAllowedSigners.count -gt 0) {
            $AllAllowedSigners.UnionWith($AllowedKMCISigners)
        }

        # Unique IDs of all Denied Signers
        $AllDeniedSigners = [System.Collections.Generic.HashSet[System.String]]@($DeniedUMCISigners.Clone())
        if ($null -ne $AllDeniedSigners -and $AllDeniedSigners.count -gt 0) {
            $AllDeniedSigners.UnionWith($DeniedKMCISigners)
        }

        $WellKnownIDs = [System.Collections.Generic.HashSet[System.String]]::new(
            [System.String[]]@('03', '04', '05', '06', '07', '09', '0A', '0E', '0G', '0H', '0I'),
            # Make it case-insensitive
            [System.StringComparer]::InvariantCultureIgnoreCase
        )

        # WHQL EKU Hex value
        [System.String]$WHQLEKUHex = '010A2B0601040182370A0305'

        # an empty list to store the output
        $Output = New-Object -TypeName 'System.Collections.Generic.List[WDACConfig.Signer]'
    }
    process {

        # Loop through each Signer node and extract all of their information
        foreach ($Signer in $XML.SiPolicy.Signers.Signer) {

            if ($AllAllowedSigners.Contains($Signer.ID)) {
                [System.Boolean]$IsAllowed = $true
            }
            elseif ($AllDeniedSigners.Contains($Signer.ID)) {
                [System.Boolean]$IsAllowed = $false
            }
            else {
                # Skip if the current signer is neither an allowed nor a denied signer, meaning it can either be UpdatePolicySigner or SupplementalPolicySigner which we don't need for simulation
                continue
            }

            # Replacing Wellknown root IDs with their corresponding TBS values and Names (Common Names)
            # These are all root certificates, they have no leaf or intermediate certificates in their chains, that's why they're called Trusted Roots
            if ($WellKnownIDs.Contains($Signer.CertRoot.Value)) {
                switch ($Signer.CertRoot.Value) {
                    '03' {
                        $Signer.CertRoot.Value = 'D67576F5521D1CCAB52E9215E0F9F743'
                        $Signer.Name = 'Microsoft Authenticode(tm) Root Authority'
                        break
                    }
                    '04' {
                        $Signer.CertRoot.Value = '8B3C3087B7056F5EC5DDBA91A1B901F0'
                        $Signer.Name = 'Microsoft Root Authority'
                        break
                    }
                    '05' {
                        $Signer.CertRoot.Value = '391BE92883D52509155BFEAE27B9BD340170B76B'
                        $Signer.Name = 'Microsoft Root Certificate Authority'
                        break
                    }
                    '06' {
                        $Signer.CertRoot.Value = '08FBA831C08544208F5208686B991CA1B2CFC510E7301784DDF1EB5BF0393239'
                        $Signer.Name = 'Microsoft Root Certificate Authority 2010'
                        break
                    }
                    '07' {
                        $Signer.CertRoot.Value = '279CD652C4E252BFBE5217AC722205D7729BA409148CFA9E6D9E5B1CB94EAFF1'
                        $Signer.Name = 'Microsoft Root Certificate Authority 2011'
                        break
                    }
                    '09' {
                        $Signer.CertRoot.Value = '09CBAFBD98E81B4D6BAAAB32B8B2F5D7'
                        $Signer.Name = 'Microsoft Test Root Authority'
                        break
                    }
                    '0A' {
                        $Signer.CertRoot.Value = '7A4D9890B0F9006A6F77472D50D83CA54975FCC2B7EA0563490134E19B78782A'
                        $Signer.Name = 'Microsoft Testing Root Certificate Authority 2010'
                        break
                    }
                    '0E' {
                        $Signer.CertRoot.Value = 'ED55F82E1444F79CA9DCE826846FDC4E0EA3859E3D26EFEF412D2FFF0C7C8E6C'
                        $Signer.Name = 'Microsoft Development Root Certificate Authority 2014'
                        break
                    }
                    '0G' {
                        $Signer.CertRoot.Value = '68D221D720E975DB5CD14B24F2970F86A5B8605A2A1BC784A17B83F7CF500A70EB177CE228273B8540A800178F23EAC8'
                        $Signer.Name = 'Microsoft ECC Testing Root Certificate Authority 2017'
                        break
                    }
                    '0H' {
                        $Signer.CertRoot.Value = '214592CB01B59104195F80AF2886DBF85771AF42A3821D104BF18F415158C49CBC233511672CD6C432351AC9228E3E75'
                        $Signer.Name = 'Microsoft ECC Development Root Certificate Authority 2018'
                        break
                    }
                    '0I' {
                        $Signer.CertRoot.Value = '32991981BF1575A1A5303BB93A381723EA346B9EC130FDB596A75BA1D7CE0B0A06570BB985D25841E23BE944E8FF118F'
                        $Signer.Name = 'Microsoft ECC Product Root Certificate Authority 2018'
                        break
                    }
                }
            }

            #Region Scope Determinations
            # Determine the scope of the signer
            [System.String]$SignerScope = $AllowedUMCISigners.Contains($Signer.ID) ? 'UserMode' : 'KernelMode'
            #Endregion Scope Determination

            #Region File Attributes Processing
            # Determine whether the signer has a FileAttribRef, if it points to a file
            if ($Signer.FileAttribRef.RuleID) {

                # Get all the FileAttribs associated with the signer
                $FileAttribsAssociatedWithTheSigner = foreach ($ID in $Signer.FileAttribRef.RuleID) {
                    $XML.SiPolicy.FileRules.FileAttrib.Where({ $_.ID -eq $ID })
                }

                # The File Attributes property that will be added to the Signer object
                # It contains details of all File Attributes associated with the Signer
                $SignerFileAttributesProperty = New-Object -TypeName 'System.Collections.Generic.Dictionary[[System.String], [System.Collections.Generic.Dictionary[[System.String], [System.String]]]]'

                # Loop over each FileAttribute associated with the Signer
                foreach ($FileAttrib in $FileAttribsAssociatedWithTheSigner) {

                    # a temp dictionary to store the current FileAttribute details
                    $Temp = New-Object -TypeName 'System.Collections.Generic.Dictionary[[System.String], [System.String]]'

                    if ($null -ne $FileAttrib.FileName) {
                        $Temp.Add('OriginalFileName', $FileAttrib.FileName)
                        $Temp.Add('SpecificFileNameLevel', 'OriginalFileName')
                    }
                    if ($null -ne $FileAttrib.FileDescription) {
                        $Temp.Add('FileDescription', $FileAttrib.FileDescription)
                        $Temp.Add('SpecificFileNameLevel', 'FileDescription')
                    }
                    if ($null -ne $FileAttrib.InternalName) {
                        $Temp.Add('InternalName', $FileAttrib.InternalName)
                        $Temp.Add('SpecificFileNameLevel', 'InternalName')
                    }
                    if ($null -ne $FileAttrib.ProductName) {
                        $Temp.Add('ProductName', $FileAttrib.ProductName)
                        $Temp.Add('SpecificFileNameLevel', 'ProductName')
                    }
                    if ($null -ne $FileAttrib.MinimumFileVersion) {
                        $Temp.Add('MinimumFileVersion', $FileAttrib.MinimumFileVersion)
                    }
                    if ($null -ne $FileAttrib.MaximumFileVersion) {
                        $Temp.Add('MaximumFileVersion', $FileAttrib.MaximumFileVersion)
                    }

                    $SignerFileAttributesProperty.Add($FileAttrib.ID, $Temp)
                }
            }
            #Endregion File Attributes Processing

            #Region EKU Processing
            # Select the EKU nodes if they exist
            if ($XML.SiPolicy.EKUs.EKU) {

                # Create a hashtable to store the correlation between the EKU IDs and their values
                [System.Collections.Hashtable]$EKUAndValuesCorrelation = @{}

                # Add the EKU IDs and their values to the hashtable
                foreach ($EKUItem in $XML.SiPolicy.EKUs.EKU) {
                    $EKUAndValuesCorrelation.Add($EKUItem.ID, $EKUItem.Value)
                }
            }

            [System.Boolean]$HasEKU = $false
            [System.Boolean]$IsWHQL = $false

            # Convert all of the EKUs that apply to the signer to their OID values and store them with the Signer info
            [System.String[]]$CertEKUs = foreach ($EKU in $Signer.CertEKU.ID) {

                if ($EKUAndValuesCorrelation[$EKU] -eq $WHQLEKUHex) {
                    $IsWHQL = $true
                }
                $HasEKU = $true
                [WDACConfig.CertificateHelper]::ConvertHexToOID($EKUAndValuesCorrelation[$EKU])
            }
            #Endregion EKU Processing

            # Create a new instance of the Signer class in the WDACConfig Namespace And add it to the output
            $Output.Add([WDACConfig.Signer]::New(
                    $Signer.ID,
                    $Signer.Name,
                    $Signer.CertRoot.Value,
                    $Signer.CertPublisher.Value,
                    $Signer.CertIssuer.Value,
                    $CertEKUs,
                    $Signer.CertOemID.Value,
                    $Signer.FileAttribRef.RuleID,
                    $SignerFileAttributesProperty,
                    $SignerScope,
                    $IsWHQL,
                    $IsAllowed,
                    $HasEKU
                ))
        }
    }
    end {
        # Return the output array
        return $Output
    }
}
Export-ModuleMember -Function 'Get-SignerInfo'
