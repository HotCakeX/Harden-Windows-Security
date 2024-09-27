Function Compare-SignerAndCertificate {
    <#
    .SYNOPSIS
        The function that compares the signer information from the WDAC policy XML file with the certificate details of the signed file
    .INPUTS
        WDACConfig.SimulationInput
    .OUTPUTS
        System.Collections.Hashtable
    .PARAMETER SimulationInput
        The SimulationInput object that contains the necessary information for the simulation
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [Parameter(Mandatory = $true)][WDACConfig.SimulationInput]$SimulationInput
    )
    Begin {
        # Get the extended file attributes
        [WDACConfig.ExFileInfo]$ExtendedFileInfo = [WDACConfig.ExFileInfo]::GetExtendedFileInfo($SimulationInput.FilePath)
    }

    Process {

        # Loop through each signer in the signer information array, these are the signers in the XML policy file
        foreach ($Signer in $SimulationInput.SignerInfo) {

            # Make sure it's an allowed signer and not a denier
            if ($Signer.IsAllowed -ne $true) {
                continue
            }

            [WDACConfig.Logger]::Write("Checking the signer: $($Signer.Name)")

            # If the signer has any EKUs, try to match it with the file's EKU OIDs
            if ($Signer.HasEKU) {

                [WDACConfig.Logger]::Write('The signer has EKUs')
                [WDACConfig.Logger]::Write("The current file has $($SimulationInput.EKUOIDs.Count) EKUs")

                # Check if any of the Signer's OIDs match any of the file's certificates' OIDs (which are basically Leaf certificates' EKU OIDs)
                # This is used for all levels, not just WHQL levels
                [System.Boolean]$EKUsMatch = $false
                foreach ($EKU in $Signer.CertEKU) {
                    if ($SimulationInput.EKUOIDs -and $SimulationInput.EKUOIDs.Contains($EKU)) {
                        [System.Boolean]$EKUsMatch = $true
                        break
                    }
                }

                # If both the file and signer had EKUs and they match
                if ($EKUsMatch) {

                    [WDACConfig.Logger]::Write("The EKUs of the signer matched with the file's EKUs")

                    # If the signer and file have matching EKUs and the signer is WHQL then start checking for OemID
                    if ($Signer.IsWHQL) {

                        [WDACConfig.Logger]::Write('The signer is WHQL')

                        # At this point the file is definitely WHQL-Signed

                        # Get the WHQL chain packages by checking for any chain whose leaf certificate contains the WHQL EKU OID
                        [WDACConfig.ChainPackage[]]$WHQLChainPackagesCandidates = $SimulationInput.AllFileSigners.Where({ $_.LeafCertificate.Certificate.EnhancedKeyUsageList.ObjectId.Contains('1.3.6.1.4.1.311.10.3.5') })

                        # HashSet to store all of the Opus data from the WHQL chain packages candidates
                        $Current_Chain_Opus = New-Object -TypeName 'System.Collections.Generic.HashSet[System.String]'

                        # List of [WDACConfig.OpusSigner] objects which are pairs of each Intermediate Certificate TBSHash and its corresponding SubjectCN
                        $OpusSigners = New-Object -TypeName 'System.Collections.Generic.List[WDACConfig.OpusSigner]'

                        # Loop through each candidate WHQL chain package
                        foreach ($ChainPackage in $WHQLChainPackagesCandidates) {

                            # Try to get the Opus data of the current chain (essentially the current chain's leaf certificate)
                            try {
                                $CurrentOpusData = ([WDACConfig.Opus]::GetOpusData($ChainPackage.SignedCms)).CertOemID
                            }
                            catch {}

                            # If there was Opus data
                            if ($CurrentOpusData.count -gt 0) {
                                # Add the Opus data to the HashSet
                                [System.Void]$Current_Chain_Opus.Add($CurrentOpusData)
                            }

                            # Capture the details of the WHQL signers, aka Intermediate certificate(s) of the signer package that had WHQL EKU
                            # In case there are more than 1 intermediate certificates in the chain, add all of them to the HashSets
                            # regardless of whether they have Opus data or not because we'll use these data for the WHQL level too and that level doesn't require Opus data match
                            foreach ($IntermediateCert in $ChainPackage.IntermediateCertificates) {

                                # Add the current TBSHash and SubjectCN pair of the intermediate certificate to the list
                                $OpusSigners.Add(
                                    [WDACConfig.OpusSigner]::New(
                                        $IntermediateCert.TBSValue,
                                        $IntermediateCert.SubjectCN
                                    )
                                )
                            }
                        }

                        # Flag indicating if the Opus data of the current signer matched with one of the file's leaf certificates Opus data
                        # Making it eligible for WHQLFilePublisher and WHQLPublisher levels
                        # if true, CertOemID of the signer matches the EKU Opus data of the file (This should belong to the leaf certificate of the file as it's the one with EKUs)
                        [System.Boolean]$OpusMatch = $Current_Chain_Opus.Contains($Signer.CertOemID)

                        # Loop through each OpusSigner
                        # This is to ensure when a file is signed by more than 1 WHQL signer then it will be properly validated as these are pairs of TBSHash and SubjectCN of each WHQL signer's details
                        foreach ($OpusSigner in $OpusSigners) {

                            # Check if the selected file's signer chain's intermediate certificates match the current signer's details
                            if (($Signer.CertRoot -eq $OpusSigner.TBSHash) -and ($Signer.Name -eq $OpusSigner.SubjectCN)) {

                                # At this point the file meets the criteria for one of the WHQL levels

                                # Indicating it's WHQLFilePublisher signer
                                if ($OpusMatch -and $Signer.FileAttrib) {

                                    [System.Collections.Hashtable[]]$CandidateFileAttrib = foreach ($Attrib in $signer.FileAttrib.GetEnumerator()) {

                                        if ($ExtendedFileInfo.Version -ge [System.Version]::New($Attrib.Value.MinimumFileVersion)) {
                                            $Attrib.Value
                                        }
                                    }

                                    # Loop over all of the candidate file attributes (if they exists) to find a match with the file's extended info
                                    if ($null -ne $CandidateFileAttrib) {
                                        foreach ($FileAttrib in $CandidateFileAttrib.GetEnumerator()) {

                                            foreach ($KeyItem in ('OriginalFileName', 'InternalName', 'ProductName', 'Version', 'FileDescription')) {

                                                if (($null -ne $ExtendedFileInfo.$KeyItem) -and ($ExtendedFileInfo.$KeyItem -eq $FileAttrib.$KeyItem)) {

                                                    [WDACConfig.Logger]::Write("The SpecificFileNameLevel is $KeyItem")

                                                    # If there was a match then assign the $KeyItem which is the name of the SpecificFileNameLevel option to the $CurrentFileInfo.SpecificFileNameLevelMatchCriteria

                                                    <#
                                                    ELIGIBILITY CHECK FOR LEVELS: WHQLFilePublisher

                                                    CRITERIA:
                                                    1) The signer's CertRoot (referring to the TBS value in the xml file which belongs to the intermediate cert of the file signed by Microsoft) Matches the TBSValue of the file's certificate that belongs to Microsoft WHQL program
                                                    2) The signer's name (Referring to the one in the XML file) matches the same Intermediate certificate's SubjectCN, the certificate that belongs to Microsoft WHQL program
                                                    3) The signer's CertEKU points to the WHQL EKU OID and one of the file's leaf certificates contains this EKU OID
                                                    4) The signer's CertOemID matches one of the Opus data of the file's certificates (Leaf certificates as they are the ones with EKUs)
                                                    5) The signer's FileAttribRef(s) point to the same file that is currently being investigated
                                                    #>

                                                    return ([WDACConfig.SimulationOutput]::New(
                                                        ([System.IO.Path]::GetFileName($SimulationInput.FilePath)),
                                                            'Signer',
                                                            $true,
                                                            $Signer.ID,
                                                            $Signer.Name,
                                                            $Signer.CertRoot,
                                                            $Signer.CertPublisher,
                                                            $Signer.SignerScope,
                                                            $Signer.FileAttribRef,
                                                            'WHQLFilePublisher',
                                                            $KeyItem,
                                                            $OpusSigner.SubjectCN,
                                                            $null, # Intentionally not collecting this info when forming the OpusSigners but the info is there if needed
                                                            $null, # Intentionally not collecting this info when forming the OpusSigners but the info is there if needed
                                                            $OpusSigner.TBSHash,
                                                            $SimulationInput.FilePath
                                                        ))
                                                }
                                            }
                                        }
                                    }
                                }

                                <#
                                ELIGIBILITY CHECK FOR LEVELS: WHQLPublisher

                                CRITERIA:
                                1) The signer's CertRoot (referring to the TBS value in the xml file which belongs to the intermediate cert of the file signed by Microsoft) Matches the TBSValue of the file's certificate that belongs to Microsoft WHQL program
                                2) The signer's name (Referring to the one in the XML file) matches the same Intermediate certificate's SubjectCN, the certificate that belongs to Microsoft WHQL program
                                3) The signer's CertEKU points to the WHQL EKU OID and one of the file's leaf certificates contains this EKU OID
                                4) The signer's CertOemID matches one of the Opus data of the file's certificates (Leaf certificates as they are the ones with EKUs)
                                #>
                                elseif ($OpusMatch) {

                                    # If the signer has FileAttributes meaning it's either WHQLFilePublisher, FilePublisher or SignedVersion then do not use it for other levels
                                    if ($Signer.FileAttribRef) { Continue }

                                    return ([WDACConfig.SimulationOutput]::New(
                                        ([System.IO.Path]::GetFileName($SimulationInput.FilePath)),
                                            'Signer',
                                            $true,
                                            $Signer.ID,
                                            $Signer.Name,
                                            $Signer.CertRoot,
                                            $Signer.CertPublisher,
                                            $Signer.SignerScope,
                                            $Signer.FileAttribRef,
                                            'WHQLPublisher',
                                            $null,
                                            $OpusSigner.SubjectCN,
                                            $null,
                                            $null,
                                            $OpusSigner.TBSHash,
                                            $SimulationInput.FilePath
                                        ))
                                }

                                <#
                                ELIGIBILITY CHECK FOR LEVELS: WHQL

                                CRITERIA:
                                1) The signer's CertRoot (referring to the TBS value in the xml file which belongs to the intermediate cert of the file signed by Microsoft) Matches the TBSValue of the file's certificate that belongs to Microsoft WHQL program
                                2) The signer's name (Referring to the one in the XML file) matches the same Intermediate certificate's SubjectCN, the certificate that belongs to Microsoft WHQL program
                                3) The signer's CertEKU points to the WHQL EKU OID and one of the file's leaf certificates contains this EKU OID
                                #>
                                else {

                                    # If the signer has FileAttributes meaning it's either WHQLFilePublisher, FilePublisher or SignedVersion then do not use it for other levels
                                    if ($Signer.FileAttribRef) { Continue }

                                    return ([WDACConfig.SimulationOutput]::New(
                                        ([System.IO.Path]::GetFileName($SimulationInput.FilePath)),
                                            'Signer',
                                            $true,
                                            $Signer.ID,
                                            $Signer.Name,
                                            $Signer.CertRoot,
                                            $Signer.CertPublisher,
                                            $Signer.SignerScope,
                                            $Signer.FileAttribRef,
                                            'WHQL',
                                            $null,
                                            $OpusSigner.SubjectCN,
                                            $null,
                                            $null,
                                            $OpusSigner.TBSHash,
                                            $SimulationInput.FilePath
                                        ))
                                }
                            }
                        }

                        if ($Signer.IsWHQL -and $EKUsMatch) {

                            # If the Signer has EKU, it was WHQL EKU but there was no WHQL level match made with the file's properties then skip the current signer
                            # as the rest of the levels are not applicable for a WHQL type of signer
                            Continue
                        }
                    }
                    #  else {
                    # If the signer isn't WHQL, just a regular signer with EKU and they matched with the file's EKUs
                    # Then do nothing and let the normal rules below handle them
                    #  }

                }
                else {
                    [WDACConfig.Logger]::Write("The signer had EKUs but they didn't match with the file's EKUs")
                    # If the signer has EKU but it didn't match with the file's EKU then skip the current signer
                    # as it shouldn't be used for any other levels
                    Continue
                }
            }

            # Loop through each certificate chain
            foreach ($Chain in $SimulationInput.AllFileSigners) {

                # Loop over each intermediate certificate in the chain
                foreach ($IntermediateCert in $Chain.IntermediateCertificates) {

                    <#
                    ELIGIBILITY CHECK FOR LEVELS: FilePublisher, Publisher, SignedVersion

                    CRITERIA:
                    1) The signer's CertRoot (referring to the TBS value in the xml file which belongs to an intermediate cert of the file) Matches the TBSValue of one of the file's intermediate certificates
                    2) The signer's name (Referring to the one in the XML file) matches the same Intermediate certificate's SubjectCN
                    3) The signer's CertPublisher (aka Leaf Certificate's CN used in the xml policy) matches the current chain's leaf certificate's SubjectCN
                    #>
                    if (($Signer.CertRoot -eq $IntermediateCert.TBSValue) -and ($Signer.Name -eq $IntermediateCert.SubjectCN) -and ($Signer.CertPublisher -eq $Chain.LeafCertificate.SubjectCN)) {

                        # Check if the matched signer has FileAttrib indicating that it was generated either with FilePublisher or SignedVersion level
                        if ($Signer.FileAttrib) {

                            [System.Collections.Hashtable[]]$CandidateFileAttrib = foreach ($Attrib in $signer.FileAttrib.GetEnumerator()) {

                                if ($ExtendedFileInfo.Version -ge [System.Version]::New($Attrib.Value.MinimumFileVersion)) {
                                    $Attrib.Value
                                }
                            }

                            # If the signer has a file attribute with a wildcard file name, then it's a SignedVersion level signer
                            # These signers have only 1 FileAttribRef and only point to a single FileAttrib
                            # If a SignedVersion signer applies to multiple files, the version number of the FileAttrib is set to the minimum version of the files
                            if (($CandidateFileAttrib.count -eq 1) -and ($CandidateFileAttrib.OriginalFileName -eq '*')) {

                                return ([WDACConfig.SimulationOutput]::New(
                                    ([System.IO.Path]::GetFileName($SimulationInput.FilePath)),
                                        'Signer',
                                        $true,
                                        $Signer.ID,
                                        $Signer.Name,
                                        $Signer.CertRoot,
                                        $Signer.CertPublisher,
                                        $Signer.SignerScope,
                                        $Signer.FileAttribRef,
                                        'SignedVersion',
                                        'Version',
                                        $IntermediateCert.SubjectCN,
                                        $IntermediateCert.IssuerCN,
                                        $IntermediateCert.NotAfter,
                                        $IntermediateCert.TBSValue,
                                        $SimulationInput.FilePath
                                    ))
                            }

                            # Loop over all of the candidate file attributes (if they exists) to find a match with the file's extended info
                            if ($null -ne $CandidateFileAttrib) {
                                foreach ($FileAttrib in $CandidateFileAttrib.GetEnumerator()) {

                                    # Loop over all of the keys in the extended file info to see which one of them is a match, to determine the SpecificFileNameLevel option
                                    foreach ($KeyItem in ('OriginalFileName', 'InternalName', 'ProductName', 'Version', 'FileDescription')) {

                                        if (($null -ne $ExtendedFileInfo.$KeyItem) -and ($ExtendedFileInfo.$KeyItem -eq $FileAttrib.$KeyItem)) {

                                            [WDACConfig.Logger]::Write("The SpecificFileNameLevel is $KeyItem")

                                            # If there was a match then assign the $KeyItem which is the name of the SpecificFileNameLevel option to the $CurrentFileInfo.SpecificFileNameLevelMatchCriteria
                                            # And break out of the loop by validating the signer as suitable for FilePublisher level
                                            return ([WDACConfig.SimulationOutput]::New(
                                                ([System.IO.Path]::GetFileName($SimulationInput.FilePath)),
                                                    'Signer',
                                                    $true,
                                                    $Signer.ID,
                                                    $Signer.Name,
                                                    $Signer.CertRoot,
                                                    $Signer.CertPublisher,
                                                    $Signer.SignerScope,
                                                    $Signer.FileAttribRef,
                                                    'FilePublisher',
                                                    $KeyItem,
                                                    $IntermediateCert.SubjectCN,
                                                    $IntermediateCert.IssuerCN,
                                                    $IntermediateCert.NotAfter,
                                                    $IntermediateCert.TBSValue,
                                                    $SimulationInput.FilePath
                                                ))
                                        }
                                    }
                                }
                            }
                        }
                        # If the Signer matched and it doesn't have a FileAttrib, then it's a Publisher level signer
                        else {
                            # If the signer has FileAttributes meaning it's either WHQLFilePublisher, FilePublisher or SignedVersion then do not use it for other levels
                            if ($Signer.FileAttribRef) { Continue }

                            return ([WDACConfig.SimulationOutput]::New(
                                ([System.IO.Path]::GetFileName($SimulationInput.FilePath)),
                                    'Signer',
                                    $true,
                                    $Signer.ID,
                                    $Signer.Name,
                                    $Signer.CertRoot,
                                    $Signer.CertPublisher,
                                    $Signer.SignerScope,
                                    $Signer.FileAttribRef,
                                    'Publisher',
                                    $null,
                                    $IntermediateCert.SubjectCN,
                                    $IntermediateCert.IssuerCN,
                                    $IntermediateCert.NotAfter,
                                    $IntermediateCert.TBSValue,
                                    $SimulationInput.FilePath
                                ))
                        }
                    }

                    <#
                    ELIGIBILITY CHECK FOR LEVELS: PcaCertificate, RootCertificate

                    CRITERIA:
                    1) The signer's CertRoot (referring to the TBS value in the xml file which belongs to an intermediate cert of the file) Matches the TBSValue of one of the file's intermediate certificates
                    2) The signer's name (Referring to the one in the XML file) matches the same Intermediate certificate's SubjectCN
                    #>
                    elseif (($Signer.CertRoot -eq $IntermediateCert.TBSValue) -and ($Signer.Name -eq $IntermediateCert.SubjectCN)) {

                        # If the signer has FileAttributes meaning it's either WHQLFilePublisher, FilePublisher or SignedVersion then do not use it for other levels
                        if ($Signer.FileAttribRef) { Continue }

                        return ([WDACConfig.SimulationOutput]::New(
                            ([System.IO.Path]::GetFileName($SimulationInput.FilePath)),
                                'Signer',
                                $true,
                                $Signer.ID,
                                $Signer.Name,
                                $Signer.CertRoot,
                                $Signer.CertPublisher,
                                $Signer.SignerScope,
                                $Signer.FileAttribRef,
                                'PcaCertificate/RootCertificate',
                                $null,
                                $IntermediateCert.SubjectCN,
                                $IntermediateCert.IssuerCN,
                                $IntermediateCert.NotAfter,
                                $IntermediateCert.TBSValue,
                                $SimulationInput.FilePath
                            ))
                    }
                }

                <#
                ELIGIBILITY CHECK FOR LEVELS: LeafCertificate

                CRITERIA:
                1) The Signer's CertRoot (referring to the TBS value in the xml file, which belongs to the leaf certificate of the file when LeafCertificate level is used) matches the TBSValue of the file's Leaf certificate certificates
                2) The signer's name (Referring to the one in the XML file) matches the Leaf certificate's SubjectCN
                #>
                if (($Signer.CertRoot -eq $Chain.LeafCertificate.TBSValue) -and ($Signer.Name -eq $Chain.LeafCertificate.SubjectCN)) {

                    # If the signer has FileAttributes meaning it's either WHQLFilePublisher, FilePublisher or SignedVersion then do not use it for other levels
                    if ($Signer.FileAttribRef) { Continue }

                    return ([WDACConfig.SimulationOutput]::New(
                        ([System.IO.Path]::GetFileName($SimulationInput.FilePath)),
                            'Signer',
                            $true,
                            $Signer.ID,
                            $Signer.Name,
                            $Signer.CertRoot,
                            $Signer.CertPublisher,
                            $Signer.SignerScope,
                            $Signer.FileAttribRef,
                            'LeafCertificate',
                            $null,
                            $Chain.LeafCertificate.SubjectCN,
                            $Chain.LeafCertificate.IssuerCN,
                            $Chain.LeafCertificate.NotAfter,
                            $Chain.LeafCertificate.TBSValue,
                            $SimulationInput.FilePath
                        ))
                }

                #Region ROOT CERTIFICATE ELIGIBILITY CHECK

                # This is regardless of how many certificates exist in the current chain

                <#
                ELIGIBILITY CHECK FOR LEVELS: FilePublisher, Publisher, SignedVersion

                CRITERIA:
                1) The signer's CertRoot (referring to the TBS value in the xml file which belongs to the Root Certificate of the file when there is only 1 Element in the chain) Matches the TBSValue of the file's root certificate
                2) The signer's name (Referring to the one in the XML file) matches the same Root certificate's SubjectCN
                3) The signer's CertPublisher matches the Root certificate's SubjectCN
                #>
                if (($Signer.CertRoot -eq $Chain.RootCertificate.TBSValue) -and ($Signer.Name -eq $Chain.RootCertificate.SubjectCN) -and ($Signer.CertPublisher -eq $Chain.RootCertificate.SubjectCN)) {

                    # Check if the matched signer has FileAttrib indicating that it was generated either with FilePublisher or SignedVersion level
                    if ($Signer.FileAttrib) {

                        # Get all of the File Attributes associated with the signer and check if the file's version is greater than or equal to the minimum version in them
                        [System.Collections.Hashtable[]]$CandidateFileAttrib = foreach ($Attrib in $signer.FileAttrib.GetEnumerator()) {

                            if ($ExtendedFileInfo.Version -ge [System.Version]::New($Attrib.Value.MinimumFileVersion)) {
                                $Attrib.Value
                            }
                        }

                        # If the signer has a file attribute with a wildcard file name, then it's a SignedVersion level signer
                        # These signers have only 1 FileAttribRef and only point to a single FileAttrib
                        # If a SignedVersion signer applies to multiple files, the version number of the FileAttrib is set to the minimum version of the files
                        if (($CandidateFileAttrib.count -eq 1) -and ($CandidateFileAttrib.OriginalFileName -eq '*')) {

                            return ([WDACConfig.SimulationOutput]::New(
                                ([System.IO.Path]::GetFileName($SimulationInput.FilePath)),
                                    'Signer',
                                    $true,
                                    $Signer.ID,
                                    $Signer.Name,
                                    $Signer.CertRoot,
                                    $Signer.CertPublisher,
                                    $Signer.SignerScope,
                                    $Signer.FileAttribRef,
                                    'SignedVersion',
                                    'Version',
                                    $Chain.RootCertificate.SubjectCN,
                                    $Chain.RootCertificate.IssuerCN,
                                    $Chain.RootCertificate.NotAfter,
                                    $Chain.RootCertificate.TBSValue,
                                    $SimulationInput.FilePath
                                ))
                        }

                        # Loop over all of the candidate file attributes (if they exists) to find a match with the file's extended info
                        if ($null -ne $CandidateFileAttrib) {
                            foreach ($FileAttrib in $CandidateFileAttrib.GetEnumerator()) {

                                foreach ($KeyItem in ('OriginalFileName', 'InternalName', 'ProductName', 'Version', 'FileDescription')) {

                                    if (($null -ne $ExtendedFileInfo.$KeyItem) -and ($ExtendedFileInfo.$KeyItem -eq $FileAttrib.$KeyItem)) {

                                        [WDACConfig.Logger]::Write("The SpecificFileNameLevel is $KeyItem")

                                        # If there was a match then assign the $KeyItem which is the name of the SpecificFileNameLevel option to the $CurrentFileInfo.SpecificFileNameLevelMatchCriteria
                                        # And break out of the loop by validating the signer as suitable for FilePublisher level

                                        return ([WDACConfig.SimulationOutput]::New(
                                            ([System.IO.Path]::GetFileName($SimulationInput.FilePath)),
                                                'Signer',
                                                $true,
                                                $Signer.ID,
                                                $Signer.Name,
                                                $Signer.CertRoot,
                                                $Signer.CertPublisher,
                                                $Signer.SignerScope,
                                                $Signer.FileAttribRef,
                                                'FilePublisher',
                                                $KeyItem,
                                                $Chain.RootCertificate.SubjectCN,
                                                $Chain.RootCertificate.IssuerCN,
                                                $Chain.RootCertificate.NotAfter,
                                                $Chain.RootCertificate.TBSValue,
                                                $SimulationInput.FilePath
                                            ))
                                    }
                                }
                            }
                        }
                    }
                    # If the Signer matched and it doesn't have a FileAttrib, then it's a Publisher level signer
                    else {
                        # If the signer has FileAttributes meaning it's either WHQLFilePublisher, FilePublisher or SignedVersion then do not use it for other levels
                        if ($Signer.FileAttribRef) { Continue }

                        return ([WDACConfig.SimulationOutput]::New(
                            ([System.IO.Path]::GetFileName($SimulationInput.FilePath)),
                                'Signer',
                                $true,
                                $Signer.ID,
                                $Signer.Name,
                                $Signer.CertRoot,
                                $Signer.CertPublisher,
                                $Signer.SignerScope,
                                $Signer.FileAttribRef,
                                'Publisher',
                                $null,
                                $Chain.RootCertificate.SubjectCN,
                                $Chain.RootCertificate.IssuerCN,
                                $Chain.RootCertificate.NotAfter,
                                $Chain.RootCertificate.TBSValue,
                                $SimulationInput.FilePath
                            ))
                    }
                }

                <#
                ELIGIBILITY CHECK FOR LEVELS: PcaCertificate, RootCertificate (LeafCertificate will also generate the same type of signer)

                CRITERIA:
                1) The signer's CertRoot (referring to the TBS value in the xml file which belongs to the Root Certificate of the file when there is only 1 Element in the chain) Matches the TBSValue of the file's root certificate
                2) The signer's name (Referring to the one in the XML file) matches the same Root certificate's SubjectCN
                #>
                elseif (($Signer.CertRoot -eq $Chain.RootCertificate.TBSValue) -and ($Signer.Name -eq $Chain.RootCertificate.SubjectCN)) {

                    # If the signer has FileAttributes meaning it's either WHQLFilePublisher, FilePublisher or SignedVersion then do not use it for other levels
                    if ($Signer.FileAttribRef) { Continue }

                    return ([WDACConfig.SimulationOutput]::New(
                        ([System.IO.Path]::GetFileName($SimulationInput.FilePath)),
                            'Signer',
                            $true,
                            $Signer.ID,
                            $Signer.Name,
                            $Signer.CertRoot,
                            $Signer.CertPublisher,
                            $Signer.SignerScope,
                            $Signer.FileAttribRef,
                            'PcaCertificate/RootCertificate',
                            $null,
                            $Chain.RootCertificate.SubjectCN,
                            $Chain.RootCertificate.IssuerCN,
                            $Chain.RootCertificate.NotAfter,
                            $Chain.RootCertificate.TBSValue,
                            $SimulationInput.FilePath
                        ))
                }

                #Endregion ROOT CERTIFICATE ELIGIBILITY CHECK
            }
        }

        # The file is signed but the signer wasn't found in the policy file that allows it
        return ([WDACConfig.SimulationOutput]::New(
            ([System.IO.Path]::GetFileName($SimulationInput.FilePath)),
                'Signer',
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
                $SimulationInput.FilePath
            ))
    }
}

Export-ModuleMember -Function 'Compare-SignerAndCertificate'
