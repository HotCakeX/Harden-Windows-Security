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
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Importing the required sub-modules
        Import-Module -FullyQualifiedName "$ModuleRootPath\WDACSimulation\Get-ExtendedFileInfo.psm1" -Force

        # A hashtable that holds the details of the current file
        $CurrentFileInfo = [System.Collections.Hashtable]@{
            SignerID                           = ''       # Gathered from the Get-SignerInfo function
            SignerName                         = ''       # Gathered from the Get-SignerInfo function
            SignerCertRoot                     = ''       # Gathered from the Get-SignerInfo function
            SignerCertPublisher                = ''       # Gathered from the Get-SignerInfo function
            SignerScope                        = ''       # Gathered from the Get-SignerInfo function
            HasFileAttrib                      = $false   # Gathered from the Get-SignerInfo function
            SignerFileAttributeIDs             = @()      # Gathered from the Get-SignerInfo function
            MatchCriteria                      = ''
            SpecificFileNameLevelMatchCriteria = ''       # Only those eligible for FilePublisher or SignedVersion levels assign this value, otherwise it stays empty
            CertSubjectCN                      = ''
            CertIssuerCN                       = ''
            CertNotAfter                       = ''
            CertTBSValue                       = ''
            FilePath                           = $SimulationInput.FilePath
        }

        # Get the extended file attributes
        [System.Collections.Hashtable]$ExtendedFileInfo = Get-ExtendedFileInfo -Path $SimulationInput.FilePath
    }

    Process {

        # Loop through each signer in the signer information array, these are the signers in the XML policy file
        :MainSignerLoop foreach ($Signer in $SimulationInput.SignerInfo) {

            # If the signer has any EKUs, try to match it with the file's EKU OIDs
            if ($Signer.HasEKU) {

                # Check if any of the Signer's OIDs match any of the file's certificates' OIDs (which are basically Leaf certificates' EKU OIDs)
                # This is used for all levels, not just WHQL levels
                [System.Boolean]$EKUsMatch = $false
                foreach ($EKU in $Signer.CertEKU) {
                    if ($SimulationInput.EKUOIDs.Contains($EKU)) {
                        [System.Boolean]$EKUsMatch = $true
                        break
                    }
                }

                # If both the file and signer had EKUs and they match
                if ($EKUsMatch) {

                    # If the signer and file have matching EKUs and the signer is WHQL then start checking for OemID
                    if ($Signer.IsWHQL) {

                        # At this point the file is definitely WHQL-Signed

                        # Get the WHQL chain packages by checking for any chain whose leaf certificate contains the WHQL EKU OID
                        [WDACConfig.ChainPackage[]]$WHQLChainPackagesCandidates = $SimulationInput.AllFileSigners.Where({ $_.LeafCertificate.Certificate.EnhancedKeyUsageList.ObjectId.Contains('1.3.6.1.4.1.311.10.3.5') })

                        # HashSet to store all of the Opus data from the WHQL chain packages candidates
                        $Current_Chain_Opus = New-Object -TypeName 'System.Collections.Generic.HashSet[System.String]'

                        # List of [WDACConfig.OpusSigner] objects which are pairs of each Intermediate Certificate TBSHash and its corresponding SubjectCN
                        $OpusSigners = New-Object -TypeName 'System.Collections.Generic.List[WDACConfig.OpusSigner]'

                        # Loop through each candidate WHQL chain package
                        foreach ($ChainPackage in $WHQLChainPackagesCandidates) {

                            # Try to get the Opus data of the current chain
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

                        # Flag indicating if the Opus data of the signer matched with the file's certificates
                        # Making it eligible for WHQLFilePublisher and WHQLPublisher levels
                        # if true, CertOemID of the signer matches the EKU Opus data of the file (This should belong to the leaf certificate of the file as it's the one with EKUs)
                        [System.Boolean]$OpusMatch = $Current_Chain_Opus.Contains($Signer.CertOemID)

                        # Loop through each OpusSigner
                        # This is to ensure when a file is signed by more than 1 WHQL signer then it will be properly validated as these are pairs of TBSHash and SubjectCN of each WHQL signer's details
                        foreach ($OpusSigner in $OpusSigners) {

                            # Check if the selected file's signer chain's intermediate certificates match the current signer's details
                            if (($OpusSigner.TBSHash -eq $Signer.CertRoot) -and ($OpusSigner.SubjectCN -eq $Signer.Name)) {

                                # At this point the file meets the criteria for one of the WHQL levels

                                # Indicating it's WHQLFilePublisher signer
                                if ($OpusMatch -and $Signer.FileAttrib) {

                                    [System.Collections.Hashtable[]]$CandidateFileAttrib = foreach ($Attrib in $signer.FileAttrib.GetEnumerator()) {

                                        if ($ExtendedFileInfo['FileVersion'] -ge $Attrib.Value.MinimumFileVersion) {
                                            $Attrib.Value
                                        }
                                    }

                                    # Loop over all of the candidate file attributes to find a match with the file's extended info
                                    foreach ($FileAttrib in $CandidateFileAttrib.GetEnumerator()) {

                                        # Loop over all of the keys in the extended file info to see which one of them is a match, to determine the SpecificFileNameLevel option
                                        foreach ($KeyItem in $ExtendedFileInfo.Keys) {

                                            if ($ExtendedFileInfo.$KeyItem -eq $FileAttrib.$KeyItem) {

                                                Write-Verbose -Message "The SpecificFileNameLevel is $KeyItem"

                                                # If there was a match then assign the $KeyItem which is the name of the SpecificFileNameLevel option to the $CurrentFileInfo.SpecificFileNameLevelMatchCriteria
                                                # And break out of the loop by validating the signer as suitable for FilePublisher level

                                                <#
                                                ELIGIBILITY CHECK FOR LEVELS: WHQLFilePublisher

                                                CRITERIA:
                                                1) The signer's CertRoot (referring to the TBS value in the xml file which belongs to the intermediate cert of the file signed by Microsoft) Matches the TBSValue of the file's certificate that belongs to Microsoft WHQL program
                                                2) The signer's name (Referring to the one in the XML file) matches the same Intermediate certificate's SubjectCN, the certificate that belongs to Microsoft WHQL program
                                                3) The signer's CertEKU points to the WHQL EKU OID and one of the file's leaf certificates contains this EKU OID
                                                4) The signer's CertOemID matches one of the Opus data of the file's certificates (Leaf certificates as they are the ones with EKUs)
                                                5) The signer's FileAttribRef(s) point to the same file that is currently being investigated
                                                #>

                                                $CurrentFileInfo.SignerID = $Signer.ID
                                                $CurrentFileInfo.SignerName = $Signer.Name
                                                $CurrentFileInfo.SignerCertRoot = $Signer.CertRoot
                                                $CurrentFileInfo.SignerCertPublisher = $Signer.CertPublisher
                                                $CurrentFileInfo.SignerScope = $Signer.SignerScope
                                                $CurrentFileInfo.HasFileAttrib = $Signer.HasFileAttrib
                                                $CurrentFileInfo.SignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                                                $CurrentFileInfo.SpecificFileNameLevelMatchCriteria = [System.String]$KeyItem
                                                $CurrentFileInfo.MatchCriteria = 'WHQLFilePublisher'
                                                $CurrentFileInfo.CertSubjectCN = $Certificate.SubjectCN
                                                $CurrentFileInfo.CertIssuerCN = $Certificate.IssuerCN
                                                $CurrentFileInfo.CertNotAfter = $Certificate.NotAfter
                                                $CurrentFileInfo.CertTBSValue = $Certificate.TBSValue

                                                break MainSignerLoop

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
                                    $CurrentFileInfo.SignerID = $Signer.ID
                                    $CurrentFileInfo.SignerName = $Signer.Name
                                    $CurrentFileInfo.SignerCertRoot = $Signer.CertRoot
                                    $CurrentFileInfo.SignerCertPublisher = $Signer.CertPublisher
                                    $CurrentFileInfo.SignerScope = $Signer.SignerScope
                                    $CurrentFileInfo.HasFileAttrib = $Signer.HasFileAttrib
                                    $CurrentFileInfo.SignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                                    $CurrentFileInfo.MatchCriteria = 'WHQLPublisher'
                                    $CurrentFileInfo.CertSubjectCN = $Certificate.SubjectCN
                                    $CurrentFileInfo.CertIssuerCN = $Certificate.IssuerCN
                                    $CurrentFileInfo.CertNotAfter = $Certificate.NotAfter
                                    $CurrentFileInfo.CertTBSValue = $Certificate.TBSValue

                                    break MainSignerLoop
                                }

                                <#
                                ELIGIBILITY CHECK FOR LEVELS: WHQL

                                CRITERIA:
                                1) The signer's CertRoot (referring to the TBS value in the xml file which belongs to the intermediate cert of the file signed by Microsoft) Matches the TBSValue of the file's certificate that belongs to Microsoft WHQL program
                                2) The signer's name (Referring to the one in the XML file) matches the same Intermediate certificate's SubjectCN, the certificate that belongs to Microsoft WHQL program
                                3) The signer's CertEKU points to the WHQL EKU OID and one of the file's leaf certificates contains this EKU OID
                                #>
                                else {
                                    $CurrentFileInfo.SignerID = $Signer.ID
                                    $CurrentFileInfo.SignerName = $Signer.Name
                                    $CurrentFileInfo.SignerCertRoot = $Signer.CertRoot
                                    $CurrentFileInfo.SignerCertPublisher = $Signer.CertPublisher
                                    $CurrentFileInfo.SignerScope = $Signer.SignerScope
                                    $CurrentFileInfo.HasFileAttrib = $Signer.HasFileAttrib
                                    $CurrentFileInfo.SignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                                    $CurrentFileInfo.MatchCriteria = 'WHQL'
                                    $CurrentFileInfo.CertSubjectCN = $Certificate.SubjectCN
                                    $CurrentFileInfo.CertIssuerCN = $Certificate.IssuerCN
                                    $CurrentFileInfo.CertNotAfter = $Certificate.NotAfter
                                    $CurrentFileInfo.CertTBSValue = $Certificate.TBSValue

                                    break MainSignerLoop
                                }
                            }
                        }

                        if ($Signer.IsWHQL -and $EKUsMatch) {

                            # If the Signer has EKU, it was WHQL EKU but there was no WHQL level match made with the file's properties then break
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
                    # If the signer has EKU but it didn't match with the file's EKU then skip the current signer
                    # as it shouldn't be used for any other levels
                    Continue
                }
            }

            # Loop through each certificate chain
            foreach ($Chain in $SimulationInput.AllFileSigners) {

                Switch ($Chain.CertificateChain.ChainElements.Count) {

                    # If the current chain in the loop being investigated has Root, at least one Intermediate and Leaf certificate
                    { $_ -gt 2 } {

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

                                        if ($ExtendedFileInfo['FileVersion'] -ge $Attrib.Value.MinimumFileVersion) {
                                            $Attrib.Value
                                        }
                                    }

                                    # If the signer has a file attribute with a wildcard file name, then it's a SignedVersion level signer
                                    # These signers have only 1 FileAttribRef and only point to a single FileAttrib
                                    # If a SignedVersion signer applies to multiple files, the version number of the FileAttrib is set to the minimum version of the files
                                    if (($CandidateFileAttrib.count -eq 1) -and ($CandidateFileAttrib.FileName -eq '*')) {

                                        $CurrentFileInfo.SignerID = $Signer.ID
                                        $CurrentFileInfo.SignerName = $Signer.Name
                                        $CurrentFileInfo.SignerCertRoot = $Signer.CertRoot
                                        $CurrentFileInfo.SignerCertPublisher = $Signer.CertPublisher
                                        $CurrentFileInfo.SignerScope = $Signer.SignerScope
                                        $CurrentFileInfo.HasFileAttrib = $Signer.HasFileAttrib
                                        $CurrentFileInfo.SignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                                        $CurrentFileInfo.SpecificFileNameLevelMatchCriteria = 'Version'
                                        $CurrentFileInfo.MatchCriteria = 'SignedVersion'
                                        $CurrentFileInfo.CertSubjectCN = $Certificate.SubjectCN
                                        $CurrentFileInfo.CertIssuerCN = $Certificate.IssuerCN
                                        $CurrentFileInfo.CertNotAfter = $Certificate.NotAfter
                                        $CurrentFileInfo.CertTBSValue = $Certificate.TBSValue

                                        break MainSignerLoop
                                    }

                                    # Loop over all of the candidate file attributes to find a match with the file's extended info
                                    foreach ($FileAttrib in $CandidateFileAttrib.GetEnumerator()) {

                                        # Loop over all of the keys in the extended file info to see which one of them is a match, to determine the SpecificFileNameLevel option
                                        foreach ($KeyItem in $ExtendedFileInfo.Keys) {

                                            if ($ExtendedFileInfo.$KeyItem -eq $FileAttrib.$KeyItem) {

                                                Write-Verbose -Message "The SpecificFileNameLevel is $KeyItem"

                                                # If there was a match then assign the $KeyItem which is the name of the SpecificFileNameLevel option to the $CurrentFileInfo.SpecificFileNameLevelMatchCriteria
                                                # And break out of the loop by validating the signer as suitable for FilePublisher level

                                                $CurrentFileInfo.SignerID = $Signer.ID
                                                $CurrentFileInfo.SignerName = $Signer.Name
                                                $CurrentFileInfo.SignerCertRoot = $Signer.CertRoot
                                                $CurrentFileInfo.SignerCertPublisher = $Signer.CertPublisher
                                                $CurrentFileInfo.SignerScope = $Signer.SignerScope
                                                $CurrentFileInfo.HasFileAttrib = $Signer.HasFileAttrib
                                                $CurrentFileInfo.SignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                                                $CurrentFileInfo.SpecificFileNameLevelMatchCriteria = [System.String]$KeyItem
                                                $CurrentFileInfo.MatchCriteria = 'FilePublisher'
                                                $CurrentFileInfo.CertSubjectCN = $Certificate.SubjectCN
                                                $CurrentFileInfo.CertIssuerCN = $Certificate.IssuerCN
                                                $CurrentFileInfo.CertNotAfter = $Certificate.NotAfter
                                                $CurrentFileInfo.CertTBSValue = $Certificate.TBSValue

                                                break MainSignerLoop

                                            }
                                        }
                                    }
                                }
                                # If the Signer matched and it doesn't have a FileAttrib, then it's a Publisher level signer
                                else {
                                    $CurrentFileInfo.SignerID = $Signer.ID
                                    $CurrentFileInfo.SignerName = $Signer.Name
                                    $CurrentFileInfo.SignerCertRoot = $Signer.CertRoot
                                    $CurrentFileInfo.SignerCertPublisher = $Signer.CertPublisher
                                    $CurrentFileInfo.SignerScope = $Signer.SignerScope
                                    $CurrentFileInfo.HasFileAttrib = $Signer.HasFileAttrib
                                    $CurrentFileInfo.SignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                                    $CurrentFileInfo.MatchCriteria = 'Publisher'
                                    $CurrentFileInfo.CertSubjectCN = $Certificate.SubjectCN
                                    $CurrentFileInfo.CertIssuerCN = $Certificate.IssuerCN
                                    $CurrentFileInfo.CertNotAfter = $Certificate.NotAfter
                                    $CurrentFileInfo.CertTBSValue = $Certificate.TBSValue

                                    break MainSignerLoop
                                }
                            }

                            <#
                            ELIGIBILITY CHECK FOR LEVELS: PcaCertificate, RootCertificate

                            CRITERIA:
                            1) The signer's CertRoot (referring to the TBS value in the xml file which belongs to an intermediate cert of the file) Matches the TBSValue of one of the file's intermediate certificates
                            2) The signer's name (Referring to the one in the XML file) matches the same Intermediate certificate's SubjectCN
                            #>
                            elseif (($Signer.CertRoot -eq $IntermediateCert.TBSValue) -and ($Signer.Name -eq $IntermediateCert.SubjectCN)) {

                                # If the signer has a FileAttrib indicating it was generated with FilePublisher or SignedVersion level, and it wasn't already matched with those levels above, then do not use it for other levels
                                if ($Signer.HasFileAttrib) { Continue }

                                $CurrentFileInfo.SignerID = $Signer.ID
                                $CurrentFileInfo.SignerName = $Signer.Name
                                $CurrentFileInfo.SignerCertRoot = $Signer.CertRoot
                                $CurrentFileInfo.SignerCertPublisher = $Signer.CertPublisher
                                $CurrentFileInfo.SignerScope = $Signer.SignerScope
                                $CurrentFileInfo.HasFileAttrib = $Signer.HasFileAttrib
                                $CurrentFileInfo.SignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                                $CurrentFileInfo.MatchCriteria = 'PcaCertificate/RootCertificate'
                                $CurrentFileInfo.CertSubjectCN = $Certificate.SubjectCN
                                $CurrentFileInfo.CertIssuerCN = $Certificate.IssuerCN
                                $CurrentFileInfo.CertNotAfter = $Certificate.NotAfter
                                $CurrentFileInfo.CertTBSValue = $Certificate.TBSValue

                                break MainSignerLoop
                            }
                        }

                        <#
                        ELIGIBILITY CHECK FOR LEVELS: LeafCertificate

                        CRITERIA:
                        1) The Signer's CertRoot (referring to the TBS value in the xml file, which belongs to the leaf certificate of the file when LeafCertificate level is used) matches the TBSValue of the file's Leaf certificate certificates
                        2) The signer's name (Referring to the one in the XML file) matches the Leaf certificate's SubjectCN
                        #>
                        if (($Signer.CertRoot -eq $Chain.LeafCertificate.TBSValue) -and ($Signer.Name -eq $Chain.LeafCertificate.SubjectCN)) {

                            # If the signer has a FileAttrib indicating it was generated with FilePublisher or SignedVersion level, and it wasn't already matched with those levels above, then do not use it for other levels
                            if ($Signer.HasFileAttrib) { Continue }

                            $CurrentFileInfo.SignerID = $Signer.ID
                            $CurrentFileInfo.SignerName = $Signer.Name
                            $CurrentFileInfo.SignerCertRoot = $Signer.CertRoot
                            $CurrentFileInfo.SignerCertPublisher = $Signer.CertPublisher
                            $CurrentFileInfo.MatchCriteria = 'LeafCertificate'
                            $CurrentFileInfo.SignerScope = $Signer.SignerScope
                            $CurrentFileInfo.HasFileAttrib = $Signer.HasFileAttrib
                            $CurrentFileInfo.SignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                            $CurrentFileInfo.CertSubjectCN = $Certificate.LeafCertificate.SubjectCN
                            $CurrentFileInfo.CertIssuerCN = $Certificate.LeafCertificate.IssuerCN
                            $CurrentFileInfo.CertNotAfter = $Certificate.LeafCertificate.NotAfter
                            $CurrentFileInfo.CertTBSValue = $Certificate.LeafCertificate.TBSValue

                            break MainSignerLoop
                        }
                    }
                    # If the current chain in the loop being investigated has a Root and a Leaf certificates only
                    { $_ -eq 2 } {


                        #  Checking for LeafCertificate level eligibility

                        #  Check if the Signer's CertRoot (referring to the TBS value in the xml file, which belongs to the leaf certificate of the file when LeafCertificate level is used)
                        #  Matches the TBSValue of the file's Leaf certificate certificates

                        #  Check if the signer's name (Referring to the one in the XML file) matches the Leaf certificate's SubjectCN
                        if (($Signer.CertRoot -eq $Chain.LeafCertificate.TBSValue) -and ($Signer.Name -eq $Chain.LeafCertificate.SubjectCN)) {

                            # If the signer has a FileAttrib indicating it was generated with FilePublisher or SignedVersion level, and it wasn't already matched with those levels above, then do not use it for other levels
                            if ($Signer.HasFileAttrib) { Continue }

                            $CurrentFileInfo.SignerID = $Signer.ID
                            $CurrentFileInfo.SignerName = $Signer.Name
                            $CurrentFileInfo.SignerCertRoot = $Signer.CertRoot
                            $CurrentFileInfo.SignerCertPublisher = $Signer.CertPublisher
                            $CurrentFileInfo.MatchCriteria = 'LeafCertificate'
                            $CurrentFileInfo.SignerScope = $Signer.SignerScope
                            $CurrentFileInfo.HasFileAttrib = $Signer.HasFileAttrib
                            $CurrentFileInfo.SignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                            $CurrentFileInfo.CertSubjectCN = $Certificate.LeafCertificate.SubjectCN
                            $CurrentFileInfo.CertIssuerCN = $Certificate.LeafCertificate.IssuerCN
                            $CurrentFileInfo.CertNotAfter = $Certificate.LeafCertificate.NotAfter
                            $CurrentFileInfo.CertTBSValue = $Certificate.LeafCertificate.TBSValue

                            break MainSignerLoop
                        }

                    }
                    # If the current chain in the loop being investigated has only a Root certificate
                    { $_ -eq 1 } {

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

                                    if ($ExtendedFileInfo['FileVersion'] -ge $Attrib.Value.MinimumFileVersion) {
                                        $Attrib.Value
                                    }
                                }

                                # If the signer has a file attribute with a wildcard file name, then it's a SignedVersion level signer
                                # These signers have only 1 FileAttribRef and only point to a single FileAttrib
                                # If a SignedVersion signer applies to multiple files, the version number of the FileAttrib is set to the minimum version of the files
                                if (($CandidateFileAttrib.count -eq 1) -and ($CandidateFileAttrib.FileName -eq '*')) {

                                    $CurrentFileInfo.SignerID = $Signer.ID
                                    $CurrentFileInfo.SignerName = $Signer.Name
                                    $CurrentFileInfo.SignerCertRoot = $Signer.CertRoot
                                    $CurrentFileInfo.SignerCertPublisher = $Signer.CertPublisher
                                    $CurrentFileInfo.SignerScope = $Signer.SignerScope
                                    $CurrentFileInfo.HasFileAttrib = $Signer.HasFileAttrib
                                    $CurrentFileInfo.SignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                                    $CurrentFileInfo.SpecificFileNameLevelMatchCriteria = 'Version'
                                    $CurrentFileInfo.MatchCriteria = 'SignedVersion'
                                    $CurrentFileInfo.CertSubjectCN = $Certificate.SubjectCN
                                    $CurrentFileInfo.CertIssuerCN = $Certificate.IssuerCN
                                    $CurrentFileInfo.CertNotAfter = $Certificate.NotAfter
                                    $CurrentFileInfo.CertTBSValue = $Certificate.TBSValue

                                    break MainSignerLoop
                                }

                                # Loop over all of the candidate file attributes to find a match with the file's extended info
                                foreach ($FileAttrib in $CandidateFileAttrib.GetEnumerator()) {

                                    # Loop over all of the keys in the extended file info to see which one of them is a match, to determine the SpecificFileNameLevel option
                                    foreach ($KeyItem in $ExtendedFileInfo.Keys) {

                                        if ($ExtendedFileInfo.$KeyItem -eq $FileAttrib.$KeyItem) {

                                            Write-Verbose -Message "The SpecificFileNameLevel is $KeyItem"

                                            # If there was a match then assign the $KeyItem which is the name of the SpecificFileNameLevel option to the $CurrentFileInfo.SpecificFileNameLevelMatchCriteria
                                            # And break out of the loop by validating the signer as suitable for FilePublisher level

                                            $CurrentFileInfo.SignerID = $Signer.ID
                                            $CurrentFileInfo.SignerName = $Signer.Name
                                            $CurrentFileInfo.SignerCertRoot = $Signer.CertRoot
                                            $CurrentFileInfo.SignerCertPublisher = $Signer.CertPublisher
                                            $CurrentFileInfo.SignerScope = $Signer.SignerScope
                                            $CurrentFileInfo.HasFileAttrib = $Signer.HasFileAttrib
                                            $CurrentFileInfo.SignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                                            $CurrentFileInfo.SpecificFileNameLevelMatchCriteria = [System.String]$KeyItem
                                            $CurrentFileInfo.MatchCriteria = 'FilePublisher'
                                            $CurrentFileInfo.CertSubjectCN = $Certificate.SubjectCN
                                            $CurrentFileInfo.CertIssuerCN = $Certificate.IssuerCN
                                            $CurrentFileInfo.CertNotAfter = $Certificate.NotAfter
                                            $CurrentFileInfo.CertTBSValue = $Certificate.TBSValue

                                            break MainSignerLoop

                                        }
                                    }
                                }
                            }
                            # If the Signer matched and it doesn't have a FileAttrib, then it's a Publisher level signer
                            else {
                                $CurrentFileInfo.SignerID = $Signer.ID
                                $CurrentFileInfo.SignerName = $Signer.Name
                                $CurrentFileInfo.SignerCertRoot = $Signer.CertRoot
                                $CurrentFileInfo.SignerCertPublisher = $Signer.CertPublisher
                                $CurrentFileInfo.SignerScope = $Signer.SignerScope
                                $CurrentFileInfo.HasFileAttrib = $Signer.HasFileAttrib
                                $CurrentFileInfo.SignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                                $CurrentFileInfo.MatchCriteria = 'Publisher'
                                $CurrentFileInfo.CertSubjectCN = $Certificate.SubjectCN
                                $CurrentFileInfo.CertIssuerCN = $Certificate.IssuerCN
                                $CurrentFileInfo.CertNotAfter = $Certificate.NotAfter
                                $CurrentFileInfo.CertTBSValue = $Certificate.TBSValue

                                break MainSignerLoop
                            }
                        }

                        <#
                        ELIGIBILITY CHECK FOR LEVELS: PcaCertificate, RootCertificate (LeafCertificate will also generate the same type of signer)

                        CRITERIA:
                        1) The signer's CertRoot (referring to the TBS value in the xml file which belongs to the Root Certificate of the file when there is only 1 Element in the chain) Matches the TBSValue of the file's root certificate
                        2) The signer's name (Referring to the one in the XML file) matches the same Root certificate's SubjectCN
                        #>
                        elseif (($Signer.CertRoot -eq $Chain.RootCertificate.TBSValue) -and ($Signer.Name -eq $Chain.RootCertificate.SubjectCN)) {

                            # If the signer has a FileAttrib indicating it was generated with FilePublisher or SignedVersion level, and it wasn't already matched with those levels above, then do not use it for other levels
                            if ($Signer.HasFileAttrib) { Continue }

                            $CurrentFileInfo.SignerID = $Signer.ID
                            $CurrentFileInfo.SignerName = $Signer.Name
                            $CurrentFileInfo.SignerCertRoot = $Signer.CertRoot
                            $CurrentFileInfo.SignerCertPublisher = $Signer.CertPublisher
                            $CurrentFileInfo.SignerScope = $Signer.SignerScope
                            $CurrentFileInfo.HasFileAttrib = $Signer.HasFileAttrib
                            $CurrentFileInfo.SignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                            $CurrentFileInfo.MatchCriteria = 'PcaCertificate/RootCertificate'
                            $CurrentFileInfo.CertSubjectCN = $Certificate.SubjectCN
                            $CurrentFileInfo.CertIssuerCN = $Certificate.IssuerCN
                            $CurrentFileInfo.CertNotAfter = $Certificate.NotAfter
                            $CurrentFileInfo.CertTBSValue = $Certificate.TBSValue

                            break MainSignerLoop
                        }
                    }
                }
            }
        }
    }

    End {
        # if the file's primary signer is authorized at least by one criteria and its criteria is not empty
        if (-NOT ([System.String]::IsNullOrWhiteSpace($CurrentFileInfo.MatchCriteria))) {
            Return $CurrentFileInfo
        }
        else {
            # Do nothing since the file's primary signer is not authorized, let alone the nested signer
            Return
        }
    }
}

Export-ModuleMember -Function 'Compare-SignerAndCertificate'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCM1/rRmGFtdp6r
# c0v4HSDzoZbDwuSXuEUM2DDJu0g1ZKCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQg4N6G01TxOtW3HaamUlt7Kzb8IjFME/VbfRWEJtZVm04wDQYJKoZIhvcNAQEB
# BQAEggIAQGMcIixfytCRzjt/Zy/DpXQ9MbZTBSJ0/c818zdolW4U+8aDwlzqlnq9
# neSD7fdLwsALVTeXsOqGbuTVj9jNEXBQwuaEutsW9Cbhz3BeiXaCwHxYBjG1fcd4
# KyX+Ul9GUCZBgyWhvrAak7uVtvvTqqnOrQGjer2WTXFIi7uo61Pn1hOQfLePXVFK
# pS4O6vOSEPe+GESjIEiHBUWnSvWM1w1UnJFNq++oGrPc3srwRXvBQJaE43ZYbCx7
# vE2qz+r6UocBkiL5IT1IbDZs+ESXmgG5VcfaVEGXvJ2OyqPzBXKpD9j1OHHSSqtc
# WQ19NYvOnqH5ixSySbTRaZiLHptG4Neua9EW4/fhrDResApXfY78h3AxO3ONkLZF
# VdRZEKcWUynmHk4HqS7Y59T8IC0YDbQsFF0ffS5orbM139uXhpNgHEvLVevO8gZg
# x7xHruaypovCQawz5YDr2cOc8phbyER8fHOSrlv8Ugkv10DwpytPhodkrRnTyoHT
# QafdInbOR+0KsVErqvEiVV87YT9vBb4BUzDD3eYTfBYQGqFRuhieN02yhthHfQIO
# By3mimwglMgX6sGb56zN4T3jvzHHSSVik3vbripnCgUb4xY9KFV6wFWxZxcdCQJi
# QFe5CNCG1MlZKGKJCLXA/v3VVD+X9THCbsuRsU3NQI/9/1sZLb0=
# SIG # End signature block
