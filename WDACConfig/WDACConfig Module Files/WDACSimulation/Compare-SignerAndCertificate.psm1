# Defining the Signer class from the WDACConfig Namespace if it doesn't already exist
if (-NOT ('WDACConfig.Signer' -as [System.Type]) ) {
    Add-Type -Path "$ModuleRootPath\C#\Signer.cs"
}
Function Compare-SignerAndCertificate {
    <#
    .SYNOPSIS
        A function that takes a WDAC policy XML file path and a Signed file path as inputs and compares the output of the Get-SignerInfo and Get-CertificateDetails functions
        Also checks if the file has nested (2nd) signer and will process it accordingly

        Only returns the result if the file is authorized by the policy using one of the signers
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        ordered
    .PARAMETER XmlFilePath
        Path to a WDAC XML file
    .PARAMETER SignedFilePath
        Path to a signed file
    #>
    [CmdletBinding()]
    [OutputType([ordered])]
    param(
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath,
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$SignedFilePath
    )
    Begin {
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Importing the required sub-modules
        Import-Module -FullyQualifiedName "$ModuleRootPath\WDACSimulation\Get-SignerInfo.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\WDACSimulation\Get-NestedSignerSignature.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\WDACSimulation\Get-CertificateDetails.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\WDACSimulation\Get-ExtendedFileInfo.psm1" -Force

        # Get the signer information from the XML file path using the Get-SignerInfo function
        [WDACConfig.Signer[]]$SignerInfo = Get-SignerInfo -XmlFilePath $XmlFilePath -SignedFilePath $SignedFilePath

        # Load the XML file as an XML document object
        [System.Xml.XmlDocument]$Xml = Get-Content -LiteralPath $XmlFilePath

        # Select the FileAttrib nodes of the XML file
        [System.Object[]]$PolicyFileAttributes = $Xml.SiPolicy.FileRules.FileAttrib

        # An ordered hashtable that holds the details of the current file
        # Values marked as "Gathered from the Get-SignerInfo function" are identical for both primary and nested signers since that function can't know which signer is going to be matched with the primary or nested certificate of a file
        $CurrentFileInfo = [ordered]@{
            #Region Primary Signer
            SignerID                                 = ''       # Gathered from the Get-SignerInfo function
            SignerName                               = ''       # Gathered from the Get-SignerInfo function
            SignerCertRoot                           = ''       # Gathered from the Get-SignerInfo function
            SignerCertPublisher                      = ''       # Gathered from the Get-SignerInfo function
            HasEKU                                   = $false   # Gathered from the Get-SignerInfo function
            EKUOID                                   = @()      # Gathered from the Get-SignerInfo function
            EKUsMatch                                = $false   # Gathered from the Get-SignerInfo function
            SignerScope                              = ''       # Gathered from the Get-SignerInfo function
            HasFileAttrib                            = $false   # Gathered from the Get-SignerInfo function
            SignerFileAttributeIDs                   = @()      # Gathered from the Get-SignerInfo function
            MatchCriteria                            = ''
            SpecificFileNameLevelMatchCriteria       = ''       # Only those eligible for FilePublisher or SignedVersion levels assign this value, otherwise it stays empty
            CertSubjectCN                            = ''
            CertIssuerCN                             = ''
            CertNotAfter                             = ''
            CertTBSValue                             = ''
            CertRootMatch                            = $false
            CertNameMatch                            = $false
            CertPublisherMatch                       = $false
            #Endregion Primary Signer

            #Region Nested Signer
            HasNestedCert                            = $false
            NestedSignerID                           = ''       # Gathered from the Get-SignerInfo function
            NestedSignerName                         = ''       # Gathered from the Get-SignerInfo function
            NestedSignerCertRoot                     = ''       # Gathered from the Get-SignerInfo function
            NestedSignerCertPublisher                = ''       # Gathered from the Get-SignerInfo function
            NestedHasEKU                             = $false   # Gathered from the Get-SignerInfo function
            NestedEKUOID                             = @()      # Gathered from the Get-SignerInfo function
            NestedEKUsMatch                          = $false   # Gathered from the Get-SignerInfo function
            NestedSignerScope                        = ''       # Gathered from the Get-SignerInfo function
            NestedHasFileAttrib                      = $false   # Gathered from the Get-SignerInfo function
            NestedSignerFileAttributeIDs             = @()      # Gathered from the Get-SignerInfo function
            NestedMatchCriteria                      = ''
            NestedSpecificFileNameLevelMatchCriteria = ''       # Only those eligible for FilePublisher or SignedVersion levels assign this value, otherwise it stays empty
            NestedCertSubjectCN                      = ''
            NestedCertIssuerCN                       = ''
            NestedCertNotAfter                       = ''
            NestedCertTBSValue                       = ''
            NestedCertRootMatch                      = $false
            NestedCertNameMatch                      = $false
            NestedCertPublisherMatch                 = $false
            #Endregion Nested Signer

            FilePath                                 = $SignedFilePath
        }

        # Get details of the intermediate and leaf certificates of the primary certificate of the signed file
        [System.Object[]]$AllPrimaryCertificateDetails = Get-CertificateDetails -FilePath $SignedFilePath

        # Store the intermediate certificate(s) details of the Primary certificate of the signed file
        [System.Object[]]$PrimaryCertificateIntermediateDetails = $AllPrimaryCertificateDetails.IntermediateCertificates

        # Store the leaf certificate details of the Primary Certificate of the signed file
        [System.Object]$PrimaryCertificateLeafDetails = $AllPrimaryCertificateDetails.LeafCertificate

        # Get the Nested (Secondary) certificate of the signed file, if any
        [System.Management.Automation.Signature]$ExtraCertificateDetails = Get-NestedSignerSignature -FilePath $SignedFilePath

        # Extract the Nested (Secondary) certificate from the nested property, if any
        $NestedCertificate = ($ExtraCertificateDetails).NestedSignature.SignerCertificate

        # If the signed file has a nested certificate
        if ($null -ne [System.Security.Cryptography.X509Certificates.X509Certificate2]$NestedCertificate) {
            # First get the CN of the leaf certificate of the nested Certificate
            $NestedCertificate.Subject -match 'CN=(?<InitialRegexTest1>.*?),.*' | Out-Null
            $LeafCNOfTheNestedCertificate = $matches['InitialRegexTest1'] -like '*"*' ? ($NestedCertificate.Subject -split 'CN="(.+?)"')[1] : $matches['InitialRegexTest1']

            Write-Verbose -Message 'Found a nested Signer in the file'

            # Send the nested certificate along with its Leaf certificate's CN to the Get-CertificateDetails function in order to get the intermediate and leaf certificates details of the Nested certificate
            [System.Object[]]$AllNestedCertificateDetails = Get-CertificateDetails -X509Certificate2 $NestedCertificate -LeafCNOfTheNestedCertificate $LeafCNOfTheNestedCertificate

            # Store the intermediate certificate(s) details of the Nested certificate from the signed file
            [System.Object[]]$NestedCertificateIntermediateDetails = $AllNestedCertificateDetails.IntermediateCertificates

            # Get the leaf certificate details of the Nested Certificate from the signed file
            [System.Object]$NestedCertificateLeafDetails = $AllNestedCertificateDetails.LeafCertificate

            # If the leaf certificate of the nested signer is the same as the leaf certificate of the primary signer
            # Set the flag for the file having nested certificate to $false because the WDAC policy only creates signer for one of them and checking for 2nd signer naturally causes inaccurate results
            if ($NestedCertificateLeafDetails.TBSValue -eq $PrimaryCertificateLeafDetails.TBSValue) {

                Write-Verbose -Message 'The Leaf Certificates of the primary and nested signers are the same'

                $CurrentFileInfo.HasNestedCert = $false
            }
            else {
                # The file has a nested certificate
                $CurrentFileInfo.HasNestedCert = $true
            }
        }

        # Assign indicators/flags to ascertain if a primary or nested signer was located, thereby avoiding redundant iterations of their loops
        # Initialize them to $False until a nested loop identifies a match
        # Owing to the complexity of the loops in those regions, a label is employed to exit multiple loops simultaneously
        [System.Boolean]$FoundMatchPrimary = $false
        [System.Boolean]$FoundMatchNested = $false

        # Initialize the flag to indicate if the file's extended info is available in the current session
        [System.Boolean]$FileExtendedInfoAvailable = $false

        # Due to the fuzzy searching nature of signers and matching them with the file's certificates, it's possible that a signer can match at multiple levels
        # The following flags are used to indicate that if a match was not already found for the primary signer in a 3-way match (FilePublisher, Publisher or SignedVersion levels)
        # Then the loop must keep going and only once it's exhausted all the signers for those 3 levels then it can move to other levels
        # This improves the accuracy in policies where SignedVersion level is used. A file could be prematurely matched with PCA/Root certificate levels while it could've been matched with higher levels had the loop continued

        # Initialize the flag to indicate if a match was found for the primary signer in a 3-way match (FilePublisher, Publisher or SignedVersion levels)
        [System.Boolean]$FoundMatchPrimary3Way = $false
        # Initialize the flag to indicate if a match was found for the nested signer in a 3-way match (FilePublisher, Publisher or SignedVersion levels)
        [System.Boolean]$FoundMatchNested3Way = $false
    }

    Process {

        # Loop through each signer in the signer information array, These are the signers in the XML policy file
        foreach ($Signer in $SignerInfo) {

            if ($FoundMatchPrimary3Way -and $FoundMatchNested3Way) {
                # Exit the process block if a match was already found for both the primary and nested signers, and stop trying other signers
                Return
            }

            # If a match wasn't already found for the primary signer
            if (-NOT $FoundMatchPrimary3Way) {

                # Loop through each of the file's primary signer certificate's intermediate certificates
                :PrimaryCertLoopLabel foreach ($Certificate in $PrimaryCertificateIntermediateDetails) {

                    # Checking for FilePublisher, Publisher or SignedVersion levels eligibility

                    # 1) Check if the Signer's CertRoot (referring to the TBS value in the xml file which belongs to an intermediate cert of the file)
                    # Matches the TBSValue of one of the file's intermediate certificates

                    # 2) Check if the signer's name (Referring to the one in the XML file) matches the same Intermediate certificate's SubjectCN

                    # 3) Check if the signer's CertPublisher (aka Leaf Certificate's CN used in the xml policy) matches the leaf certificate's SubjectCN (of the file)
                    if (($Signer.CertRoot -eq $Certificate.TBSValue) -and ($Signer.Name -eq $Certificate.SubjectCN) -and ($Signer.CertPublisher -eq $PrimaryCertificateLeafDetails.SubjectCN)) {

                        # At this point we know the Signer is either FilePublisher, Publisher or SignedVersion level, but we need to narrow it down

                        # Check if the signer has FileAttrib indicating that it was generated either with FilePublisher or SignedVersion level
                        if ($Signer.HasFileAttrib) {

                            # Get the extended file attributes as ordered hashtable
                            $ExtendedFileInfo = Get-ExtendedFileInfo -Path $SignedFilePath

                            # Get the current file's version
                            [System.Version]$FileVersion = (Get-Item -LiteralPath $SignedFilePath).VersionInfo.FileVersionRaw

                            # If the file version couldn't be retrieved from the file using Get-Item cmdlet
                            if (-NOT $FileVersion) {

                                # Create a Shell.Application object
                                [System.__ComObject]$Shell = New-Object -ComObject Shell.Application

                                # Get the folder and file names from the path
                                [System.String]$Folder = Split-Path $Path
                                [System.String]$File = Split-Path $Path -Leaf

                                # Get the ShellFolder and ShellFile objects from the Shell.Application object
                                [System.__ComObject]$ShellFolder = $Shell.Namespace($Folder)
                                [System.__ComObject]$ShellFile = $ShellFolder.ParseName($File)

                                # Get the file version from the ShellFile object using the 166th property ID
                                [System.Version]$FileVersion = $ShellFolder.GetDetailsOf($ShellFile, 166)

                                # Release the Shell.Application object
                                [Runtime.InteropServices.Marshal]::ReleaseComObject($Shell) | Out-Null
                            }

                            # Set the flag to indicate that the file's extended info have has collected and are available in the current session
                            $FileExtendedInfoAvailable = $True

                            # Get all of the file attributes in the policy XML file whose IDs are in the Signer's FileAttribRef IDs array and the file's version is equal or greater than the minimum version specified in the FileAttrib
                            [System.Xml.XmlElement[]]$PrimaryCandidatePolicyFileAttributes = ($PolicyFileAttributes | Where-Object -FilterScript { ($Signer.SignerFileAttributeIDs -contains $_.ID) -and ($FileVersion -ge [system.version]$_.MinimumFileVersion) })

                            # If the signer has a file attribute with a wildcard file name, then it's a SignedVersion level signer
                            # These signers have only 1 FileAttribRef and only point to a single FileAttrib
                            # If a SignedVersion signer applies to multiple files, the version number of the FileAttrib is set to the minimum version of the files
                            if (($PrimaryCandidatePolicyFileAttributes.count -eq 1) -and ($PrimaryCandidatePolicyFileAttributes.FileName -eq '*')) {

                                $CurrentFileInfo.SignerID = $Signer.ID
                                $CurrentFileInfo.SignerName = $Signer.Name
                                $CurrentFileInfo.SignerCertRoot = $Signer.CertRoot
                                $CurrentFileInfo.SignerCertPublisher = $Signer.CertPublisher
                                $CurrentFileInfo.HasEKU = $Signer.HasEKU
                                $CurrentFileInfo.EKUOID = $Signer.EKUOID
                                $CurrentFileInfo.EKUsMatch = $Signer.EKUsMatch
                                $CurrentFileInfo.SignerScope = $Signer.SignerScope
                                $CurrentFileInfo.HasFileAttrib = $Signer.HasFileAttrib
                                $CurrentFileInfo.SignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                                $CurrentFileInfo.SpecificFileNameLevelMatchCriteria = 'Version'
                                $CurrentFileInfo.MatchCriteria = 'SignedVersion'
                                $CurrentFileInfo.CertSubjectCN = $Certificate.SubjectCN
                                $CurrentFileInfo.CertIssuerCN = $Certificate.IssuerCN
                                $CurrentFileInfo.CertNotAfter = $Certificate.NotAfter
                                $CurrentFileInfo.CertTBSValue = $Certificate.TBSValue
                                $CurrentFileInfo.CertRootMatch = $true
                                $CurrentFileInfo.CertNameMatch = $true
                                $CurrentFileInfo.CertPublisherMatch = $true

                                # Set the flag to indicate that a match was found
                                $FoundMatchPrimary = $true
                                # Set a flag to indicate that a match was found for the nested signer in a 3-way match
                                $FoundMatchPrimary3Way = $true

                                break PrimaryCertLoopLabel
                            }

                            # Loop over all of the candidate file attributes to find a match with the file's extended info
                            foreach ($FileAttrib in $PrimaryCandidatePolicyFileAttributes) {

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
                                        $CurrentFileInfo.HasEKU = $Signer.HasEKU
                                        $CurrentFileInfo.EKUOID = $Signer.EKUOID
                                        $CurrentFileInfo.EKUsMatch = $Signer.EKUsMatch
                                        $CurrentFileInfo.SignerScope = $Signer.SignerScope
                                        $CurrentFileInfo.HasFileAttrib = $Signer.HasFileAttrib
                                        $CurrentFileInfo.SignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                                        $CurrentFileInfo.SpecificFileNameLevelMatchCriteria = [System.String]$KeyItem
                                        $CurrentFileInfo.MatchCriteria = 'FilePublisher'
                                        $CurrentFileInfo.CertSubjectCN = $Certificate.SubjectCN
                                        $CurrentFileInfo.CertIssuerCN = $Certificate.IssuerCN
                                        $CurrentFileInfo.CertNotAfter = $Certificate.NotAfter
                                        $CurrentFileInfo.CertTBSValue = $Certificate.TBSValue
                                        $CurrentFileInfo.CertRootMatch = $true
                                        $CurrentFileInfo.CertNameMatch = $true
                                        $CurrentFileInfo.CertPublisherMatch = $true

                                        # Set the flag to indicate that a match was found
                                        $FoundMatchPrimary = $true
                                        # Set a flag to indicate that a match was found for the nested signer in a 3-way match
                                        $FoundMatchPrimary3Way = $true

                                        break PrimaryCertLoopLabel
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
                            $CurrentFileInfo.HasEKU = $Signer.HasEKU
                            $CurrentFileInfo.EKUOID = $Signer.EKUOID
                            $CurrentFileInfo.EKUsMatch = $Signer.EKUsMatch
                            $CurrentFileInfo.SignerScope = $Signer.SignerScope
                            $CurrentFileInfo.HasFileAttrib = $Signer.HasFileAttrib
                            $CurrentFileInfo.SignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                            $CurrentFileInfo.MatchCriteria = 'Publisher'
                            $CurrentFileInfo.CertSubjectCN = $Certificate.SubjectCN
                            $CurrentFileInfo.CertIssuerCN = $Certificate.IssuerCN
                            $CurrentFileInfo.CertNotAfter = $Certificate.NotAfter
                            $CurrentFileInfo.CertTBSValue = $Certificate.TBSValue
                            $CurrentFileInfo.CertRootMatch = $true
                            $CurrentFileInfo.CertNameMatch = $true
                            $CurrentFileInfo.CertPublisherMatch = $true

                            # Set the flag to indicate that a match was found
                            $FoundMatchPrimary = $true
                            # Set a flag to indicate that a match was found for the nested signer in a 3-way match
                            $FoundMatchPrimary3Way = $true

                            break PrimaryCertLoopLabel
                        }
                    }

                    # Checking for PcaCertificate, RootCertificate levels eligibility

                    # Check if the Signer's CertRoot (referring to the TBS value in the xml file which belongs to an intermediate cert of the file)
                    # Matches the TBSValue of one of the file's intermediate certificates

                    # Check if the signer's name (Referring to the one in the XML file) matches the same Intermediate certificate's SubjectCN
                    elseif (($Signer.CertRoot -eq $Certificate.TBSValue) -and ($Signer.Name -eq $Certificate.SubjectCN)) {

                        # If the signer has a FileAttrib indicating it was generated with FilePublisher or SignedVersion level, and it wasn't already matched with those levels above, then do not use it for other levels
                        if ($Signer.HasFileAttrib) { Continue }

                        $CurrentFileInfo.SignerID = $Signer.ID
                        $CurrentFileInfo.SignerName = $Signer.Name
                        $CurrentFileInfo.SignerCertRoot = $Signer.CertRoot
                        $CurrentFileInfo.SignerCertPublisher = $Signer.CertPublisher
                        $CurrentFileInfo.HasEKU = $Signer.HasEKU
                        $CurrentFileInfo.EKUOID = $Signer.EKUOID
                        $CurrentFileInfo.EKUsMatch = $Signer.EKUsMatch
                        $CurrentFileInfo.SignerScope = $Signer.SignerScope
                        $CurrentFileInfo.HasFileAttrib = $Signer.HasFileAttrib
                        $CurrentFileInfo.SignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                        $CurrentFileInfo.MatchCriteria = 'PcaCertificate/RootCertificate'
                        $CurrentFileInfo.CertSubjectCN = $Certificate.SubjectCN
                        $CurrentFileInfo.CertIssuerCN = $Certificate.IssuerCN
                        $CurrentFileInfo.CertNotAfter = $Certificate.NotAfter
                        $CurrentFileInfo.CertTBSValue = $Certificate.TBSValue
                        $CurrentFileInfo.CertRootMatch = $true
                        $CurrentFileInfo.CertNameMatch = $true
                        $CurrentFileInfo.CertPublisherMatch = $false

                        # Set the flag to indicate that a match was found
                        $FoundMatchPrimary = $true

                        break PrimaryCertLoopLabel
                    }

                    #  Checking for LeafCertificate level eligibility

                    #  Check if the Signer's CertRoot (referring to the TBS value in the xml file, which belongs to the leaf certificate of the file when LeafCertificate level is used)
                    #  Matches the TBSValue of the file's Leaf certificate certificates

                    #  Check if the signer's name (Referring to the one in the XML file) matches the Leaf certificate's SubjectCN
                    elseif (($Signer.CertRoot -eq $PrimaryCertificateLeafDetails.TBSValue) -and ($Signer.Name -eq $PrimaryCertificateLeafDetails.SubjectCN)) {

                        # If the signer has a FileAttrib indicating it was generated with FilePublisher or SignedVersion level, and it wasn't already matched with those levels above, then do not use it for other levels
                        if ($Signer.HasFileAttrib) { Continue }

                        $CurrentFileInfo.SignerID = $Signer.ID
                        $CurrentFileInfo.SignerName = $Signer.Name
                        $CurrentFileInfo.SignerCertRoot = $Signer.CertRoot
                        $CurrentFileInfo.SignerCertPublisher = $Signer.CertPublisher
                        $CurrentFileInfo.HasEKU = $Signer.HasEKU
                        $CurrentFileInfo.EKUOID = $Signer.EKUOID
                        $CurrentFileInfo.EKUsMatch = $Signer.EKUsMatch
                        $CurrentFileInfo.MatchCriteria = 'LeafCertificate'
                        $CurrentFileInfo.SignerScope = $Signer.SignerScope
                        $CurrentFileInfo.HasFileAttrib = $Signer.HasFileAttrib
                        $CurrentFileInfo.SignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                        $CurrentFileInfo.CertSubjectCN = $PrimaryCertificateLeafDetails.SubjectCN
                        $CurrentFileInfo.CertIssuerCN = $PrimaryCertificateLeafDetails.IssuerCN
                        $CurrentFileInfo.CertNotAfter = $PrimaryCertificateLeafDetails.NotAfter
                        $CurrentFileInfo.CertTBSValue = $PrimaryCertificateLeafDetails.TBSValue
                        $CurrentFileInfo.CertRootMatch = $true
                        $CurrentFileInfo.CertNameMatch = $true
                        $CurrentFileInfo.CertPublisherMatch = $false

                        # Set the flag to indicate that a match was found
                        $FoundMatchPrimary = $true

                        break PrimaryCertLoopLabel
                    }
                }
            }

            # if the file has a nested certificate
            if ($CurrentFileInfo.HasNestedCert) {

                # If a match wasn't already found for the nested signer
                if (-NOT $FoundMatchNested3Way) {

                    :NestedCertLoopLabel foreach ($NestedCertificate in $NestedCertificateIntermediateDetails) {

                        # FilePublisher, Publisher and SignedVersion levels eligibility check
                        if (($Signer.CertRoot -eq $NestedCertificate.TBSValue) -and ($Signer.Name -eq $NestedCertificate.SubjectCN) -and ($Signer.CertPublisher -eq $NestedCertificateLeafDetails.SubjectCN)) {

                            # At this point we know the Nested Signer is either FilePublisher, Publisher or SignedVersion level, but we need to narrow it down

                            # Check if the signer has FileAttrib indicating that it was generated either with FilePublisher or SignedVersion level
                            if ($Signer.HasFileAttrib) {

                                # If the file's extended info is not available in the current session then get them
                                if (-NOT $FileExtendedInfoAvailable) {

                                    # Get the extended file attributes as ordered hashtable
                                    $ExtendedFileInfo = Get-ExtendedFileInfo -Path $SignedFilePath

                                    # Get the current file's version
                                    [System.Version]$FileVersion = (Get-Item -LiteralPath $SignedFilePath).VersionInfo.FileVersionRaw

                                    # If the file version couldn't be retrieved from the file using Get-Item cmdlet
                                    if (-NOT $FileVersion) {

                                        # Create a Shell.Application object
                                        [System.__ComObject]$Shell = New-Object -ComObject Shell.Application

                                        # Get the folder and file names from the path
                                        [System.String]$Folder = Split-Path $Path
                                        [System.String]$File = Split-Path $Path -Leaf

                                        # Get the ShellFolder and ShellFile objects from the Shell.Application object
                                        [System.__ComObject]$ShellFolder = $Shell.Namespace($Folder)
                                        [System.__ComObject]$ShellFile = $ShellFolder.ParseName($File)

                                        # Get the file version from the ShellFile object using the 166th property ID
                                        [System.Version]$FileVersion = $ShellFolder.GetDetailsOf($ShellFile, 166)

                                        # Release the Shell.Application object
                                        [Runtime.InteropServices.Marshal]::ReleaseComObject($Shell) | Out-Null
                                    }
                                }

                                # Get all of the file attributes in the policy XML file whose IDs are in the Nested Signer's FileAttribRef IDs array and the file's version is equal or greater than the minimum version specified in the FileAttrib
                                [System.Xml.XmlElement[]]$NestedCandidatePolicyFileAttributes = ($PolicyFileAttributes | Where-Object -FilterScript { ($Signer.SignerFileAttributeIDs -contains $_.ID) })

                                # If the signer has a file attribute with a wildcard file name, then it's a SignedVersion level signer
                                # These signers have only 1 FileAttribRef and only point to a single FileAttrib
                                # If a SignedVersion signer applies to multiple files, the version number of the FileAttrib is set to the minimum version of the files
                                if (($NestedCandidatePolicyFileAttributes.count -eq 1) -and ($NestedCandidatePolicyFileAttributes.FileName -eq '*')) {

                                    $CurrentFileInfo.NestedSignerID = $Signer.ID
                                    $CurrentFileInfo.NestedSignerName = $Signer.Name
                                    $CurrentFileInfo.NestedSignerCertRoot = $Signer.CertRoot
                                    $CurrentFileInfo.NestedSignerCertPublisher = $Signer.CertPublisher
                                    $CurrentFileInfo.NestedHasEKU = $Signer.HasEKU
                                    $CurrentFileInfo.NestedEKUOID = $Signer.EKUOID
                                    $CurrentFileInfo.NestedEKUsMatch = $Signer.EKUsMatch
                                    $CurrentFileInfo.NestedSignerScope = $Signer.SignerScope
                                    $CurrentFileInfo.NestedHasFileAttrib = $Signer.HasFileAttrib
                                    $CurrentFileInfo.NestedSignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                                    $CurrentFileInfo.NestedSpecificFileNameLevelMatchCriteria = 'Version'
                                    $CurrentFileInfo.NestedMatchCriteria = 'SignedVersion'
                                    $CurrentFileInfo.NestedCertSubjectCN = $NestedCertificate.SubjectCN
                                    $CurrentFileInfo.NestedCertIssuerCN = $NestedCertificate.IssuerCN
                                    $CurrentFileInfo.NestedCertNotAfter = $NestedCertificate.NotAfter
                                    $CurrentFileInfo.NestedCertTBSValue = $NestedCertificate.TBSValue
                                    $CurrentFileInfo.NestedCertRootMatch = $true
                                    $CurrentFileInfo.NestedCertNameMatch = $true
                                    $CurrentFileInfo.NestedCertPublisherMatch = $true

                                    # Set the flag to indicate that a match was found
                                    $FoundMatchNested = $true
                                    # Set a flag to indicate that a match was found for the nested signer in a 3-way match
                                    $FoundMatchNested3Way = $true

                                    break NestedCertLoopLabel
                                }

                                # Loop over all of the candidate file attributes to find a match with the file's extended info
                                foreach ($FileAttrib in $NestedCandidatePolicyFileAttributes) {

                                    # Loop over all of the keys in the extended file info to see which one of them is a match, to determine the SpecificFileNameLevel option
                                    foreach ($KeyItem in $ExtendedFileInfo.Keys) {

                                        if ($ExtendedFileInfo.$KeyItem -eq $FileAttrib.$KeyItem) {
                                            Write-Verbose -Message "The SpecificFileNameLevel is $KeyItem"

                                            # If there was a match then assign the $KeyItem which is the name of the SpecificFileNameLevel option to the $CurrentFileInfo.NestedSpecificFileNameLevelMatchCriteria
                                            # And break out of the loop by validating the signer as suitable for FilePublisher level

                                            $CurrentFileInfo.NestedSignerID = $Signer.ID
                                            $CurrentFileInfo.NestedSignerName = $Signer.Name
                                            $CurrentFileInfo.NestedSignerCertRoot = $Signer.CertRoot
                                            $CurrentFileInfo.NestedSignerCertPublisher = $Signer.CertPublisher
                                            $CurrentFileInfo.NestedHasEKU = $Signer.HasEKU
                                            $CurrentFileInfo.NestedEKUOID = $Signer.EKUOID
                                            $CurrentFileInfo.NestedEKUsMatch = $Signer.EKUsMatch
                                            $CurrentFileInfo.NestedSignerScope = $Signer.SignerScope
                                            $CurrentFileInfo.NestedHasFileAttrib = $Signer.HasFileAttrib
                                            $CurrentFileInfo.NestedSignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                                            $CurrentFileInfo.NestedSpecificFileNameLevelMatchCriteria = [System.String]$KeyItem
                                            $CurrentFileInfo.NestedMatchCriteria = 'FilePublisher'
                                            $CurrentFileInfo.NestedCertSubjectCN = $NestedCertificate.SubjectCN
                                            $CurrentFileInfo.NestedCertIssuerCN = $NestedCertificate.IssuerCN
                                            $CurrentFileInfo.NestedCertNotAfter = $NestedCertificate.NotAfter
                                            $CurrentFileInfo.NestedCertTBSValue = $NestedCertificate.TBSValue
                                            $CurrentFileInfo.NestedCertRootMatch = $true
                                            $CurrentFileInfo.NestedCertNameMatch = $true
                                            $CurrentFileInfo.NestedCertPublisherMatch = $true

                                            # Set the flag to indicate that a match was found
                                            $FoundMatchNested = $true
                                            # Set a flag to indicate that a match was found for the nested signer in a 3-way match
                                            $FoundMatchNested3Way = $true

                                            break NestedCertLoopLabel
                                        }
                                    }
                                }
                            }
                            # If the Signer matched and it doesn't have a FileAttrib, then it's a Publisher level signer
                            else {
                                $CurrentFileInfo.NestedSignerID = $Signer.ID
                                $CurrentFileInfo.NestedSignerName = $Signer.Name
                                $CurrentFileInfo.NestedSignerCertRoot = $Signer.CertRoot
                                $CurrentFileInfo.NestedSignerCertPublisher = $Signer.CertPublisher
                                $CurrentFileInfo.NestedHasEKU = $Signer.HasEKU
                                $CurrentFileInfo.NestedEKUOID = $Signer.EKUOID
                                $CurrentFileInfo.NestedEKUsMatch = $Signer.EKUsMatch
                                $CurrentFileInfo.NestedSignerScope = $Signer.SignerScope
                                $CurrentFileInfo.NestedHasFileAttrib = $Signer.HasFileAttrib
                                $CurrentFileInfo.NestedSignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                                $CurrentFileInfo.NestedMatchCriteria = 'Publisher'
                                $CurrentFileInfo.NestedCertSubjectCN = $NestedCertificate.SubjectCN
                                $CurrentFileInfo.NestedCertIssuerCN = $NestedCertificate.IssuerCN
                                $CurrentFileInfo.NestedCertNotAfter = $NestedCertificate.NotAfter
                                $CurrentFileInfo.NestedCertTBSValue = $NestedCertificate.TBSValue
                                $CurrentFileInfo.NestedCertRootMatch = $true
                                $CurrentFileInfo.NestedCertNameMatch = $true
                                $CurrentFileInfo.NestedCertPublisherMatch = $true

                                # Set the flag to indicate that a match was found
                                $FoundMatchNested = $true
                                # Set a flag to indicate that a match was found for the nested signer in a 3-way match
                                $FoundMatchNested3Way = $true

                                break NestedCertLoopLabel
                            }
                        }

                        # PcaCertificate, RootCertificate levels eligibility check
                        elseif (($Signer.CertRoot -eq $NestedCertificate.TBSValue) -and ($Signer.Name -eq $NestedCertificate.SubjectCN)) {

                            # If the signer has a FileAttrib indicating it was generated with FilePublisher or SignedVersion level, and it wasn't already matched with those levels above, then do not use it for other levels
                            if ($Signer.HasFileAttrib) { Continue }

                            $CurrentFileInfo.NestedSignerID = $Signer.ID
                            $CurrentFileInfo.NestedSignerName = $Signer.Name
                            $CurrentFileInfo.NestedSignerCertRoot = $Signer.CertRoot
                            $CurrentFileInfo.NestedSignerCertPublisher = $Signer.CertPublisher
                            $CurrentFileInfo.NestedHasEKU = $Signer.HasEKU
                            $CurrentFileInfo.NestedEKUOID = $Signer.EKUOID
                            $CurrentFileInfo.NestedEKUsMatch = $Signer.EKUsMatch
                            $CurrentFileInfo.NestedSignerScope = $Signer.SignerScope
                            $CurrentFileInfo.NestedHasFileAttrib = $Signer.HasFileAttrib
                            $CurrentFileInfo.NestedSignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                            $CurrentFileInfo.NestedMatchCriteria = 'PcaCertificate/RootCertificate'
                            $CurrentFileInfo.NestedCertSubjectCN = $NestedCertificate.SubjectCN
                            $CurrentFileInfo.NestedCertIssuerCN = $NestedCertificate.IssuerCN
                            $CurrentFileInfo.NestedCertNotAfter = $NestedCertificate.NotAfter
                            $CurrentFileInfo.NestedCertTBSValue = $NestedCertificate.TBSValue
                            $CurrentFileInfo.NestedCertRootMatch = $true
                            $CurrentFileInfo.NestedCertNameMatch = $true
                            $CurrentFileInfo.NestedCertPublisherMatch = $false

                            # Set the flag to indicate that a match was found
                            $FoundMatchNested = $true

                            break NestedCertLoopLabel
                        }

                        # LeafCertificate level eligibility check
                        elseif (($Signer.CertRoot -eq $NestedCertificateLeafDetails.TBSValue) -and ($Signer.Name -eq $NestedCertificateLeafDetails.SubjectCN)) {

                            # If the signer has a FileAttrib indicating it was generated with FilePublisher or SignedVersion level, and it wasn't already matched with those levels above, then do not use it for other levels
                            if ($Signer.HasFileAttrib) { Continue }

                            $CurrentFileInfo.NestedSignerID = $Signer.ID
                            $CurrentFileInfo.NestedSignerName = $Signer.Name
                            $CurrentFileInfo.NestedSignerCertRoot = $Signer.CertRoot
                            $CurrentFileInfo.NestedSignerCertPublisher = $Signer.CertPublisher
                            $CurrentFileInfo.NestedHasEKU = $Signer.HasEKU
                            $CurrentFileInfo.NestedEKUOID = $Signer.EKUOID
                            $CurrentFileInfo.NestedEKUsMatch = $Signer.EKUsMatch
                            $CurrentFileInfo.NestedSignerScope = $Signer.SignerScope
                            $CurrentFileInfo.NestedHasFileAttrib = $Signer.HasFileAttrib
                            $CurrentFileInfo.NestedSignerFileAttributeIDs = $Signer.SignerFileAttributeIDs
                            $CurrentFileInfo.NestedMatchCriteria = 'LeafCertificate'
                            $CurrentFileInfo.NestedCertSubjectCN = $NestedCertificateLeafDetails.SubjectCN
                            $CurrentFileInfo.NestedCertIssuerCN = $NestedCertificateLeafDetails.IssuerCN
                            $CurrentFileInfo.NestedCertNotAfter = $NestedCertificateLeafDetails.NotAfter
                            $CurrentFileInfo.NestedCertTBSValue = $NestedCertificateLeafDetails.TBSValue
                            $CurrentFileInfo.NestedCertRootMatch = $true
                            $CurrentFileInfo.NestedCertNameMatch = $true
                            $CurrentFileInfo.NestedCertPublisherMatch = $false

                            # Set the flag to indicate that a match was found
                            $FoundMatchNested = $true

                            break NestedCertLoopLabel
                        }
                    }
                }
            }
        }
    }

    End {
        # if the file's primary signer is authorized at least by one criteria and its criteria is not empty
        if (-NOT ([System.String]::IsNullOrWhiteSpace($CurrentFileInfo.MatchCriteria))) {

            Write-Verbose -Message "The primary signer is authorized by the criteria: $($CurrentFileInfo.MatchCriteria) by the following SignerID: $($CurrentFileInfo.SignerID)"

            # If the file has a nested signer
            if ($CurrentFileInfo.HasNestedCert -eq $true) {

                # If the file's nested signer is authorized at least by one criteria and its criteria is not empty
                if (-NOT ([System.String]::IsNullOrWhiteSpace($CurrentFileInfo.NestedMatchCriteria))) {

                    Write-Verbose -Message "The nested signer is authorized by the criteria: $($CurrentFileInfo.NestedMatchCriteria) by the following SignerID: $($CurrentFileInfo.NestedSignerID)"

                    # Return the comparison result of the given file if there is no nested signer
                    Return $CurrentFileInfo

                }
                else {
                    Write-Verbose -Message 'The primary signer is authorized but the nested signer is not authorized'
                    Return
                }
            }
            else {
                # Return the comparison result of the given file with primary signer only, if there is no nested signer
                Return $CurrentFileInfo
            }
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
