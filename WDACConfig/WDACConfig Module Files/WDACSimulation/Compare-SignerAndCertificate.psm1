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

    begin {
        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null

        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Importing the required sub-modules
        Import-Module -FullyQualifiedName "$ModuleRootPath\WDACSimulation\Get-SignerInfo.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\WDACSimulation\Get-AuthenticodeSignatureEx.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\WDACSimulation\Get-CertificateDetails.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-ExtendedFileInfo.psm1" -Force

        # Get the signer information from the XML file path using the Get-SignerInfo function
        [WDACConfig.Signer[]]$SignerInfo = Get-SignerInfo -XmlFilePath $XmlFilePath -SignedFilePath $SignedFilePath

        # Load the XML file as an XML document object
        [System.Xml.XmlDocument]$Xml = Get-Content -LiteralPath $XmlFilePath

        # Select the FileAttrib nodes of the XML file
        [System.Object[]]$PolicyFileAttributes = $Xml.SiPolicy.FileRules.FileAttrib

        # An ordered hashtable that holds the details of the current file
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
            SpecificFileNameLevelMatchCriteria       = ''       # Only those eligible for FilePublisher level assign this value, otherwise it stays empty
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
            NestedSpecificFileNameLevelMatchCriteria = ''       # Only those eligible for FilePublisher level assign this value, otherwise it stays empty
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

        # Store th leaf certificate details of the Primary Certificate of the signed file
        [System.Object]$PrimaryCertificateLeafDetails = $AllPrimaryCertificateDetails.LeafCertificate

        # Get the Nested (Secondary) certificate of the signed file, if any
        [System.Management.Automation.Signature]$ExtraCertificateDetails = Get-AuthenticodeSignatureEx -FilePath $SignedFilePath

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

                Write-Verbose -Message 'The Leaf Certificates of the primary and nester signers are the same'

                $CurrentFileInfo.HasNestedCert = $false
            }
            else {
                # The file has a nested certificate
                $CurrentFileInfo.HasNestedCert = $true
            }
        }

        # Assign indicators/flags to ascertain if a primary or nested signer was located, thereby avoiding redundant iterations of their loops
        # Initialize them to $False until a nested loop of the FilePublisher identifies a match for SpecificFileNameLevel
        # Owing to the complexity of the loops in those regions, a label is employed to exit multiple loops simultaneously
        [System.Boolean]$FoundMatchPrimary = $false
        [System.Boolean]$FoundMatchNested = $false
    }

    Process {

        # Loop through each signer in the signer information array, These are the signers in the XML policy file
        foreach ($Signer in $SignerInfo) {

            # If a match wasn't already found for the primary signer based on the FilePublisher level
            if (-NOT $FoundMatchPrimary) {

                # Loop through each of the file's primary signer certificate's intermediate certificates
                :PrimaryCertLoopLabel foreach ($Certificate in $PrimaryCertificateIntermediateDetails) {

                    <#         Checking for FilePublisher, Publisher levels eligibility

                    1)  Check if the Signer's CertRoot (referring to the TBS value in the xml file which belongs to an intermediate cert of the file)
                        Matches the TBSValue of one of the file's intermediate certificates

                    2) check if the signer's name (Referring to the one in the XML file) matches the same Intermediate certificate's SubjectCN

                    3) Check if the signer's CertPublisher (aka Leaf Certificate's CN used in the xml policy) matches the leaf certificate's SubjectCN (of the file)
                #>
                    if (($Signer.CertRoot -eq $Certificate.TBSValue) -and ($Signer.Name -eq $Certificate.SubjectCN) -and ($Signer.CertPublisher -eq $PrimaryCertificateLeafDetails.SubjectCN)) {

                        # At this point we know the Signer is either FilePublisher or Publisher level, but we need to narrow it down

                        # Check if the signer has FileAttrib indicating that it was generated with FilePublisher rule
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

                            # Loop over all of the file attributes in the policy XML file whose IDs are in the Signer's file attrib IDs array and the file's version is equal or greater than the minimum version of the file attribute
                            foreach ($FileAttrib in ($PolicyFileAttributes | Where-Object -FilterScript { $Signer.SignerFileAttributeIDs -contains $_.ID -and ($FileVersion -ge [system.version]$_.MinimumFileVersion) })) {

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

                                        break PrimaryCertLoopLabel
                                    }
                                }
                            }
                        }
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
                        }
                    }

                    <#         Checking for PcaCertificate, RootCertificate levels eligibility

                    1)  Check if the Signer's CertRoot (referring to the TBS value in the xml file which belongs to an intermediate cert of the file)
                        Matches the TBSValue of one of the file's intermediate certificates

                    2) check if the signer's name (Referring to the one in the XML file) matches the same Intermediate certificate's SubjectCN
                 #>
                    elseif (($Signer.CertRoot -eq $Certificate.TBSValue) -and ($Signer.Name -eq $Certificate.SubjectCN)) {

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
                    }

                    <#         Checking for LeafCertificate level eligibility

                    1)  Check if the Signer's CertRoot (referring to the TBS value in the xml file, which belongs to the leaf certificate of the file when LeafCertificate level is used)
                        Matches the TBSValue of the file's Leaf certificate certificates

                    2) Check if the signer's name (Referring to the one in the XML file) matches the Leaf certificate's SubjectCN
                 #>
                    elseif (($Signer.CertRoot -eq $PrimaryCertificateLeafDetails.TBSValue) -and ($Signer.Name -eq $PrimaryCertificateLeafDetails.SubjectCN)) {

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
                    }
                }
            }

            # if the file has a nested certificate
            if ($CurrentFileInfo.HasNestedCert) {

                # If a match wasn't already found for the nested signer based on the FilePublisher level
                if (-NOT $FoundMatchNested) {

                    :NestedCertLoopLabel foreach ($NestedCertificate in $NestedCertificateIntermediateDetails) {

                        # FilePublisher, Publisher levels eligibility check
                        if (($Signer.CertRoot -eq $NestedCertificate.TBSValue) -and ($Signer.Name -eq $NestedCertificate.SubjectCN) -and ($Signer.CertPublisher -eq $NestedCertificateLeafDetails.SubjectCN)) {

                            # At this point we know the Signer is either FilePublisher or Publisher level, but we need to narrow it down

                            # Check if the signer has FileAttrib indicating that it was generated with FilePublisher rule
                            if ($Signer.NestedHasFileAttrib) {

                                # Loop over all of the file attributes in the policy XML file whose IDs are in the Signer's file attrib IDs array and the file's version is equal or greater than the minimum version of the file attribute
                                # The File version and ExtendedFileInfo are the same as the primary signer's, so we don't need to reassign them since both signers are being validated for the same file and the primary singer loop always runs first before nested signer loop
                                foreach ($FileAttrib in ($PolicyFileAttributes | Where-Object -FilterScript { ($Signer.SignerFileAttributeIDs -contains $_.ID) -and ($FileVersion -ge [system.version]$_.MinimumFileVersion) })) {

                                    # Loop over all of the keys in the extended file info to see which one of them is a match, to determine the SpecificFileNameLevel option
                                    foreach ($KeyItem in $ExtendedFileInfo.Keys) {

                                        if ($ExtendedFileInfo.$KeyItem -eq $FileAttrib.$KeyItem) {
                                            Write-Verbose -Message "The SpecificFileNameLevel is $KeyItem"

                                            # If there was a match then assign the $KeyItem which is the name of the SpecificFileNameLevel option to the $CurrentFileInfo.SpecificFileNameLevelMatchCriteria
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

                                            break NestedCertLoopLabel
                                        }
                                    }
                                }
                            }
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
                            }
                        }

                        # PcaCertificate, RootCertificate levels eligibility check
                        elseif (($Signer.CertRoot -eq $NestedCertificate.TBSValue) -and ($Signer.Name -eq $NestedCertificate.SubjectCN)) {

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
                        }

                        # LeafCertificate level eligibility check
                        elseif (($Signer.CertRoot -eq $NestedCertificateLeafDetails.TBSValue) -and ($Signer.Name -eq $NestedCertificateLeafDetails.SubjectCN)) {

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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCsatrJxx3D622T
# cvIwxuc3pXQNWCviOyxRcaRno/+OyaCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgAhbDvzcBhOkxBS6ApEx88vdbS07uu4NZ1uts/Nlsi5owDQYJKoZIhvcNAQEB
# BQAEggIAXPuXdVtD1dKOt6qYNAr6N3ULUpZfYJcGrGZ9HTCcQCl+CKvYoo2YsRHH
# kN1fJmHo2YVbwGFMTwPSEXBrAnKxwfI8N2KnCHnqyH4mYNB0CqqNPR4QjZAEWOj1
# 7dcs5XePN0S81cYTioPNlyJDkhxsisZW7zaUf09mxj+XXM64NWSNZbFVoAjv+eaA
# hlYzQ/moFlVQkCnc113LUp2IF8V2jAsUpkNyVBRHxaUyJUxhzRf7P0Ldiu8Bi+l1
# K/yN1ECPjMWiRRQ/5dfUAXwM2GtAAJ/8fpzr7IRNt8bweUjA4+GuTfIUJBH0vNlC
# nKGE0LAeQmbDWeo/9rZT3UPfyQ2XrxMlwEeZj8N3VTSItA8SWO71GxTHvwvpqeia
# nwSnz/7mu0S/2Uy23E1P+pUQpku9kTuvzpEfr40t7ycCf12L/N/lJhWDnsif/f7Z
# BnfPk4DXVeVrSSOP21XqaebETPwIGvaL7cu+iIVOtKhiF/76SB3tZunp2nMGcoDu
# 7znP2WbkmUCPmTRvdTHGSAhjaMNuZJiY9F2z0po9iFqfDkCkBdRhnqLalPe8QUY6
# O6M7hvmycVXGMnuxUMqPEP/AdCRcl3sFbiu3VyzFKUQA8DXFMJgay334lKIAJbTv
# YNhTMtBX4FIRojVAojQS15PsOSb0uHxR9Spm2HO4yYEP+PoBtzU=
# SIG # End signature block
