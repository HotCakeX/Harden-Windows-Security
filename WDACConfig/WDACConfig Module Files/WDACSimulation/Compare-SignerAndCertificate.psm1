# Defining the Signer class from the WDACConfig Namespace if it doesn't already exist
if (-NOT ('WDACConfig.Signer' -as [System.Type]) ) {
    Add-Type -Path "$ModuleRootPath\C#\Signer.cs"
}
Function Compare-SignerAndCertificate {
    <#
    .SYNOPSIS
        A function that takes a WDAC policy XML file path and a Signed file path as inputs and compares the output of the Get-SignerInfo and Get-CertificateDetails functions
        Also checks if the file has nested (2nd) signer and will process it accordingly

        Only returns the result if the file is authorized by the policy using one of the singers
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

        # Get the signer information from the XML file path using the Get-SignerInfo function
        [WDACConfig.Signer[]]$SignerInfo = Get-SignerInfo -XmlFilePath $XmlFilePath -SignedFilePath $SignedFilePath

        # An ordered hashtable that holds the details of the current file
        $CurrentFileInfo = [ordered]@{
            SignerID                       = ''
            SignerName                     = ''
            SignerCertRoot                 = ''
            SignerCertPublisher            = ''
            HasEKU                         = $false
            EKUOID                         = @()
            EKUsMatch                      = $false
            SignerScope                    = ''
            HasFileAttrib                  = $false
            FileAttribName                 = ''
            FileAttribMinimumVersion       = ''
            MatchCriteria                  = ''
            CertSubjectCN                  = ''
            CertIssuerCN                   = ''
            CertNotAfter                   = ''
            CertTBSValue                   = ''
            CertRootMatch                  = $false
            CertNameMatch                  = $false
            CertPublisherMatch             = $false
            HasNestedCert                  = $false
            NestedSignerID                 = ''
            NestedSignerName               = ''
            NestedSignerCertRoot           = ''
            NestedSignerCertPublisher      = ''
            NestedHasEKU                   = $false
            NestedEKUOID                   = @()
            NestedEKUsMatch                = $false
            NestedSignerScope              = ''
            NestedHasFileAttrib            = $false
            NestedFileAttribName           = ''
            NestedFileAttribMinimumVersion = ''
            NestedMatchCriteria            = ''
            NestedCertSubjectCN            = ''
            NestedCertIssuerCN             = ''
            NestedCertNotAfter             = ''
            NestedCertTBSValue             = ''
            NestedCertRootMatch            = $false
            NestedCertNameMatch            = $false
            NestedCertPublisherMatch       = $false
            FilePath                       = $SignedFilePath
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

            # The file has a nested certificate
            $CurrentFileInfo.HasNestedCert = $true
        }
    }

    Process {

        # Loop through each signer in the signer information array, These are the singers in the XML policy file
        foreach ($Signer in $SignerInfo) {

            # Loop through each of the file's primary signer certificate's intermediate certificates
            foreach ($Certificate in $PrimaryCertificateIntermediateDetails) {

                <#         Checking for FilePublisher, Publisher levels eligibility

                    1)  Check if the Signer's CertRoot (referring to the TBS value in the xml file which belongs to an intermediate cert of the file)
                        Matches the TBSValue of one of the file's intermediate certificates

                    2) check if the signer's name (Referring to the one in the XML file) matches the same Intermediate certificate's SubjectCN

                    3) Check if the signer's CertPublisher (aka Leaf Certificate's CN used in the xml policy) matches the leaf certificate's SubjectCN (of the file)
                #>
                if (($Signer.CertRoot -eq $Certificate.TBSValue) -and ($Signer.Name -eq $Certificate.SubjectCN) -and ($Signer.CertPublisher -eq $PrimaryCertificateLeafDetails.SubjectCN)) {

                    $CurrentFileInfo.SignerID = $Signer.ID
                    $CurrentFileInfo.SignerName = $Signer.Name
                    $CurrentFileInfo.SignerCertRoot = $Signer.CertRoot
                    $CurrentFileInfo.SignerCertPublisher = $Signer.CertPublisher
                    $CurrentFileInfo.HasEKU = $Signer.HasEKU
                    $CurrentFileInfo.EKUOID = $Signer.EKUOID
                    $CurrentFileInfo.EKUsMatch = $Signer.EKUsMatch
                    $CurrentFileInfo.SignerScope = $Signer.SignerScope
                    $CurrentFileInfo.HasFileAttrib = $Signer.HasFileAttrib
                    $CurrentFileInfo.FileAttribName = $Signer.FileAttribName
                    $CurrentFileInfo.FileAttribMinimumVersion = $Signer.FileAttribMinimumVersion
                    $CurrentFileInfo.MatchCriteria = 'FilePublisher/Publisher'
                    $CurrentFileInfo.CertSubjectCN = $Certificate.SubjectCN
                    $CurrentFileInfo.CertIssuerCN = $Certificate.IssuerCN
                    $CurrentFileInfo.CertNotAfter = $Certificate.NotAfter
                    $CurrentFileInfo.CertTBSValue = $Certificate.TBSValue
                    $CurrentFileInfo.CertRootMatch = $true
                    $CurrentFileInfo.CertNameMatch = $true
                    $CurrentFileInfo.CertPublisherMatch = $true
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
                    $CurrentFileInfo.FileAttribName = $Signer.FileAttribName
                    $CurrentFileInfo.FileAttribMinimumVersion = $Signer.FileAttribMinimumVersion
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
                    $CurrentFileInfo.FileAttribName = $Signer.FileAttribName
                    $CurrentFileInfo.FileAttribMinimumVersion = $Signer.FileAttribMinimumVersion
                    $CurrentFileInfo.MatchCriteria = 'LeafCertificate'
                    $CurrentFileInfo.SignerScope = $Signer.SignerScope
                    $CurrentFileInfo.HasFileAttrib = $Signer.HasFileAttrib
                    $CurrentFileInfo.CertSubjectCN = $PrimaryCertificateLeafDetails.SubjectCN
                    $CurrentFileInfo.CertIssuerCN = $PrimaryCertificateLeafDetails.IssuerCN
                    $CurrentFileInfo.CertNotAfter = $PrimaryCertificateLeafDetails.NotAfter
                    $CurrentFileInfo.CertTBSValue = $PrimaryCertificateLeafDetails.TBSValue
                    $CurrentFileInfo.CertRootMatch = $true
                    $CurrentFileInfo.CertNameMatch = $true
                    $CurrentFileInfo.CertPublisherMatch = $false
                }
            }

            # if the file has a nested certificate
            if ($CurrentFileInfo.HasNestedCert) {

                foreach ($NestedCertificate in $NestedCertificateIntermediateDetails) {

                    # FilePublisher, Publisher levels eligibility check
                    if (($Signer.CertRoot -eq $NestedCertificate.TBSValue) -and ($Signer.Name -eq $NestedCertificate.SubjectCN) -and ($Signer.CertPublisher -eq $NestedCertificateLeafDetails.SubjectCN)) {

                        $CurrentFileInfo.NestedSignerID = $Signer.ID
                        $CurrentFileInfo.NestedSignerName = $Signer.Name
                        $CurrentFileInfo.NestedSignerCertRoot = $Signer.CertRoot
                        $CurrentFileInfo.NestedSignerCertPublisher = $Signer.CertPublisher
                        $CurrentFileInfo.NestedHasEKU = $Signer.HasEKU
                        $CurrentFileInfo.NestedEKUOID = $Signer.EKUOID
                        $CurrentFileInfo.NestedEKUsMatch = $Signer.EKUsMatch
                        $CurrentFileInfo.NestedSignerScope = $Signer.SignerScope
                        $CurrentFileInfo.NestedHasFileAttrib = $Signer.HasFileAttrib
                        $CurrentFileInfo.NestedFileAttribName = $Signer.FileAttribName
                        $CurrentFileInfo.NestedFileAttribMinimumVersion = $Signer.FileAttribMinimumVersion
                        $CurrentFileInfo.NestedMatchCriteria = 'FilePublisher/Publisher'
                        $CurrentFileInfo.NestedCertSubjectCN = $NestedCertificate.SubjectCN
                        $CurrentFileInfo.NestedCertIssuerCN = $NestedCertificate.IssuerCN
                        $CurrentFileInfo.NestedCertNotAfter = $NestedCertificate.NotAfter
                        $CurrentFileInfo.NestedCertTBSValue = $NestedCertificate.TBSValue
                        $CurrentFileInfo.NestedCertRootMatch = $true
                        $CurrentFileInfo.NestedCertNameMatch = $true
                        $CurrentFileInfo.NestedCertPublisherMatch = $true
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
                        $CurrentFileInfo.NestedFileAttribName = $Signer.FileAttribName
                        $CurrentFileInfo.NestedFileAttribMinimumVersion = $Signer.FileAttribMinimumVersion
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
                        $CurrentFileInfo.NestedFileAttribName = $Signer.FileAttribName
                        $CurrentFileInfo.NestedFileAttribMinimumVersion = $Signer.FileAttribMinimumVersion
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

    End {

        # if the file's primary signer is authorized at least by one criteria and its criteria is not empty
        if (-NOT ([System.String]::IsNullOrWhiteSpace($CurrentFileInfo.MatchCriteria))) {

            Write-Verbose -Message "The primary signer is authorized by the criteria: $($CurrentFileInfo.MatchCriteria) by the following SignerID: $($CurrentFileInfo.SignerID)"

            # If the signer has FileAttrib indicating that it was generated with FilePublisher rule
            if ($CurrentFileInfo.HasFileAttrib -eq $true) {

                # but the criteria is not FilePublisher/Publisher
                if ($CurrentFileInfo.MatchCriteria -ne 'FilePublisher/Publisher') {
                    Write-Verbose -Message "The file's primary signer is authorized and has FileAttrib but the criteria is not FilePublisher/Publisher"
                    Return
                }

                # If the signer's FileAttribName is not empty and it's not 'N/A' which is a place holder assigned by the Get-SignerInfo function if the file doesn't have OriginalFileName attribute
                if ((-NOT ([System.String]::IsNullOrWhiteSpace($CurrentFileInfo.FileAttribName))) -and ($CurrentFileInfo.FileAttribName -ne 'N/A')) {

                    # If the file has original file name attribute
                    if (-NOT ([System.String]::IsNullOrWhiteSpace((Get-Item -Path $CurrentFileInfo.FilePath).VersionInfo.OriginalFilename)) ) {

                        # If the file's original name is not equal to the FileAttribName then the file is not authorized
                        if ((Get-Item -Path $CurrentFileInfo.FilePath).VersionInfo.OriginalFilename -ne $CurrentFileInfo.FileAttribName) {
                            Write-Verbose -Message "The file is not authorized because the FileAttribName '$($CurrentFileInfo.FileAttribName)' does not match the file's OriginalFilename attribute '$((Get-Item -Path $CurrentFileInfo.FilePath).VersionInfo.OriginalFilename)'"
                            Return
                        }
                        else {
                            Write-Verbose -Message "The FileAttribName '$($CurrentFileInfo.FileAttribName)' matches the file's OriginalFilename attribute '$((Get-Item -Path $CurrentFileInfo.FilePath).VersionInfo.OriginalFilename)'"
                        }
                    }
                    else {
                        Write-Verbose -Message 'The file is not authorized because it does not have an OriginalFilename attribute. The signer requires one.'
                        Return
                    }
                }
                else {
                    # If the signer's FileAttribName is empty then there is no need to perform other checks. Maybe file's OriginalFilename wasn't considered for file rule
                }

                # If the signer's FileAttribMinimumVersion is not empty and is not '0.0.0.0' which is either set by WDAC if version can't be determined or it's set by Get-SignerInfo function if version does not exist, as a place holder
                if ((-NOT ([System.String]::IsNullOrWhiteSpace($CurrentFileInfo.FileAttribMinimumVersion))) -and ($CurrentFileInfo.FileAttribMinimumVersion -ne '0.0.0.0')) {

                    # If the file's version is not empty
                    if (-NOT ([System.String]::IsNullOrWhiteSpace((Get-Item -Path $CurrentFileInfo.FilePath).VersionInfo.FileVersionRaw)) ) {

                        # If the file's version is less than the FileAttribMinimumVersion then the file is not authorized
                        if (-NOT ([System.Version]::Parse((Get-Item -Path $CurrentFileInfo.FilePath).VersionInfo.FileVersionRaw) -ge [System.Version]::Parse($CurrentFileInfo.FileAttribMinimumVersion))) {
                            Write-Verbose -Message 'The file is not authorized because the FileAttribMinimumVersion is greater than the file version'
                            Return
                        }
                        else {
                            Write-Verbose -Message "The file's version '$((Get-Item -Path $CurrentFileInfo.FilePath).VersionInfo.FileVersionRaw)' is greater than or equal to the FileAttribMinimumVersion '$($CurrentFileInfo.FileAttribMinimumVersion)'"
                        }
                    }
                    else {
                        # If the file's version is empty then there is no need to perform other checks. Maybe the file doesn't have Version attribute
                    }
                }
            }
            else {
                # If the signer doesn't have FileAttrib then no need to perform other checks since the signer wasn't generated based on FilePublisher level
            }

            # If the file has a nested signer
            if ($CurrentFileInfo.HasNestedCert -eq $true) {

                # If the nested signer is authorized at least by one criteria and its criteria is not empty
                if (-NOT ([System.String]::IsNullOrWhiteSpace($CurrentFileInfo.NestedMatchCriteria))) {

                    Write-Verbose -Message "The nested signer is authorized by the criteria: $($CurrentFileInfo.NestedMatchCriteria) by the following SignerID: $($CurrentFileInfo.NestedSignerID)"

                    # If the nested signer has FileAttrib indicating that it was generated with FilePublisher rule
                    if ($CurrentFileInfo.NestedHasFileAttrib -eq $true) {

                        # but the criteria is not FilePublisher/Publisher
                        if ($CurrentFileInfo.NestedMatchCriteria -ne 'FilePublisher/Publisher') {
                            Write-Verbose -Message "The file's Nested signer is authorized and has FileAttrib but the criteria is not FilePublisher/Publisher"
                            Return
                        }

                        # If the Nested signer's FileAttribName is not empty and it's not 'N/A' which is a place holder assigned by the Get-SignerInfo function if the file doesn't have OriginalFileName attribute
                        if ((-NOT ([System.String]::IsNullOrWhiteSpace($CurrentFileInfo.NestedFileAttribName))) -and ($CurrentFileInfo.NestedFileAttribName -ne 'N/A')) {

                            # If the file has original file name attribute
                            if (-NOT ([System.String]::IsNullOrWhiteSpace((Get-Item -Path $CurrentFileInfo.FilePath).VersionInfo.OriginalFilename))) {

                                # If the file's original name is not equal to the NestedFileAttribName then the file is not authorized
                                if ((Get-Item -Path $CurrentFileInfo.FilePath).VersionInfo.OriginalFilename -ne $CurrentFileInfo.NestedFileAttribName) {
                                    Write-Verbose -Message "The file is not authorized by the nested signer because the NestedFileAttribName '$($CurrentFileInfo.NestedFileAttribName)' does not match the file's OriginalFilename attribute '$((Get-Item -Path $CurrentFileInfo.FilePath).VersionInfo.OriginalFilename)'"
                                    Return
                                }
                                else {
                                    Write-Verbose -Message "The NestedFileAttribName '$($CurrentFileInfo.NestedFileAttribName)' matches the file's OriginalFilename attribute '$((Get-Item -Path $CurrentFileInfo.FilePath).VersionInfo.OriginalFilename)'"
                                }
                            }
                            else {
                                Write-Verbose -Message 'The file is not authorized because it does not have an OriginalFilename attribute. The signer requires one.'
                                Return
                            }
                        }
                        else {
                            # If the nested signer's FileAttribName is empty then there is no need to perform other checks. Maybe file's version wasn't considered for file rule
                        }

                        # If the nested signer's FileAttribMinimumVersion is not empty and it's not '0.0.0.0' which is either set by WDAC if version can't be determined or it's set by Get-SignerInfo function if version does not exist, as a place holder
                        if ((-NOT ([System.String]::IsNullOrWhiteSpace($CurrentFileInfo.NestedFileAttribMinimumVersion))) -and ($CurrentFileInfo.NestedFileAttribMinimumVersion -ne '0.0.0.0')) {

                            # If the file's version is not empty
                            if (-NOT ([System.String]::IsNullOrWhiteSpace((Get-Item -Path $CurrentFileInfo.FilePath).VersionInfo.FileVersionRaw)) ) {

                                # If the file's version is less than the FileAttribMinimumVersion then the file is not authorized
                                if (-NOT ([System.Version]::Parse((Get-Item -Path $CurrentFileInfo.FilePath).VersionInfo.FileVersionRaw) -ge [System.Version]::Parse($CurrentFileInfo.NestedFileAttribMinimumVersion))) {
                                    Write-Verbose -Message 'The file is not authorized by the nested signer because the NestedFileAttribMinimumVersion is greater than the file version'
                                    Return
                                }
                                else {
                                    Write-Verbose -Message "The file's version '$((Get-Item -Path $CurrentFileInfo.FilePath).VersionInfo.FileVersionRaw)' is greater than or equal to the NestedFileAttribMinimumVersion '$($CurrentFileInfo.NestedFileAttribMinimumVersion)'"
                                }
                            }
                            else {
                                # If the file's version is empty then there is no need to perform other checks. Maybe the file doesn't have Version attribute
                            }
                        }
                    }
                    else {
                        # If the nested signer doesn't have FileAttrib then no need to perform other checks since the nested signer wasn't generated based on FilePublisher level
                    }

                    # Return the comparison result of the given file after all the checks have been passed for both primary and nested signers
                    Return $CurrentFileInfo
                }
                else {
                    Write-Verbose -Message "The file's primary signer is authorized but the nested signer is not authorized"
                    Return
                }
            }
            else {
                # Return the comparison result of the given file if there is no nested signer
                Return $CurrentFileInfo
            }
        }
        else {
            # Do nothing since the file's primary signer is not authorized, let alone the nested signer
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
