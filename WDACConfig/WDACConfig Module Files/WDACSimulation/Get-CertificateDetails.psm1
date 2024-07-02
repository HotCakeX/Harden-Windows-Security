Function Get-CertificateDetails {
    <#
    .SYNOPSIS
        A function to detect Root, Intermediate and Leaf certificates
        It returns a compound object that contains 2 nested objects for Intermediate and Leaf certificates
    .INPUTS
        WDACConfig.AllCertificatesGrabber.AllFileSigners[]
    .OUTPUTS
        WDACConfig.ChainPackage[]
    .PARAMETER CompleteSignatureResult
    .NOTES
        Old method of recognizing the certificate type:
        If the file's subject common name is equal to the certificate's subject common name, then it's the leaf certificate - If a certificate's subject common name is equal to its issuer common name, then it's a root certificate - otherwise it's an intermediate certificate
        CertType    = ($SubjectCN -eq $IssuerCN) ? 'Root' : (($SubjectCN -eq $FileSubjectCN) ? 'Leaf' : 'Intermediate')
    #>
    [CmdletBinding()]
    [OutputType([WDACConfig.ChainPackage[]])]
    param (
        [Parameter(Mandatory = $true)][WDACConfig.AllCertificatesGrabber.AllFileSigners[]]$CompleteSignatureResult
    )
    Begin {
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false
        . "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\PSDefaultParameterValues.ps1"

        $FinalObject = New-Object -TypeName System.Collections.Generic.List[WDACConfig.ChainPackage]
    }

    process {

        # Loop over each signer of the file, in case the file has multiple separate signers
        for ($i = 0; $i -lt $CompleteSignatureResult.Count; $i++) {

            # Get the current chain and SignedCms of the signer
            [System.Security.Cryptography.X509Certificates.X509Chain]$CurrentChain = $CompleteSignatureResult.Chain[$i]
            [System.Security.Cryptography.Pkcs.SignedCms]$CurrentSignedCms = $CompleteSignatureResult.Signer[$i]

            [System.UInt32]$CertificatesInChainCount = $CurrentChain.ChainElements.Certificate.Count

            :ChainProcessLoop Switch ($CertificatesInChainCount) {

                # If the chain includes a Root, Leaf and at least one Intermediate certificate
                { $_ -gt 2 } {

                    # The last certificate in the chain is the Root certificate
                    [System.Security.Cryptography.X509Certificates.X509Certificate]$CurrentRootCertificate = $CurrentChain.ChainElements.Certificate[-1]

                    $RootCertificate = [WDACConfig.ChainElement]::New(
                        [WDACConfig.CryptoAPI]::GetNameString($CurrentRootCertificate.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $false), # SubjectCN
                        [WDACConfig.CryptoAPI]::GetNameString($CurrentRootCertificate.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $true), # IssuerCN
                        $CurrentRootCertificate.NotAfter,
                        [WDACConfig.CertificateHelper]::GetTBSCertificate($CurrentRootCertificate),
                        $CurrentRootCertificate, # Append the certificate object itself to the output object as well
                        [WDACConfig.CertificateType]::Root
                    )

                    # An array to hold the Intermediate Certificate(s) of the current chain
                    $IntermediateCertificates = New-Object -TypeName System.Collections.Generic.List[WDACConfig.ChainElement]

                    # All the certificates in between are Intermediate certificates
                    foreach ($Cert in $CurrentChain.ChainElements.Certificate[1..($CertificatesInChainCount - 2)]) {

                        # Create a collection of intermediate certificates
                        $IntermediateCertificates.Add([WDACConfig.ChainElement]::New(
                                [WDACConfig.CryptoAPI]::GetNameString($Cert.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $false),
                                [WDACConfig.CryptoAPI]::GetNameString($Cert.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $true),
                                $Cert.NotAfter,
                                [WDACConfig.CertificateHelper]::GetTBSCertificate($Cert) ,
                                $Cert, # Append the certificate object itself to the output object as well
                                [WDACConfig.CertificateType]::Intermediate
                            ))
                    }

                    # The first certificate in the chain is the Leaf certificate
                    [System.Security.Cryptography.X509Certificates.X509Certificate]$CurrentLeafCertificate = $CurrentChain.ChainElements.Certificate[0]

                    $LeafCertificate = [WDACConfig.ChainElement]::New(
                        [WDACConfig.CryptoAPI]::GetNameString($CurrentLeafCertificate.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $false),
                        [WDACConfig.CryptoAPI]::GetNameString($CurrentLeafCertificate.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $true),
                        $CurrentLeafCertificate.NotAfter,
                        [WDACConfig.CertificateHelper]::GetTBSCertificate($CurrentLeafCertificate),
                        $CurrentLeafCertificate, # Append the certificate object itself to the output object as well
                        [WDACConfig.CertificateType]::Leaf
                    )

                    $FinalObject.Add([WDACConfig.ChainPackage]::New(
                            $CurrentChain, # The entire current chain of the certificate
                            $CurrentSignedCms, # The entire current SignedCms object
                            $RootCertificate,
                            $IntermediateCertificates,
                            $LeafCertificate
                        ))

                    Break ChainProcessLoop
                }

                # If the chain only includes a Root and Leaf certificate
                { $_ -eq 2 } {

                    # The last certificate in the chain is the Root certificate
                    [System.Security.Cryptography.X509Certificates.X509Certificate]$CurrentRootCertificate = $CurrentChain.ChainElements.Certificate[-1]

                    $RootCertificate = [WDACConfig.ChainElement]::New(
                        [WDACConfig.CryptoAPI]::GetNameString($CurrentRootCertificate.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $false), # SubjectCN
                        [WDACConfig.CryptoAPI]::GetNameString($CurrentRootCertificate.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $true), # IssuerCN
                        $CurrentRootCertificate.NotAfter,
                        [WDACConfig.CertificateHelper]::GetTBSCertificate($CurrentRootCertificate),
                        $CurrentRootCertificate, # Append the certificate object itself to the output object as well
                        [WDACConfig.CertificateType]::Root
                    )

                    # The first certificate in the chain is the Leaf certificate
                    [System.Security.Cryptography.X509Certificates.X509Certificate]$CurrentLeafCertificate = $CurrentChain.ChainElements.Certificate[0]

                    $LeafCertificate = [WDACConfig.ChainElement]::New(
                        [WDACConfig.CryptoAPI]::GetNameString($CurrentLeafCertificate.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $false),
                        [WDACConfig.CryptoAPI]::GetNameString($CurrentLeafCertificate.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $true),
                        $CurrentLeafCertificate.NotAfter,
                        [WDACConfig.CertificateHelper]::GetTBSCertificate($CurrentLeafCertificate),
                        $CurrentLeafCertificate, # Append the certificate object itself to the output object as well
                        [WDACConfig.CertificateType]::Leaf
                    )

                    $FinalObject.Add([WDACConfig.ChainPackage]::New(
                            $CurrentChain, # The entire current chain of the certificate
                            $CurrentSignedCms, # The entire current SignedCms object
                            $RootCertificate,
                            $null,
                            $LeafCertificate
                        ))

                    break ChainProcessLoop
                }

                # If the chain only includes a Root certificate
                { $_ -eq 1 } {

                    # The only certificate in the chain is the Root certificate
                    [System.Security.Cryptography.X509Certificates.X509Certificate]$CurrentRootCertificate = $CurrentChain.ChainElements.Certificate

                    $RootCertificate = [WDACConfig.ChainElement]::New(
                        [WDACConfig.CryptoAPI]::GetNameString($CurrentRootCertificate.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $false), # SubjectCN
                        [WDACConfig.CryptoAPI]::GetNameString($CurrentRootCertificate.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $true), # IssuerCN
                        $CurrentRootCertificate.NotAfter,
                        [WDACConfig.CertificateHelper]::GetTBSCertificate($CurrentRootCertificate),
                        $CurrentRootCertificate, # Append the certificate object itself to the output object as well
                        [WDACConfig.CertificateType]::Root
                    )

                    $FinalObject.Add([WDACConfig.ChainPackage]::New(
                            $CurrentChain, # The entire current chain of the certificate
                            $CurrentSignedCms, # The entire current SignedCms object
                            $RootCertificate,
                            $null,
                            $null
                        ))

                    break ChainProcessLoop
                }
            }
        }
    }
    End {
        return $FinalObject
    }
}
Export-ModuleMember -Function 'Get-CertificateDetails'
