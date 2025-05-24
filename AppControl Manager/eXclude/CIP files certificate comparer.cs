using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;

public class ExtensionDetail
{
    public string OidFriendlyName { get; set; }
    public string OidValue { get; set; }
    public bool Critical { get; set; }
    public string FormattedValue { get; set; }
    public string RawDataHex { get; set; }
    public int RawDataLength { get; set; }
    public override string ToString() => $"{OidFriendlyName ?? "Unknown OID"} ({OidValue}), Critical: {Critical}, Value: {FormattedValue}";
}

public class CertificateDetail
{
    public string Subject { get; set; }
    public string Issuer { get; set; }
    public string Thumbprint { get; set; }
    public string SerialNumber { get; set; }
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public string SignatureAlgorithmFriendlyName { get; set; }
    public string SignatureAlgorithmOid { get; set; }
    public int Version { get; set; }
    public string PublicKeyAlgorithmFriendlyName { get; set; }
    public string PublicKeyAlgorithmOid { get; set; }
    public int PublicKeyLength { get; set; }
    public bool IsSelfSigned { get; set; }
    public string PublicKeyHex { get; set; }
    public string RawDataHex { get; set; }
    public int RawDataLength { get; set; }
    public bool HasPrivateKey { get; set; }
    public bool Archived { get; set; }
    public string FriendlyName { get; set; }
    public List<ExtensionDetail> Extensions { get; set; } = [];
    public List<string> SubjectAlternativeNames { get; set; } = [];
    public List<string> ExtendedKeyUsages { get; set; } = [];
    public string KeyUsage { get; set; }
    public string BasicConstraints { get; set; }
    public string AuthorityKeyIdentifier { get; set; }
    public string SubjectKeyIdentifier { get; set; }
    public string CrlDistributionPoints { get; set; }
    public string AuthorityInformationAccess { get; set; }
    public string CertificatePolicies { get; set; }
    public override string ToString() => $"Cert Subject: {Subject}, Thumbprint: {Thumbprint}";
}

public class AttributeDetail
{
    public string OidFriendlyName { get; set; }
    public string OidValue { get; set; }
    public List<string> Values { get; set; } = [];
    public List<string> RawDataHex { get; set; } = [];
    public override string ToString() => $"{OidFriendlyName ?? "Unknown OID"} ({OidValue}), Values: {string.Join("; ", Values)}";
}

public class SignerIdentifierDetail
{
    public SubjectIdentifierType Type { get; set; }
    public string Value { get; set; }
    public string RawDataHex { get; set; }
    public override string ToString() => $"Type: {Type}, Value: {Value}";
}

public class SignerInfoDetail
{
    public int Version { get; set; }
    public CertificateDetail SignerCertificate { get; set; }
    public string DigestAlgorithmFriendlyName { get; set; }
    public string DigestAlgorithmOid { get; set; }
    public List<AttributeDetail> SignedAttributes { get; set; } = [];
    public List<AttributeDetail> UnsignedAttributes { get; set; } = [];
    public SignerIdentifierDetail SignerIdentifier { get; set; }
    public string SignatureHex { get; set; }
    public int SignatureLength { get; set; }
    public override string ToString() => $"SignerInfo Version: {Version}, Digest: {DigestAlgorithmFriendlyName}";
}

public class FileSignatureDetails
{
    public string FilePath { get; set; }
    public int CmsVersion { get; set; }
    public bool IsDetached { get; set; }
    public string ContentTypeFriendlyName { get; set; }
    public string ContentTypeOid { get; set; }
    public List<SignerInfoDetail> SignerInfos { get; set; } = [];
    public List<CertificateDetail> AllCertificates { get; set; } = [];
    public string RawCmsDataHex { get; set; }
    public int RawCmsDataLength { get; set; }
    public string ContentInfoDataHex { get; set; }
    public int ContentInfoDataLength { get; set; }
}

public class ComparisonResult
{
    public string File1 { get; set; }
    public string File2 { get; set; }
    public FileSignatureDetails Details1 { get; set; }
    public FileSignatureDetails Details2 { get; set; }
    public List<string> OverallCmsStructureDiffs { get; set; } = [];
    public List<string> SignerInfoDiffs { get; set; } = [];
    public List<string> CertificateDiffs { get; set; } = [];
    public List<string> RawDataDiffs { get; set; } = [];
    public List<string> ExtensionDetailDiffs { get; set; } = [];
    public List<string> AttributeDetailDiffs { get; set; } = [];
    public bool ComparisonAborted { get; set; }
    public string AbortReason { get; set; }
}

public static class SignatureComparer
{
    public static FileSignatureDetails GetFileSignatureDetails(string filePath)
    {
        if (!File.Exists(filePath))
        {
            return null;
        }

        byte[] fileBytes;
        try
        {
            fileBytes = File.ReadAllBytes(filePath);
        }
        catch
        {
            return null;
        }

        SignedCms signedCms = new();
        try
        {
            signedCms.Decode(fileBytes);
        }
        catch
        {
            return null;
        }

        var details = new FileSignatureDetails
        {
            FilePath = filePath,
            CmsVersion = signedCms.Version,
            IsDetached = signedCms.Detached,
            ContentTypeFriendlyName = signedCms.ContentInfo.ContentType.FriendlyName,
            ContentTypeOid = signedCms.ContentInfo.ContentType.Value,
            RawCmsDataHex = Convert.ToHexString(fileBytes),
            RawCmsDataLength = fileBytes.Length,
            ContentInfoDataHex = Convert.ToHexString(signedCms.ContentInfo.Content),
            ContentInfoDataLength = signedCms.ContentInfo.Content.Length
        };

        foreach (SignerInfo signerInfo in signedCms.SignerInfos)
        {
            var signerInfoDetail = new SignerInfoDetail
            {
                Version = signerInfo.Version,
                DigestAlgorithmFriendlyName = signerInfo.DigestAlgorithm.FriendlyName,
                DigestAlgorithmOid = signerInfo.DigestAlgorithm.Value
            };

            if (signerInfo.Certificate != null)
            {
                signerInfoDetail.SignerCertificate = ExtractCertificateDetail(signerInfo.Certificate);
            }

            foreach (CryptographicAttributeObject attr in signerInfo.SignedAttributes)
            {
                signerInfoDetail.SignedAttributes.Add(ExtractAttributeDetail(attr));
            }

            foreach (CryptographicAttributeObject attr in signerInfo.UnsignedAttributes)
            {
                signerInfoDetail.UnsignedAttributes.Add(ExtractAttributeDetail(attr));
            }

            signerInfoDetail.SignerIdentifier = new SignerIdentifierDetail
            {
                Type = signerInfo.SignerIdentifier.Type,
                RawDataHex = signerInfo.SignerIdentifier.Value != null ? Convert.ToHexString(Encoding.UTF8.GetBytes(signerInfo.SignerIdentifier.Value.ToString())) : ""
            };

            switch (signerInfo.SignerIdentifier.Type)
            {
                case SubjectIdentifierType.IssuerAndSerialNumber:
                    X509IssuerSerial issuerSerial = (X509IssuerSerial)signerInfo.SignerIdentifier.Value;
                    signerInfoDetail.SignerIdentifier.Value = $"Issuer: {issuerSerial.IssuerName}, SerialNumber: {issuerSerial.SerialNumber}";
                    break;
                case SubjectIdentifierType.SubjectKeyIdentifier:
                    signerInfoDetail.SignerIdentifier.Value = (string)signerInfo.SignerIdentifier.Value;
                    break;
                case SubjectIdentifierType.Unknown:
                case SubjectIdentifierType.NoSignature:
                    signerInfoDetail.SignerIdentifier.Value = signerInfo.SignerIdentifier.Value?.ToString() ?? "N/A";
                    break;
                default:
                    signerInfoDetail.SignerIdentifier.Value = $"Unknown Type - Value: {signerInfo.SignerIdentifier.Value?.ToString() ?? "N/A"}";
                    break;
            }
            details.SignerInfos.Add(signerInfoDetail);
        }

        foreach (X509Certificate2 cert in signedCms.Certificates)
        {
            details.AllCertificates.Add(ExtractCertificateDetail(cert));
        }
        return details;
    }

    private static CertificateDetail ExtractCertificateDetail(X509Certificate2 cert)
    {
        if (cert == null) return null;

        int publicKeyLength = 0;
        try
        {
            if (cert.PublicKey.Oid.Value == "1.2.840.113549.1.1.1") // RSA
            {
                using (RSA rsa = cert.GetRSAPublicKey())
                {
                    if (rsa != null)
                        publicKeyLength = rsa.KeySize;
                }
            }
            else if (cert.PublicKey.Oid.Value == "1.2.840.10045.2.1") // ECC
            {
                using (ECDsa ecdsa = cert.GetECDsaPublicKey())
                {
                    if (ecdsa != null)
                        publicKeyLength = ecdsa.KeySize;
                }
            }
            else
            {
                // Fallback to the obsolete method for other key types
#pragma warning disable SYSLIB0027
                publicKeyLength = cert.PublicKey.Key?.KeySize ?? 0;
#pragma warning restore SYSLIB0027
            }
        }
        catch
        {
            publicKeyLength = 0;
        }

        var certDetail = new CertificateDetail
        {
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            Thumbprint = cert.Thumbprint,
            SerialNumber = cert.SerialNumber,
            NotBefore = cert.NotBefore.ToUniversalTime(),
            NotAfter = cert.NotAfter.ToUniversalTime(),
            SignatureAlgorithmFriendlyName = cert.SignatureAlgorithm.FriendlyName,
            SignatureAlgorithmOid = cert.SignatureAlgorithm.Value,
            Version = cert.Version,
            PublicKeyAlgorithmFriendlyName = cert.PublicKey.Oid.FriendlyName,
            PublicKeyAlgorithmOid = cert.PublicKey.Oid.Value,
            PublicKeyLength = publicKeyLength,
            IsSelfSigned = string.Equals(cert.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase),
            PublicKeyHex = Convert.ToHexString(cert.PublicKey.EncodedKeyValue.RawData),
            RawDataHex = Convert.ToHexString(cert.RawData),
            RawDataLength = cert.RawData.Length,
            HasPrivateKey = cert.HasPrivateKey,
            Archived = cert.Archived,
            FriendlyName = cert.FriendlyName ?? ""
        };

        // Extract detailed extension information
        ExtractDetailedExtensions(cert, certDetail);

        foreach (X509Extension ext in cert.Extensions)
        {
            var extDetail = new ExtensionDetail
            {
                OidFriendlyName = ext.Oid.FriendlyName,
                OidValue = ext.Oid.Value,
                Critical = ext.Critical,
                RawDataHex = Convert.ToHexString(ext.RawData),
                RawDataLength = ext.RawData.Length
            };

            try
            {
                AsnEncodedData asn = new(ext.Oid, ext.RawData);
                extDetail.FormattedValue = asn.Format(true);
            }
            catch (Exception ex)
            {
                extDetail.FormattedValue = $"Error formatting extension: {ex.Message}. Raw Data (hex): {Convert.ToHexString(ext.RawData)}";
            }
            certDetail.Extensions.Add(extDetail);
        }
        return certDetail;
    }

    private static void ExtractDetailedExtensions(X509Certificate2 cert, CertificateDetail certDetail)
    {
        // Subject Alternative Names
        foreach (X509Extension ext in cert.Extensions)
        {
            if (ext.Oid.Value == "2.5.29.17") // Subject Alternative Name
            {
                try
                {
                    X509SubjectAlternativeNameExtension sanExt = new(ext.RawData, ext.Critical);
                    certDetail.SubjectAlternativeNames.AddRange(sanExt.Format(false).Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries));
                }
                catch { }
            }
            else if (ext.Oid.Value == "2.5.29.37") // Extended Key Usage
            {
                try
                {
                    X509EnhancedKeyUsageExtension ekuExt = new(ext, ext.Critical);
                    foreach (Oid oid in ekuExt.EnhancedKeyUsages)
                    {
                        certDetail.ExtendedKeyUsages.Add($"{oid.FriendlyName} ({oid.Value})");
                    }
                }
                catch { }
            }
            else if (ext.Oid.Value == "2.5.29.15") // Key Usage
            {
                try
                {
                    X509KeyUsageExtension kuExt = new(ext, ext.Critical);
                    certDetail.KeyUsage = kuExt.Format(false);
                }
                catch { }
            }
            else if (ext.Oid.Value == "2.5.29.19") // Basic Constraints
            {
                try
                {
                    X509BasicConstraintsExtension bcExt = new(ext, ext.Critical);
                    certDetail.BasicConstraints = $"CA: {bcExt.CertificateAuthority}, PathLengthConstraint: {(bcExt.HasPathLengthConstraint ? bcExt.PathLengthConstraint.ToString() : "None")}";
                }
                catch { }
            }
            else if (ext.Oid.Value == "2.5.29.35") // Authority Key Identifier
            {
                try
                {
                    certDetail.AuthorityKeyIdentifier = Convert.ToHexString(ext.RawData);
                }
                catch { }
            }
            else if (ext.Oid.Value == "2.5.29.14") // Subject Key Identifier
            {
                try
                {
                    X509SubjectKeyIdentifierExtension skiExt = new(ext, ext.Critical);
                    certDetail.SubjectKeyIdentifier = skiExt.SubjectKeyIdentifier;
                }
                catch { }
            }
            else if (ext.Oid.Value == "2.5.29.31") // CRL Distribution Points
            {
                try
                {
                    certDetail.CrlDistributionPoints = ext.Format(false);
                }
                catch { }
            }
            else if (ext.Oid.Value == "1.3.6.1.5.5.7.1.1") // Authority Information Access
            {
                try
                {
                    certDetail.AuthorityInformationAccess = ext.Format(false);
                }
                catch { }
            }
            else if (ext.Oid.Value == "2.5.29.32") // Certificate Policies
            {
                try
                {
                    certDetail.CertificatePolicies = ext.Format(false);
                }
                catch { }
            }
        }
    }

    private static AttributeDetail ExtractAttributeDetail(CryptographicAttributeObject attr)
    {
        var attrDetail = new AttributeDetail
        {
            OidFriendlyName = attr.Oid.FriendlyName,
            OidValue = attr.Oid.Value
        };

        foreach (AsnEncodedData val in attr.Values)
        {
            attrDetail.RawDataHex.Add(Convert.ToHexString(val.RawData));

            if (val is Pkcs9SigningTime signingTime)
            {
                attrDetail.Values.Add(signingTime.SigningTime.ToUniversalTime().ToString("o"));
            }
            else
            {
                try
                {
                    attrDetail.Values.Add(val.Format(true));
                }
                catch (Exception ex)
                {
                    attrDetail.Values.Add($"Error formatting attribute value: {ex.Message}. Raw Data (hex): {Convert.ToHexString(val.RawData)}");
                }
            }
        }
        return attrDetail;
    }

    public static ComparisonResult CompareSignatures(string filePath1, string filePath2)
    {
        var result = new ComparisonResult
        {
            File1 = filePath1,
            File2 = filePath2
        };

        string file1Name = Path.GetFileName(filePath1);
        string file2Name = Path.GetFileName(filePath2);

        FileSignatureDetails details1 = GetFileSignatureDetails(filePath1);
        FileSignatureDetails details2 = GetFileSignatureDetails(filePath2);

        result.Details1 = details1;
        result.Details2 = details2;

        if (details1 == null || details2 == null)
        {
            result.ComparisonAborted = true;
            result.AbortReason = "Comparison aborted due to errors in retrieving signature details for one or both files.";
            return result;
        }

        // Compare overall CMS structure
        CompareField(details1.CmsVersion, details2.CmsVersion, "CMS Version", file1Name, file2Name, result.OverallCmsStructureDiffs);
        CompareField(details1.IsDetached, details2.IsDetached, "Is Detached", file1Name, file2Name, result.OverallCmsStructureDiffs);
        CompareField(details1.ContentTypeFriendlyName, details2.ContentTypeFriendlyName, "Content Type Friendly Name", file1Name, file2Name, result.OverallCmsStructureDiffs);
        CompareField(details1.ContentTypeOid, details2.ContentTypeOid, "Content Type OID", file1Name, file2Name, result.OverallCmsStructureDiffs);
        CompareField(details1.RawCmsDataLength, details2.RawCmsDataLength, "Raw CMS Data Length", file1Name, file2Name, result.OverallCmsStructureDiffs);
        CompareField(details1.ContentInfoDataLength, details2.ContentInfoDataLength, "Content Info Data Length", file1Name, file2Name, result.OverallCmsStructureDiffs);

        // Compare raw data if different lengths
        if (details1.RawCmsDataLength != details2.RawCmsDataLength || details1.RawCmsDataHex != details2.RawCmsDataHex)
        {
            result.RawDataDiffs.Add($"Raw CMS Data differs between files:");
            result.RawDataDiffs.Add($"  '{file1Name}' length: {details1.RawCmsDataLength} bytes");
            result.RawDataDiffs.Add($"  '{file2Name}' length: {details2.RawCmsDataLength} bytes");
            if (details1.RawCmsDataLength == details2.RawCmsDataLength)
            {
                result.RawDataDiffs.Add("  Same length but different content - performing byte-by-byte comparison...");
                CompareHexData(details1.RawCmsDataHex, details2.RawCmsDataHex, "Raw CMS Data", file1Name, file2Name, result.RawDataDiffs);
            }
        }

        if (details1.ContentInfoDataLength != details2.ContentInfoDataLength || details1.ContentInfoDataHex != details2.ContentInfoDataHex)
        {
            result.RawDataDiffs.Add($"Content Info Data differs between files:");
            result.RawDataDiffs.Add($"  '{file1Name}' length: {details1.ContentInfoDataLength} bytes");
            result.RawDataDiffs.Add($"  '{file2Name}' length: {details2.ContentInfoDataLength} bytes");
            if (details1.ContentInfoDataLength == details2.ContentInfoDataLength)
            {
                result.RawDataDiffs.Add("  Same length but different content - performing byte-by-byte comparison...");
                CompareHexData(details1.ContentInfoDataHex, details2.ContentInfoDataHex, "Content Info Data", file1Name, file2Name, result.RawDataDiffs);
            }
        }

        // Compare SignerInfos
        if (details1.SignerInfos.Count != details2.SignerInfos.Count)
        {
            result.SignerInfoDiffs.Add($"Number of SignerInfos differs: '{file1Name}' has {details1.SignerInfos.Count}, '{file2Name}' has {details2.SignerInfos.Count}");
        }
        else
        {
            for (int i = 0; i < details1.SignerInfos.Count; i++)
            {
                CompareSignerInfoDetail(details1.SignerInfos[i], details2.SignerInfos[i], $"SignerInfo #{i + 1}", file1Name, file2Name, result.SignerInfoDiffs, result.AttributeDetailDiffs, result.RawDataDiffs);
            }
        }

        // Compare certificates
        CompareCertificateListByThumbprint(details1.AllCertificates, details2.AllCertificates, "CMS Certificates Collection", file1Name, file2Name, result.CertificateDiffs, result.ExtensionDetailDiffs, result.RawDataDiffs);

        return result;
    }

    private static void CompareHexData(string hex1, string hex2, string context, string file1Name, string file2Name, List<string> output)
    {
        if (hex1 == hex2) return;

        int minLength = Math.Min(hex1.Length, hex2.Length);
        List<int> diffPositions = new();

        for (int i = 0; i < minLength; i += 2) // Compare byte by byte (2 hex chars = 1 byte)
        {
            if (i + 1 < hex1.Length && i + 1 < hex2.Length)
            {
                string byte1 = hex1.Substring(i, 2);
                string byte2 = hex2.Substring(i, 2);
                if (byte1 != byte2)
                {
                    diffPositions.Add(i / 2);
                }
            }
        }

        if (diffPositions.Any())
        {
            output.Add($"{context} - Byte differences found at positions: {string.Join(", ", diffPositions.Take(10))}{(diffPositions.Count > 10 ? $" (and {diffPositions.Count - 10} more)" : "")}");

            // Show first few byte differences
            for (int i = 0; i < Math.Min(5, diffPositions.Count); i++)
            {
                int pos = diffPositions[i];
                string byte1 = pos * 2 + 1 < hex1.Length ? hex1.Substring(pos * 2, 2) : "??";
                string byte2 = pos * 2 + 1 < hex2.Length ? hex2.Substring(pos * 2, 2) : "??";
                output.Add($"  Byte {pos}: '{file1Name}' = 0x{byte1}, '{file2Name}' = 0x{byte2}");
            }
        }

        if (hex1.Length != hex2.Length)
        {
            output.Add($"{context} - Length difference: '{file1Name}' = {hex1.Length / 2} bytes, '{file2Name}' = {hex2.Length / 2} bytes");
        }
    }

    private static void CompareField<T>(T val1, T val2, string fieldName, string file1Name, string file2Name, List<string> output)
    {
        bool val1IsDefault = EqualityComparer<T>.Default.Equals(val1, default(T));
        bool val2IsDefault = EqualityComparer<T>.Default.Equals(val2, default(T));

        if (val1IsDefault && val2IsDefault) return;

        if (val1IsDefault)
        {
            output.Add($"{fieldName}: Only present in '{file2Name}': {val2}");
            return;
        }
        if (val2IsDefault)
        {
            output.Add($"{fieldName}: Only present in '{file1Name}': {val1}");
            return;
        }

        if (!EqualityComparer<T>.Default.Equals(val1, val2))
        {
            output.Add($"{fieldName} differs:\n  '{file1Name}': {val1}\n  '{file2Name}': {val2}");
        }
    }

    private static void CompareSignerInfoDetail(SignerInfoDetail si1, SignerInfoDetail si2, string context, string file1Name, string file2Name, List<string> signerOutput, List<string> attributeOutput, List<string> rawDataOutput)
    {
        CompareField(si1.Version, si2.Version, $"{context} - Version", file1Name, file2Name, signerOutput);
        CompareField(si1.DigestAlgorithmFriendlyName, si2.DigestAlgorithmFriendlyName, $"{context} - Digest Algorithm", file1Name, file2Name, signerOutput);
        CompareField(si1.DigestAlgorithmOid, si2.DigestAlgorithmOid, $"{context} - Digest Algorithm OID", file1Name, file2Name, signerOutput);
        CompareField(si1.SignatureLength, si2.SignatureLength, $"{context} - Signature Length", file1Name, file2Name, signerOutput);

        if (si1.SignatureHex != si2.SignatureHex)
        {
            rawDataOutput.Add($"{context} - Signature differs");
            CompareHexData(si1.SignatureHex, si2.SignatureHex, $"{context} - Signature", file1Name, file2Name, rawDataOutput);
        }

        CompareField(si1.SignerIdentifier?.Type, si2.SignerIdentifier?.Type, $"{context} - Signer Identifier Type", file1Name, file2Name, signerOutput);
        CompareField(si1.SignerIdentifier?.Value, si2.SignerIdentifier?.Value, $"{context} - Signer Identifier Value", file1Name, file2Name, signerOutput);
        CompareField(si1.SignerIdentifier?.RawDataHex, si2.SignerIdentifier?.RawDataHex, $"{context} - Signer Identifier Raw Data", file1Name, file2Name, rawDataOutput);

        CompareCertificateDetail(si1.SignerCertificate, si2.SignerCertificate, $"{context} - Signer Certificate", file1Name, file2Name, signerOutput, attributeOutput, rawDataOutput);

        CompareAttributeList(si1.SignedAttributes, si2.SignedAttributes, $"{context} - Signed Attributes", file1Name, file2Name, attributeOutput, rawDataOutput);

        CompareAttributeList(si1.UnsignedAttributes, si2.UnsignedAttributes, $"{context} - Unsigned Attributes", file1Name, file2Name, attributeOutput, rawDataOutput);
    }

    private static void CompareCertificateDetail(CertificateDetail cert1, CertificateDetail cert2, string context, string file1Name, string file2Name, List<string> certOutput, List<string> extOutput, List<string> rawDataOutput)
    {
        if (cert1 == null && cert2 == null)
        {
            return;
        }
        if (cert1 == null)
        {
            certOutput.Add($"{context}: Only present in '{file2Name}' (Subject: {cert2?.Subject}, Thumbprint: {cert2?.Thumbprint})");
            return;
        }
        if (cert2 == null)
        {
            certOutput.Add($"{context}: Only present in '{file1Name}' (Subject: {cert1?.Subject}, Thumbprint: {cert1?.Thumbprint})");
            return;
        }

        // Basic certificate fields
        CompareField(cert1.Subject, cert2.Subject, $"{context} - Subject", file1Name, file2Name, certOutput);
        CompareField(cert1.Issuer, cert2.Issuer, $"{context} - Issuer", file1Name, file2Name, certOutput);
        CompareField(cert1.Thumbprint, cert2.Thumbprint, $"{context} - Thumbprint", file1Name, file2Name, certOutput);
        CompareField(cert1.SerialNumber, cert2.SerialNumber, $"{context} - SerialNumber", file1Name, file2Name, certOutput);
        CompareField(cert1.NotBefore, cert2.NotBefore, $"{context} - NotBefore (UTC)", file1Name, file2Name, certOutput);
        CompareField(cert1.NotAfter, cert2.NotAfter, $"{context} - NotAfter (UTC)", file1Name, file2Name, certOutput);
        CompareField(cert1.SignatureAlgorithmFriendlyName, cert2.SignatureAlgorithmFriendlyName, $"{context} - Signature Algorithm", file1Name, file2Name, certOutput);
        CompareField(cert1.SignatureAlgorithmOid, cert2.SignatureAlgorithmOid, $"{context} - Signature Algorithm OID", file1Name, file2Name, certOutput);
        CompareField(cert1.Version, cert2.Version, $"{context} - Certificate Version", file1Name, file2Name, certOutput);
        CompareField(cert1.PublicKeyAlgorithmFriendlyName, cert2.PublicKeyAlgorithmFriendlyName, $"{context} - Public Key Algorithm", file1Name, file2Name, certOutput);
        CompareField(cert1.PublicKeyAlgorithmOid, cert2.PublicKeyAlgorithmOid, $"{context} - Public Key Algorithm OID", file1Name, file2Name, certOutput);
        CompareField(cert1.PublicKeyLength, cert2.PublicKeyLength, $"{context} - Public Key Length", file1Name, file2Name, certOutput);
        CompareField(cert1.IsSelfSigned, cert2.IsSelfSigned, $"{context} - IsSelfSigned", file1Name, file2Name, certOutput);
        CompareField(cert1.HasPrivateKey, cert2.HasPrivateKey, $"{context} - HasPrivateKey", file1Name, file2Name, certOutput);
        CompareField(cert1.Archived, cert2.Archived, $"{context} - Archived", file1Name, file2Name, certOutput);
        CompareField(cert1.FriendlyName, cert2.FriendlyName, $"{context} - FriendlyName", file1Name, file2Name, certOutput);
        CompareField(cert1.RawDataLength, cert2.RawDataLength, $"{context} - Raw Data Length", file1Name, file2Name, certOutput);

        // Enhanced extension comparisons
        CompareField(cert1.KeyUsage, cert2.KeyUsage, $"{context} - Key Usage", file1Name, file2Name, certOutput);
        CompareField(cert1.BasicConstraints, cert2.BasicConstraints, $"{context} - Basic Constraints", file1Name, file2Name, certOutput);
        CompareField(cert1.AuthorityKeyIdentifier, cert2.AuthorityKeyIdentifier, $"{context} - Authority Key Identifier", file1Name, file2Name, certOutput);
        CompareField(cert1.SubjectKeyIdentifier, cert2.SubjectKeyIdentifier, $"{context} - Subject Key Identifier", file1Name, file2Name, certOutput);
        CompareField(cert1.CrlDistributionPoints, cert2.CrlDistributionPoints, $"{context} - CRL Distribution Points", file1Name, file2Name, certOutput);
        CompareField(cert1.AuthorityInformationAccess, cert2.AuthorityInformationAccess, $"{context} - Authority Information Access", file1Name, file2Name, certOutput);
        CompareField(cert1.CertificatePolicies, cert2.CertificatePolicies, $"{context} - Certificate Policies", file1Name, file2Name, certOutput);

        // Compare lists
        CompareStringList(cert1.SubjectAlternativeNames, cert2.SubjectAlternativeNames, $"{context} - Subject Alternative Names", file1Name, file2Name, certOutput);
        CompareStringList(cert1.ExtendedKeyUsages, cert2.ExtendedKeyUsages, $"{context} - Extended Key Usages", file1Name, file2Name, certOutput);

        // Raw data comparison
        if (cert1.PublicKeyHex != cert2.PublicKeyHex)
        {
            rawDataOutput.Add($"{context} - Public Key Raw Data differs");
            CompareHexData(cert1.PublicKeyHex, cert2.PublicKeyHex, $"{context} - Public Key", file1Name, file2Name, rawDataOutput);
        }

        if (cert1.RawDataHex != cert2.RawDataHex)
        {
            rawDataOutput.Add($"{context} - Certificate Raw Data differs");
            CompareHexData(cert1.RawDataHex, cert2.RawDataHex, $"{context} - Certificate Raw Data", file1Name, file2Name, rawDataOutput);
        }

        CompareExtensionList(cert1.Extensions, cert2.Extensions, $"{context} - Extensions", file1Name, file2Name, extOutput, rawDataOutput);
    }

    private static void CompareStringList(List<string> list1, List<string> list2, string context, string file1Name, string file2Name, List<string> output)
    {
        if (list1.Count != list2.Count)
        {
            output.Add($"{context} - Count differs: '{file1Name}' has {list1.Count}, '{file2Name}' has {list2.Count}");
        }

        var allItems = list1.Union(list2).Distinct().OrderBy(x => x).ToList();
        foreach (var item in allItems)
        {
            bool in1 = list1.Contains(item);
            bool in2 = list2.Contains(item);

            if (in1 && !in2)
            {
                output.Add($"{context} - Item only in '{file1Name}': {item}");
            }
            else if (!in1 && in2)
            {
                output.Add($"{context} - Item only in '{file2Name}': {item}");
            }
        }
    }

    private static void CompareExtensionList(List<ExtensionDetail> exts1, List<ExtensionDetail> exts2, string context, string file1Name, string file2Name, List<string> extOutput, List<string> rawDataOutput)
    {
        var allOids = exts1.Select(e => e.OidValue).Union(exts2.Select(e => e.OidValue)).Distinct().OrderBy(o => o).ToList();

        if (!allOids.Any() && (exts1.Any() || exts2.Any()))
        {
            extOutput.Add($"{context}: Problem identifying OIDs for extensions. File1 has {exts1.Count}, File2 has {exts2.Count}");
            return;
        }
        if (!allOids.Any()) return;

        foreach (var oid in allOids)
        {
            var ext1 = exts1.FirstOrDefault(e => e.OidValue == oid);
            var ext2 = exts2.FirstOrDefault(e => e.OidValue == oid);
            string extFriendlyName = ext1?.OidFriendlyName ?? ext2?.OidFriendlyName ?? oid;

            if (ext1 != null && ext2 != null)
            {
                if (ext1.Critical != ext2.Critical)
                {
                    extOutput.Add($"{context} - Extension '{extFriendlyName}' ({oid}) - Critical flag differs:\n  '{file1Name}': {ext1.Critical}\n  '{file2Name}': {ext2.Critical}");
                }

                if (ext1.RawDataLength != ext2.RawDataLength)
                {
                    extOutput.Add($"{context} - Extension '{extFriendlyName}' ({oid}) - Raw data length differs:\n  '{file1Name}': {ext1.RawDataLength} bytes\n  '{file2Name}': {ext2.RawDataLength} bytes");
                }

                if (ext1.RawDataHex != ext2.RawDataHex)
                {
                    rawDataOutput.Add($"{context} - Extension '{extFriendlyName}' ({oid}) - Raw data differs");
                    CompareHexData(ext1.RawDataHex, ext2.RawDataHex, $"{context} - Extension '{extFriendlyName}' Raw Data", file1Name, file2Name, rawDataOutput);
                }

                string formatted1 = ext1.FormattedValue?.Replace("\r\n", "\n");
                string formatted2 = ext2.FormattedValue?.Replace("\r\n", "\n");

                if (formatted1 != formatted2)
                {
                    extOutput.Add($"{context} - Extension '{extFriendlyName}' ({oid}) - Formatted value differs:\n  '{file1Name}' Formatted Value:\n    {formatted1?.Replace("\n", "\n    ")}\n  '{file2Name}' Formatted Value:\n    {formatted2?.Replace("\n", "\n    ")}");
                }
            }
            else if (ext1 != null)
            {
                extOutput.Add($"{context} - Extension '{extFriendlyName}' ({oid}) is ONLY in '{file1Name}'. Length: {ext1.RawDataLength} bytes. Value:\n    {ext1.FormattedValue?.Replace("\n", "\n    ")}");
            }
            else
            {
                extOutput.Add($"{context} - Extension '{extFriendlyName}' ({oid}) is ONLY in '{file2Name}'. Length: {ext2.RawDataLength} bytes. Value:\n    {ext2.FormattedValue?.Replace("\n", "\n    ")}");
            }
        }
    }

    private static void CompareAttributeList(List<AttributeDetail> attrs1, List<AttributeDetail> attrs2, string context, string file1Name, string file2Name, List<string> attrOutput, List<string> rawDataOutput)
    {
        var allOids = attrs1.Select(a => a.OidValue).Union(attrs2.Select(a => a.OidValue)).Distinct().OrderBy(o => o).ToList();

        if (!allOids.Any() && (attrs1.Any() || attrs2.Any()))
        {
            attrOutput.Add($"{context}: Problem identifying OIDs for attributes. File1 has {attrs1.Count}, File2 has {attrs2.Count}");
            return;
        }
        if (!allOids.Any()) return;

        foreach (var oid in allOids)
        {
            var attr1 = attrs1.FirstOrDefault(a => a.OidValue == oid);
            var attr2 = attrs2.FirstOrDefault(a => a.OidValue == oid);
            string attrFriendlyName = attr1?.OidFriendlyName ?? attr2?.OidFriendlyName ?? oid;

            if (attr1 != null && attr2 != null)
            {
                var values1 = attr1.Values.Select(v => v?.Replace("\r\n", "\n")).ToList();
                var values2 = attr2.Values.Select(v => v?.Replace("\r\n", "\n")).ToList();

                if (!values1.SequenceEqual(values2))
                {
                    attrOutput.Add($"{context} - Attribute '{attrFriendlyName}' ({oid}) - Values differ:\n  '{file1Name}' Values ({attr1.Values.Count}):\n    {string.Join("\n    ", attr1.Values.Select(v => v?.Replace("\n", "\n      ")))}\n  '{file2Name}' Values ({attr2.Values.Count}):\n    {string.Join("\n    ", attr2.Values.Select(v => v?.Replace("\n", "\n      ")))}");
                }

                // Compare raw data for each value
                if (attr1.RawDataHex.Count == attr2.RawDataHex.Count)
                {
                    for (int i = 0; i < attr1.RawDataHex.Count; i++)
                    {
                        if (attr1.RawDataHex[i] != attr2.RawDataHex[i])
                        {
                            rawDataOutput.Add($"{context} - Attribute '{attrFriendlyName}' ({oid}) - Value #{i + 1} raw data differs");
                            CompareHexData(attr1.RawDataHex[i], attr2.RawDataHex[i], $"{context} - Attribute '{attrFriendlyName}' Value #{i + 1}", file1Name, file2Name, rawDataOutput);
                        }
                    }
                }
                else
                {
                    rawDataOutput.Add($"{context} - Attribute '{attrFriendlyName}' ({oid}) - Different number of raw data values: '{file1Name}' has {attr1.RawDataHex.Count}, '{file2Name}' has {attr2.RawDataHex.Count}");
                }
            }
            else if (attr1 != null)
            {
                attrOutput.Add($"{context} - Attribute '{attrFriendlyName}' ({oid}) is ONLY in '{file1Name}'. Values ({attr1.Values.Count}):\n    {string.Join("\n    ", attr1.Values.Select(v => v?.Replace("\n", "\n      ")))}");
            }
            else
            {
                attrOutput.Add($"{context} - Attribute '{attrFriendlyName}' ({oid}) is ONLY in '{file2Name}'. Values ({attr2.Values.Count}):\n    {string.Join("\n    ", attr2.Values.Select(v => v?.Replace("\n", "\n      ")))}");
            }
        }
    }

    private static void CompareCertificateListByThumbprint(List<CertificateDetail> certs1, List<CertificateDetail> certs2, string context, string file1Name, string file2Name, List<string> certOutput, List<string> extOutput, List<string> rawDataOutput)
    {
        var allThumbprints = certs1.Select(c => c.Thumbprint)
                                   .Union(certs2.Select(c => c.Thumbprint))
                                   .Where(t => !string.IsNullOrEmpty(t))
                                   .Distinct()
                                   .OrderBy(t => t)
                                   .ToList();

        if (!allThumbprints.Any() && (certs1.Any() || certs2.Any()))
        {
            certOutput.Add($"{context}: Problem identifying Thumbprints for certificates. File1 has {certs1.Count}, File2 has {certs2.Count}");
            return;
        }
        if (!allThumbprints.Any()) return;

        certOutput.Add($"Total unique valid certificate thumbprints in {context}: {allThumbprints.Count}");
        foreach (var thumbprint in allThumbprints)
        {
            var cert1 = certs1.FirstOrDefault(c => c.Thumbprint == thumbprint);
            var cert2 = certs2.FirstOrDefault(c => c.Thumbprint == thumbprint);

            string certContext = $"{context} - Certificate (Thumbprint: {thumbprint})";
            if (cert1 != null && cert2 != null)
            {
                certOutput.Add($"Comparing {certContext} (present in both files):");
                CompareCertificateDetail(cert1, cert2, certContext, file1Name, file2Name, certOutput, extOutput, rawDataOutput);
            }
            else if (cert1 != null)
            {
                certOutput.Add($"{certContext} is ONLY in '{file1Name}'. Subject: {cert1.Subject}");
            }
            else
            {
                certOutput.Add($"{certContext} is ONLY in '{file2Name}'. Subject: {cert2.Subject}");
            }
        }
    }
}

class Program
{
    static void Main(string[] args)
    {
        string fileA = @"C:\Users\HotCakeX\Downloads\OLD\AllowMicrosoft.CIP";
        string fileB = @"C:\Users\HotCakeX\Downloads\NEW\AllowMicrosoft.CIP";

        ComparisonResult result = SignatureComparer.CompareSignatures(fileA, fileB);

        Console.WriteLine("== Enhanced Certificate Comparison Result ==");
        Console.WriteLine($"File1: {result.File1}");
        Console.WriteLine($"File2: {result.File2}");

        if (result.ComparisonAborted)
        {
            Console.WriteLine($"Aborted: {result.AbortReason}");
        }
        else
        {
            Console.WriteLine("\n-- Overall CMS Structure Differences --");
            if (!result.OverallCmsStructureDiffs.Any())
            {
                Console.WriteLine("No differences found in CMS structure.");
            }
            else
            {
                foreach (var diff in result.OverallCmsStructureDiffs)
                    Console.WriteLine(diff);
            }

            Console.WriteLine("\n-- SignerInfo Differences --");
            if (!result.SignerInfoDiffs.Any())
            {
                Console.WriteLine("No differences found in SignerInfo.");
            }
            else
            {
                foreach (var diff in result.SignerInfoDiffs)
                    Console.WriteLine(diff);
            }

            Console.WriteLine("\n-- Certificate Differences --");
            if (!result.CertificateDiffs.Any())
            {
                Console.WriteLine("No differences found in certificates.");
            }
            else
            {
                foreach (var diff in result.CertificateDiffs)
                    Console.WriteLine(diff);
            }

            Console.WriteLine("\n-- Raw Data Differences --");
            if (!result.RawDataDiffs.Any())
            {
                Console.WriteLine("No differences found in raw data.");
            }
            else
            {
                foreach (var diff in result.RawDataDiffs)
                    Console.WriteLine(diff);
            }

            Console.WriteLine("\n-- Extension Detail Differences --");
            if (!result.ExtensionDetailDiffs.Any())
            {
                Console.WriteLine("No differences found in extension details.");
            }
            else
            {
                foreach (var diff in result.ExtensionDetailDiffs)
                    Console.WriteLine(diff);
            }

            Console.WriteLine("\n-- Attribute Detail Differences --");
            if (!result.AttributeDetailDiffs.Any())
            {
                Console.WriteLine("No differences found in attribute details.");
            }
            else
            {
                foreach (var diff in result.AttributeDetailDiffs)
                    Console.WriteLine(diff);
            }
        }

        Console.ReadKey();
    }
}