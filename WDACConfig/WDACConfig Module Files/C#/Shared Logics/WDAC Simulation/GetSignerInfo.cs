using System;
using System.Collections.Generic;
using System.Xml;

#nullable enable

namespace WDACConfig
{
    public class GetSignerInfo
    {
        /// <summary>
        /// Takes an XML policy content as input and returns an array of Signer objects
        /// The output contains as much info as possible about each signer
        /// </summary>
        /// <param name="xmlContent"></param>
        /// <returns> List<WDACConfig.Signer> </returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static List<Signer> Get(XmlDocument xmlContent)
        {
            // Create namespace manager and add the default namespace with a prefix
            XmlNamespaceManager namespaceManager = new(xmlContent.NameTable);
            namespaceManager.AddNamespace("ns", "urn:schemas-microsoft-com:sipolicy");

            // Get SiPolicy node
            XmlNode siPolicyNode = xmlContent.SelectSingleNode("ns:SiPolicy", namespaceManager)
                ?? throw new InvalidOperationException("Invalid XML structure, SiPolicy node not found");

            // Get User Mode Signers IDs
            HashSet<string> allowedUMCISigners = GetSignerIds(siPolicyNode, namespaceManager, "12", "AllowedSigners");
            HashSet<string> deniedUMCISigners = GetSignerIds(siPolicyNode, namespaceManager, "12", "DeniedSigners");

            // Get Kernel Mode Signers IDs
            HashSet<string> allowedKMCISigners = GetSignerIds(siPolicyNode, namespaceManager, "131", "AllowedSigners");
            HashSet<string> deniedKMCISigners = GetSignerIds(siPolicyNode, namespaceManager, "131", "DeniedSigners");

            // Unique IDs of all Allowed Signers
            HashSet<string> allAllowedSigners = new(allowedUMCISigners, StringComparer.OrdinalIgnoreCase);
            allAllowedSigners.UnionWith(allowedKMCISigners);

            // Unique IDs of all Denied Signers
            HashSet<string> allDeniedSigners = new(deniedUMCISigners, StringComparer.OrdinalIgnoreCase);
            allDeniedSigners.UnionWith(deniedKMCISigners);

            // Well-known IDs for replacing root certificate values
            HashSet<string> wellKnownIDs = new(
            [
                "03", "04", "05", "06", "07", "09", "0A", "0E", "0G", "0H", "0I"
            ], StringComparer.OrdinalIgnoreCase);

            // WHQL EKU Hex value
            string whqlEKUHex = "010A2B0601040182370A0305";

            // An empty list to store the output
            List<Signer> output = [];


            #region
            // Storing all the FileAttrib nodes in the <FileRules> node, in a list
            XmlNodeList? fileAttributes = siPolicyNode.SelectNodes("ns:FileRules/ns:FileAttrib", namespaceManager);

            // Dictionary to store the FileAttrib(s) by their ID for fast lookups
            // It's created only once and used by all signers in the XML file
            Dictionary<string, XmlNode> fileAttribDictionary = [];

            if (fileAttributes is not null)
            {
                // Populate the dictionary with FileAttrib nodes, using their ID as the key
                foreach (XmlNode fileAttrib in fileAttributes)
                {
                    string? id = fileAttrib.Attributes?["ID"]?.Value;

                    if (!string.IsNullOrWhiteSpace(id))
                    {
                        fileAttribDictionary[id] = fileAttrib;
                    }
                }
            }
            #endregion


            #region
            // Select all the EKU nodes in the XML file, if they exist
            XmlNodeList? ekuNodes = siPolicyNode.SelectNodes("ns:EKUs/ns:EKU", namespaceManager);

            // A dictionary to store the correlation between the EKU IDs and their values
            // Keys are EKU IDs
            // Values are EKU values
            Dictionary<string, string> EKUAndValuesCorrelation = [];

            if (ekuNodes is not null)
            {
                // Add the EKU IDs and their values to the dictionary
                foreach (XmlNode Eku in ekuNodes)
                {
                    string? EkuID = Eku.Attributes?["ID"]?.Value;
                    string? EkuValue = Eku.Attributes?["Value"]?.Value;

                    if (EkuID is not null && EkuValue is not null)
                    {
                        EKUAndValuesCorrelation.Add(EkuID, EkuValue);
                    }
                }
            }
            #endregion

            // Get all of the Signer nodes in the Signers node
            XmlNodeList? signerNodes = siPolicyNode.SelectNodes("ns:Signers/ns:Signer", namespaceManager);

            if (signerNodes != null)
            {
                // Loop through each Signer node and extract all of their information
                foreach (XmlNode signer in signerNodes)
                {

                    // Get the ID of the current Signer
                    string signerId = signer.Attributes?["ID"]?.Value!;

                    // Get the name of the current Signer
                    string signerName = signer.Attributes?["Name"]?.Value!;

                    // Determine if the signer is Allowed or Denied
                    bool isAllowed;
                    if (allAllowedSigners.Contains(signerId))
                    {
                        isAllowed = true;
                    }
                    else if (allDeniedSigners.Contains(signerId))
                    {
                        isAllowed = false;
                    }
                    else
                    {
                        // Skip if the current signer is neither an allowed nor a denied signer, meaning it can either be UpdatePolicySigner or SupplementalPolicySigner which we don't need for simulation
                        continue;
                    }

                    // Replacing Wellknown root IDs with their corresponding TBS values and Names (Common Names)
                    // These are all root certificates, they have no leaf or intermediate certificates in their chains, that's why they're called Trusted Roots

                    // Get the CertRoot node of the current Signer
                    XmlNode? certRootNode = signer.SelectSingleNode("ns:CertRoot", namespaceManager);

                    string? certRootValue = null;

                    if (certRootNode is not null)
                    {
                        // Get the Value of the CertRoot
                        certRootValue = certRootNode.Attributes?["Value"]?.Value;
                    }

                    if (certRootNode is not null && certRootValue is not null && wellKnownIDs.Contains(certRootValue))
                    {
                        switch (certRootValue)
                        {
                            case "03":
                                certRootValue = "D67576F5521D1CCAB52E9215E0F9F743";
                                signerName = "Microsoft Authenticode(tm) Root Authority";
                                break;
                            case "04":
                                certRootValue = "8B3C3087B7056F5EC5DDBA91A1B901F0";
                                signerName = "Microsoft Root Authority";
                                break;
                            case "05":
                                certRootValue = "391BE92883D52509155BFEAE27B9BD340170B76B";
                                signerName = "Microsoft Root Certificate Authority";
                                break;
                            case "06":
                                certRootValue = "08FBA831C08544208F5208686B991CA1B2CFC510E7301784DDF1EB5BF0393239";
                                signerName = "Microsoft Root Certificate Authority 2010";
                                break;
                            case "07":
                                certRootValue = "279CD652C4E252BFBE5217AC722205D7729BA409148CFA9E6D9E5B1CB94EAFF1";
                                signerName = "Microsoft Root Certificate Authority 2011";
                                break;
                            case "09":
                                certRootValue = "09CBAFBD98E81B4D6BAAAB32B8B2F5D7";
                                signerName = "Microsoft Test Root Authority";
                                break;
                            case "0A":
                                certRootValue = "7A4D9890B0F9006A6F77472D50D83CA54975FCC2B7EA0563490134E19B78782A";
                                signerName = "Microsoft Testing Root Certificate Authority 2010";
                                break;
                            case "0E":
                                certRootValue = "ED55F82E1444F79CA9DCE826846FDC4E0EA3859E3D26EFEF412D2FFF0C7C8E6C";
                                signerName = "Microsoft Development Root Certificate Authority 2014";
                                break;
                            case "0G":
                                certRootValue = "68D221D720E975DB5CD14B24F2970F86A5B8605A2A1BC784A17B83F7CF500A70EB177CE228273B8540A800178F23EAC8";
                                signerName = "Microsoft ECC Testing Root Certificate Authority 2017";
                                break;
                            case "0H":
                                certRootValue = "214592CB01B59104195F80AF2886DBF85771AF42A3821D104BF18F415158C49CBC233511672CD6C432351AC9228E3E75";
                                signerName = "Microsoft ECC Development Root Certificate Authority 2018";
                                break;
                            case "0I":
                                certRootValue = "32991981BF1575A1A5303BB93A381723EA346B9EC130FDB596A75BA1D7CE0B0A06570BB985D25841E23BE944E8FF118F";
                                signerName = "Microsoft ECC Product Root Certificate Authority 2018";
                                break;
                            default:
                                break;
                        }
                    }

                    // Determine the scope of the signer
                    string signerScope = allowedUMCISigners.Contains(signerId) ? "UserMode" : "KernelMode";

                    // Find all the FileAttribRef nodes within the current signer
                    XmlNodeList? FileAttribRefNodes = signer.SelectNodes("ns:FileAttribRef", namespaceManager);

                    List<string>? ruleIds = [];

                    if (FileAttribRefNodes is not null)
                    {
                        // Extract the RuleID of all of the FileAttribRef nodes
                        foreach (XmlNode FileAttribRefNode in FileAttribRefNodes)
                        {
                            ruleIds.Add(FileAttribRefNode!.Attributes?["RuleID"]?.Value!);
                        }
                    }


                    // Determine whether the signer has a FileAttribRef, if it points to a file
                    #region Region File Attributes Processing

                    // The File Attributes property that will be added to the Signer object
                    // It contains details of all File Attributes associated with the Signer
                    Dictionary<string, Dictionary<string, string>> SignerFileAttributesProperty = [];

                    if (ruleIds.Count > 0)
                    {

                        // Create a list to store matching file attributes
                        var FileAttribsAssociatedWithTheSigner = new List<XmlNode>();

                        // Iterate through the rule IDs and find matching FileAttrib nodes in the dictionary that holds the FileAttrib nodes in the <FileRules> node
                        // Get all the FileAttribs associated with the signer
                        foreach (var id in ruleIds)
                        {
                            if (fileAttribDictionary.TryGetValue(id, out var matchingFileAttrib))
                            {
                                FileAttribsAssociatedWithTheSigner.Add(matchingFileAttrib);
                            }
                        }


                        // Loop over each FileAttribute associated with the Signer
                        foreach (XmlNode item in FileAttribsAssociatedWithTheSigner)
                        {

                            // a temp dictionary to store the current FileAttribute details
                            Dictionary<string, string> temp = [];

                            string? FileName = item.Attributes?["FileName"]?.Value;
                            string? FileDescription = item.Attributes?["FileDescription"]?.Value;
                            string? InternalName = item.Attributes?["InternalName"]?.Value;
                            string? ProductName = item.Attributes?["ProductName"]?.Value;

                            if (FileName is not null)
                            {
                                temp.Add("OriginalFileName", FileName);
                                temp.Add("SpecificFileNameLevel", "OriginalFileName");
                            }
                            else if (FileDescription is not null)
                            {
                                temp.Add("FileDescription", FileDescription);
                                temp.Add("SpecificFileNameLevel", "FileDescription");
                            }
                            else if (InternalName is not null)
                            {
                                temp.Add("InternalName", InternalName);
                                temp.Add("SpecificFileNameLevel", "InternalName");
                            }
                            else if (ProductName is not null)
                            {
                                temp.Add("ProductName", ProductName);
                                temp.Add("SpecificFileNameLevel", "ProductName");
                            }

                            string? MinimumFileVersion = item.Attributes?["MinimumFileVersion"]?.Value;
                            string? MaximumFileVersion = item.Attributes?["MaximumFileVersion"]?.Value;


                            if (MinimumFileVersion is not null)
                            {
                                temp.Add("MinimumFileVersion", MinimumFileVersion);
                            }

                            if (MaximumFileVersion is not null)
                            {
                                temp.Add("MaximumFileVersion", MaximumFileVersion);
                            }

                            SignerFileAttributesProperty.Add(item.Attributes?["ID"]?.Value!, temp);

                        }

                    }

                    #endregion


                    #region Region EKU Processing

                    bool HasEKU = false;
                    bool IsWHQL = false;

                    // Convert all of the EKUs that apply to the signer to their OID values and store them with the Signer info

                    // This list stores only the IDs of the EKUs
                    List<string> CertEKUIDs = [];

                    // This list stores the OID of the current signer's EKUs
                    List<string> CertEKUs = [];

                    // Select all of the <CertEKU> nodes in the current signer
                    XmlNodeList? CertEKU = signer.SelectNodes("ns:CertEKU", namespaceManager);

                    if (CertEKU is not null)
                    {
                        foreach (XmlNode EKU in CertEKU)
                        {
                            string? EKUId = EKU.Attributes?["ID"]?.Value;
                            if (EKUId is not null)
                            {
                                CertEKUIDs.Add(EKUId);
                            }
                        }
                    }


                    foreach (string EkuID in CertEKUIDs)
                    {
                        _ = EKUAndValuesCorrelation.TryGetValue(EkuID, out string? EkuValue);

                        if (EkuValue is not null)
                        {
                            // Check if the current EKU of the signer is WHQL
                            if (string.Equals(EkuValue, whqlEKUHex, StringComparison.OrdinalIgnoreCase))
                            {
                                IsWHQL = true;
                            }

                            // The signer has at least one EKU, so set this to true
                            HasEKU = true;

                            CertEKUs.Add(CertificateHelper.ConvertHexToOID(EkuValue));
                        }
                    }


                    #endregion

                    // Get the signer's cert publisher
                    XmlNode? signerCertPublisher = signer.SelectSingleNode("ns:CertPublisher", namespaceManager);
                    string? certPublisher = null;
                    if (signerCertPublisher is not null)
                    {
                        certPublisher = signerCertPublisher.Attributes?["Value"]?.Value;
                    }


                    // Get the signer's cert Issuer
                    XmlNode? signerCertCertIssuer = signer.SelectSingleNode("ns:CertIssuer", namespaceManager);
                    string? certIssuer = null;
                    if (signerCertCertIssuer is not null)
                    {
                        certIssuer = signerCertCertIssuer.Attributes?["Value"]?.Value;
                    }


                    // Get the signer's CertOemID
                    XmlNode? signerCertOemID = signer.SelectSingleNode("ns:CertOemID", namespaceManager);
                    string? CertOemID = null;
                    if (signerCertOemID is not null)
                    {
                        CertOemID = signerCertOemID.Attributes?["Value"]?.Value;
                    }


                    // Add the current signer's info to the output array
                    output.Add(
                        new Signer(
                           id: signerId,
                            name: signerName,
                            certRoot: certRootValue!,
                            certPublisher: certPublisher,
                            certIssuer: certIssuer,
                            certEKU: CertEKUs.ToArray(),
                            certOemID: CertOemID,
                            fileAttribRef: ruleIds.ToArray(),
                            fileAttrib: SignerFileAttributesProperty,
                            signerScope: signerScope,
                            isWHQL: IsWHQL,
                            isAllowed: isAllowed,
                            hasEKU: HasEKU
                            )
                        );

                }
            }

            return output;
        }

        private static HashSet<string> GetSignerIds(XmlNode siPolicyNode, XmlNamespaceManager namespaceManager, string scenarioValue, string signerType)
        {
            HashSet<string> signerIds = [];
            XmlNodeList? signerNodes = siPolicyNode.SelectNodes($"ns:SigningScenarios/ns:SigningScenario[@Value='{scenarioValue}']/ns:ProductSigners/ns:{signerType}/ns:Signer", namespaceManager);

            if (string.Equals(signerType, "AllowedSigners", StringComparison.OrdinalIgnoreCase))
            {
                signerNodes = siPolicyNode.SelectNodes($"ns:SigningScenarios/ns:SigningScenario[@Value='{scenarioValue}']/ns:ProductSigners/ns:AllowedSigners/ns:AllowedSigner", namespaceManager);
            }
            else if (string.Equals(signerType, "DeniedSigners", StringComparison.OrdinalIgnoreCase))
            {
                signerNodes = siPolicyNode.SelectNodes($"ns:SigningScenarios/ns:SigningScenario[@Value='{scenarioValue}']/ns:ProductSigners/ns:DeniedSigners/ns:DeniedSigner", namespaceManager);
            }

            if (signerNodes != null)
            {
                foreach (XmlNode signerNode in signerNodes)
                {
                    string signerId = signerNode.Attributes?["SignerId"]?.Value ?? string.Empty;
                    if (!string.IsNullOrEmpty(signerId))
                    {
                        _ = signerIds.Add(signerId);
                    }
                }
            }
            return signerIds;
        }

    }
}
