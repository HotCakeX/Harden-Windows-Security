using System.Collections.Generic;

#nullable enable

namespace WDACConfig
{
    // Application Control event tags intelligence
    public class CILogIntel
    {
        // Requested and Validated Signing Level Mappings: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-tag-explanations#requested-and-validated-signing-level
        public static readonly Dictionary<ushort, string> ReqValSigningLevels = new()
        {
            { 0 , "Signing level hasn't yet been checked"},
            { 1 , "File is unsigned or has no signature that passes the active policies"},
            { 2 , "Trusted by Windows Defender Application Control policy"},
            { 3 , "Developer signed code"},
            { 4 , "Authenticode signed"},
            { 5 , "Microsoft Store signed app PPL (Protected Process Light)"},
            { 6 , "Microsoft Store-signed"},
            { 7 , "Signed by an Antimalware vendor whose product is using AMPPL"},
            { 8 , "Microsoft signed"},
            { 11 , "Only used for signing of the .NET NGEN compiler"},
            { 12 , "Windows signed"},
            { 14 , "Windows Trusted Computing Base signed"}
        };

        // SignatureType Mappings: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-tag-explanations#signaturetype
        public static readonly Dictionary<ushort, string> SignatureTypeTable = new()
        {
            { 0,  "Unsigned or verification hasn't been attempted" },
            { 1 , "Embedded signature" },
            { 2 , "Cached signature; presence of a CI EA means the file was previously verified" },
            { 3 , "Cached catalog verified via Catalog Database or searching catalog directly" },
            { 4 , "Uncached catalog verified via Catalog Database or searching catalog directly" },
            { 5 , "Successfully verified using an EA that informs CI that catalog to try first" },
            { 6 , "AppX / MSIX package catalog verified" },
            { 7 , "File was verified" }
        };

        // VerificationError mappings: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-tag-explanations#verificationerror
        public static readonly Dictionary<ushort, string> VerificationErrorTable = new()
        {
            { 0  ,   "Successfully verified signature."},
            { 1  ,   "File has an invalid hash."},
            { 2  ,   "File contains shared writable sections."},
            { 3  ,   "File isn't signed."},
            { 4  ,   "Revoked signature."},
            { 5  ,   "Expired signature."},
            { 6  ,   "File is signed using a weak hashing algorithm, which doesn't meet the minimum policy."},
            { 7  ,   "Invalid root certificate."},
            { 8  ,   "Signature was unable to be validated; generic error."},
            { 9  ,   "Signing time not trusted."},
            { 10 ,   "The file must be signed using page hashes for this scenario."},
            { 11 ,   "Page hash mismatch."},
            { 12 ,   "Not valid for a PPL (Protected Process Light)."},
            { 13 ,   "Not valid for a PP (Protected Process)."},
            { 14 ,   "The signature is missing the required ARM processor EKU."},
            { 15 ,   "Failed WHQL check."},
            { 16 ,   "Default policy signing level not met."},
            { 17 ,   "Custom policy signing level not met; returned when signature doesn't validate against an SBCP-defined set of certs."},
            { 18 ,   "Custom signing level not met; returned if signature fails to match CISigners in UMCI."},
            { 19 ,   "Binary is revoked based on its file hash."},
            { 20 ,   "SHA1 cert hash's timestamp is missing or after valid cutoff as defined by Weak Crypto Policy."},
            { 21 ,   "Failed to pass Windows Defender Application Control policy."},
            { 22 ,   "Not Isolated User Mode (IUM) signed; indicates an attempt to load a standard Windows binary into a virtualization-based security (VBS) trustlet."},
            { 23 ,   "Invalid image hash. This error can indicate file corruption or a problem with the file's signature. Signatures using elliptic curve cryptography (ECC), such as ECDSA, return this VerificationError."},
            { 24 ,   "Flight root not allowed; indicates trying to run flight-signed code on production OS."},
            { 25 ,   "Anti-cheat policy violation."},
            { 26 ,   "Explicitly denied by WDAC policy."},
            { 27 ,   "The signing chain appears to be tampered / invalid."},
            { 28 ,   "Resource page hash mismatch."}
        };
    }
}
