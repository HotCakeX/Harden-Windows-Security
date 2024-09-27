#nullable enable

using System.Management.Automation;

namespace WDACConfig
{
    // Argument tab auto-completion and ValidateSet for Levels and Fallbacks parameters in the entire module
    public class ScanLevelz : IValidateSetValuesGenerator
    {
        public string[] GetValidValues()
        {
            string[] scanLevelz =
            [
                "Hash", "FileName", "SignedVersion", "Publisher", "FilePublisher",
                "LeafCertificate", "PcaCertificate", "RootCertificate", "WHQL",
                "WHQLPublisher", "WHQLFilePublisher", "PFN", "FilePath", "None"
            ];
            return scanLevelz;
        }
    }
}
