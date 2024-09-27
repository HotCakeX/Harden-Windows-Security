namespace WDACConfig
{
    public class PolicyToCIPConverter
    {
        /// <summary>
        /// Converts a XML policy file to CIP binary file using the ConvertFrom-CIPolicy PowerShell cmdlet of the ConfigCI module
        /// </summary>
        /// <param name="XmlFilePath"></param>
        /// <param name="BinaryFilePath"></param>
        public static void Convert(string XmlFilePath, string BinaryFilePath)
        {

            string script = $"ConvertFrom-CIPolicy -XmlFilePath \"{XmlFilePath}\" -BinaryFilePath \"{BinaryFilePath}\"";

            _ = PowerShellExecutor.ExecuteScript(script);
        }
    }
}
