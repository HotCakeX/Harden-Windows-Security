namespace HardenWindowsSecurity;

internal static class PolicyToCIPConverter
{
	/// <summary>
	/// Converts a XML policy file to CIP binary file using the ConvertFrom-CIPolicy cmdlet of the ConfigCI module
	/// </summary>
	/// <param name="XmlFilePath"></param>
	/// <param name="BinaryFilePath"></param>
	internal static void Convert(string XmlFilePath, string BinaryFilePath)
	{

		// Escape the output policy path for PowerShell
		string escapedXMLFile = $"\\\"{XmlFilePath}\\\"";

		// Escape the output policy path for PowerShell
		string escapedOutputCIP = $"\\\"{BinaryFilePath}\\\"";

		// Construct the PowerShell script
		string script = $"ConvertFrom-CIPolicy -XmlFilePath {escapedXMLFile} -BinaryFilePath {escapedOutputCIP}";

		Logger.LogMessage($"PowerShell code that will be executed: {script}", LogTypeIntel.Information);

		// Execute the command
		ProcessStarter.RunCommand("powershell.exe", $"-NoProfile -Command \"{script}\"");
	}

}
