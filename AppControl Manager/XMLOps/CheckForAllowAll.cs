using System.IO;
using System.Text.RegularExpressions;

namespace AppControlManager.XMLOps;

internal static partial class CheckForAllowAll
{
	/// <summary>
	/// Takes a XML file path and checks whether it has an allow all rule
	/// </summary>
	/// <param name="xmlFilePath"></param>
	/// <returns></returns>
	internal static bool Check(string xmlFilePath)
	{
		// Read the content of the XML file into a string
		string xmlContent = File.ReadAllText(xmlFilePath);

		Regex allowAllRegex = MyRegex();

		// Check if the pattern matches the XML content
		return allowAllRegex.IsMatch(xmlContent);
	}

	[GeneratedRegex(@"<Allow ID=""ID_ALLOW_.*"" FriendlyName="".*"" FileName=""\*"".*/>", RegexOptions.Compiled)]
	private static partial Regex MyRegex();
}
