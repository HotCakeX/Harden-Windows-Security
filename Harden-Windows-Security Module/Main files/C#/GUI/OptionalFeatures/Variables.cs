using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows;
using System.Windows.Controls;
using Windows.Management.Deployment;

namespace HardenWindowsSecurity;

internal static class GUIOptionalFeatures
{
	internal static UserControl? View;

	internal static Grid? ParentGrid;

	public class SafeToRemoveApp
	{
		[JsonPropertyName("Name")]
		public required string Name { get; set; }

		[JsonPropertyName("Description")]
		public required string Description { get; set; }
	}

	// Class used to deserialize the SafeToRemoveAppsList.json file
	public class SafeToRemoveAppsCol
	{
		[JsonPropertyName("SafeToRemoveAppsList")]
		public required IReadOnlyCollection<SafeToRemoveApp> SafeToRemoveAppsList { get; set; }
	}

	internal static Dictionary<string, string> nameToDescriptionApps = [];
	internal static Dictionary<string, string> descriptionToNameApps = [];

	internal static readonly Thickness thicc = new(10, 10, 40, 10);

	// A dictionary to store all checkboxes for Apps ListView
	internal static Dictionary<string, CheckBox> appsCheckBoxes = [];

	internal static PackageManager packageMgr = new();

	// Dictionary to store pairs of App Names and FullNames
	internal static Dictionary<string, string> appNameToFullNameDictionary = [];

	internal static JsonSerializerOptions JsonSerializerOptions = new()
	{
		PropertyNameCaseInsensitive = true,  // Case-insensitive property matching
		WriteIndented = true,               // Pretty-print JSON outputs
		DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull // Ignore null values
	};
}
