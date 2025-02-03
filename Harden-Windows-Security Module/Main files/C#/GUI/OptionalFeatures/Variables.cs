using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows;
using System.Windows.Controls;
using Windows.Management.Deployment;

namespace HardenWindowsSecurity;

#pragma warning disable CA1812

internal sealed class SafeToRemoveApp
{
	[JsonInclude]
	internal required string Name { get; set; }

	[JsonInclude]
	internal required string Description { get; set; }
}

// Class used to deserialize the SafeToRemoveAppsList.json file
internal sealed class SafeToRemoveAppsCol
{
	[JsonInclude]
	internal required IReadOnlyCollection<SafeToRemoveApp> SafeToRemoveAppsList { get; set; }
}

#pragma warning restore CA1812

internal static class GUIOptionalFeatures
{
	internal static UserControl? View;

	internal static Grid? ParentGrid;

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
