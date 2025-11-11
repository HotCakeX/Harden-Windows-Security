using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace HardenSystemSecurity.Protect;

/// <summary>
/// Represents a single desired WMI value with its declared type.
/// If any of these values match the result of a WMI call then the security measure must be considered value/true/applied.
/// </summary>
internal sealed class WmiDesiredValue(
	string value,
	string type
)
{
	[JsonInclude]
	internal string Value => value;

	[JsonInclude]
	internal string Type => type;
}

/// <summary>
/// Represents one specialized verification item from the JSON file which is an array of these objects.
/// </summary>
internal sealed class WmiSpecialVerificationItem(
	string category,
	string friendlyName,
	uint registryHive,
	string registryKeyName,
	string registryValueName,
	string wmiNamespace,
	string wmiClass,
	string wmiProperty,
	List<WmiDesiredValue> desiredWmiValues,
	bool isSpecialVerification
)
{
	[JsonInclude]
	internal string Category => category;

	[JsonInclude]
	internal string FriendlyName => friendlyName;

	[JsonInclude]
	internal uint RegistryHive => registryHive;

	[JsonInclude]
	internal string RegistryKeyName => registryKeyName;

	[JsonInclude]
	internal string RegistryValueName => registryValueName;

	[JsonInclude]
	internal string WMINamespace => wmiNamespace;

	[JsonInclude]
	internal string WMIClass => wmiClass;

	[JsonInclude]
	internal string WMIProperty => wmiProperty;

	[JsonInclude]
	internal List<WmiDesiredValue> DesiredWMIValues => desiredWmiValues;

	[JsonInclude]
	internal bool IsSpecialVerification => isSpecialVerification;

	// PolicyKey format must match fallback lookup in MUnit (KeyName|ValueName)
	internal string PolicyKey => string.Concat(RegistryKeyName, "|", RegistryValueName);
}

/// <summary>
/// Source generation context for deserializing the JSON array.
/// </summary>
[JsonSourceGenerationOptions(WriteIndented = false)]
[JsonSerializable(typeof(List<WmiSpecialVerificationItem>))]
internal sealed partial class WmiSpecialVerificationJsonContext : JsonSerializerContext
{
}
