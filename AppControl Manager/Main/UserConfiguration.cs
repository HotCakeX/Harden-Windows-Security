using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using AppControlManager.IntelGathering;
using AppControlManager.Others;
using AppControlManager.Sidebar;

namespace AppControlManager.Main;

// This is to ensure the Serialize method works when trimming is enabled
// Using source-generated context improves performance
// Embeds the WriteIndented = true configuration into the generated metadata. This means the resulting JSON will be formatted with indentation.
[JsonSerializable(typeof(UserConfiguration), GenerationMode = JsonSourceGenerationMode.Serialization)]
[JsonSourceGenerationOptions(WriteIndented = true)]
public partial class UserConfigurationContext : JsonSerializerContext
{
}



// Represents an instance of the User configurations JSON settings file
// Maintains the order of the properties when writing to the JSON file
// Includes the methods for interacting with user configurations JSON file
public sealed partial class UserConfiguration(
		string? signedPolicyPath,
		string? unsignedPolicyPath,
		string? signToolCustomPath,
		string? certificateCommonName,
		string? certificatePath,
		Guid? strictKernelPolicyGUID,
		DateTime? lastUpdateCheck,
		bool? autoUpdateCheck,
		Dictionary<string, DateTime>? signedPolicyStage1RemovalTimes = null
	)
{
	[JsonPropertyOrder(1)]
	public string? SignedPolicyPath { get; set; } = signedPolicyPath;

	[JsonPropertyOrder(2)]
	public string? UnsignedPolicyPath { get; set; } = unsignedPolicyPath;

	[JsonPropertyOrder(3)]
	public string? SignToolCustomPath { get; set; } = signToolCustomPath;

	[JsonPropertyOrder(4)]
	public string? CertificateCommonName { get; set; } = certificateCommonName;

	[JsonPropertyOrder(5)]
	public string? CertificatePath { get; set; } = certificatePath;

	[JsonPropertyOrder(6)]
	public Guid? StrictKernelPolicyGUID { get; set; } = strictKernelPolicyGUID;

	[JsonPropertyOrder(7)]
	public DateTime? LastUpdateCheck { get; set; } = lastUpdateCheck;

	[JsonPropertyOrder(8)]
	public bool? AutoUpdateCheck { get; set; } = autoUpdateCheck;

	[JsonPropertyOrder(9)]
	public Dictionary<string, DateTime>? SignedPolicyStage1RemovalTimes { get; set; } = signedPolicyStage1RemovalTimes;



	/// <summary>
	/// Sets user configuration settings to the JSON file
	/// By default all params are null, so use named parameters when calling this method for easy invocation
	/// </summary>
	/// <param name="SignedPolicyPath"></param>
	/// <param name="UnsignedPolicyPath"></param>
	/// <param name="SignToolCustomPath"></param>
	/// <param name="CertificateCommonName"></param>
	/// <param name="CertificatePath"></param>
	/// <param name="StrictKernelPolicyGUID"></param>
	/// <param name="LastUpdateCheck"></param>
	/// <param name="AutoUpdateCheck"></param>
	/// <param name="SignedPolicyStage1RemovalTimes"></param>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static UserConfiguration Set(
		string? SignedPolicyPath = null,
		string? UnsignedPolicyPath = null,
		string? SignToolCustomPath = null,
		string? CertificateCommonName = null,
		string? CertificatePath = null,
		Guid? StrictKernelPolicyGUID = null,
		DateTime? LastUpdateCheck = null,
		bool? AutoUpdateCheck = null,
		Dictionary<string, DateTime>? SignedPolicyStage1RemovalTimes = null
		)
	{
		// Validate certificateCommonName
		if (!string.IsNullOrWhiteSpace(CertificateCommonName))
		{
			// Get valid certificate common names
			HashSet<string> certCommonNames = CertCNFetcher.GetCertCNs();

			if (!certCommonNames.Contains(CertificateCommonName))
			{
				throw new InvalidOperationException($"{CertificateCommonName} does not belong to a subject CN of any of the deployed certificates");
			}
		}

		// Validate the SignedPolicyPath parameter
		if (!string.IsNullOrWhiteSpace(SignedPolicyPath))
		{
			if (PolicyFileSigningStatusDetection.Check(SignedPolicyPath) is not SignatureStatus.IsSigned)
			{
				throw new InvalidOperationException($"The specified policy file '{SignedPolicyPath}' is not signed. Please provide a signed policy file.");
			}
		}

		// Validate the UnsignedPolicyPath parameter
		if (!string.IsNullOrWhiteSpace(UnsignedPolicyPath))
		{
			if (PolicyFileSigningStatusDetection.Check(UnsignedPolicyPath) is SignatureStatus.IsSigned)
			{
				throw new InvalidOperationException($"The specified policy file '{UnsignedPolicyPath}' is signed. Please provide an Unsigned policy file.");
			}
		}


		Logger.Write("Trying to parse and read the current user configurations file");
		UserConfiguration UserConfiguration = ReadUserConfiguration();

		// Modify the properties based on the input
		if (!string.IsNullOrWhiteSpace(SignedPolicyPath)) UserConfiguration.SignedPolicyPath = SignedPolicyPath;



		if (!string.IsNullOrWhiteSpace(UnsignedPolicyPath))
		{
			UserConfiguration.UnsignedPolicyPath = UnsignedPolicyPath;

			// This will raise the event and notify all subscribers that the unsigned policy path in user configurations has been changed/set
			Events.UnsignedPolicyManager.OnUnsignedPolicyInUserConfigChanged(UnsignedPolicyPath);
		}


		if (!string.IsNullOrWhiteSpace(SignToolCustomPath)) UserConfiguration.SignToolCustomPath = SignToolCustomPath;
		if (!string.IsNullOrWhiteSpace(CertificateCommonName)) UserConfiguration.CertificateCommonName = CertificateCommonName;
		if (!string.IsNullOrWhiteSpace(CertificatePath)) UserConfiguration.CertificatePath = CertificatePath;
		if (StrictKernelPolicyGUID.HasValue) UserConfiguration.StrictKernelPolicyGUID = StrictKernelPolicyGUID;
		if (LastUpdateCheck.HasValue) UserConfiguration.LastUpdateCheck = LastUpdateCheck;
		if (AutoUpdateCheck.HasValue) UserConfiguration.AutoUpdateCheck = AutoUpdateCheck;

		if (SignedPolicyStage1RemovalTimes is not null)
		{
			UserConfiguration.SignedPolicyStage1RemovalTimes = SignedPolicyStage1RemovalTimes;
		}

		// Write the updated properties back to the JSON file
		WriteUserConfiguration(UserConfiguration);

		return UserConfiguration;
	}


	/// <summary>
	/// Gets the current user configuration settings from the JSON file and return them
	/// </summary>
	/// <returns></returns>
	internal static UserConfiguration Get()
	{
		// Read the current configuration
		UserConfiguration currentConfig = ReadUserConfiguration();
		return currentConfig;
	}


	/// <summary>
	/// Removes the user configurations from the JSON file one by one using the provided parameters
	/// </summary>
	/// <param name="SignedPolicyPath"></param>
	/// <param name="UnsignedPolicyPath"></param>
	/// <param name="SignToolCustomPath"></param>
	/// <param name="CertificateCommonName"></param>
	/// <param name="CertificatePath"></param>
	/// <param name="StrictKernelPolicyGUID"></param>
	/// <param name="LastUpdateCheck"></param>
	/// <param name="AutoUpdateCheck"></param>
	/// <param name="SignedPolicyStage1RemovalTimes"></param>
	internal static void Remove(
	bool SignedPolicyPath = false,
	bool UnsignedPolicyPath = false,
	bool SignToolCustomPath = false,
	bool CertificateCommonName = false,
	bool CertificatePath = false,
	bool StrictKernelPolicyGUID = false,
	bool LastUpdateCheck = false,
	bool AutoUpdateCheck = false,
	bool SignedPolicyStage1RemovalTimes = false
	)
	{
		// Read the current configuration
		UserConfiguration currentConfig = ReadUserConfiguration();

		// Remove properties by setting them to null based on the specified flags
		if (SignedPolicyPath) currentConfig.SignedPolicyPath = null;
		if (UnsignedPolicyPath) currentConfig.UnsignedPolicyPath = null;
		if (SignToolCustomPath) currentConfig.SignToolCustomPath = null;
		if (CertificateCommonName) currentConfig.CertificateCommonName = null;
		if (CertificatePath) currentConfig.CertificatePath = null;
		if (StrictKernelPolicyGUID) currentConfig.StrictKernelPolicyGUID = null;
		if (LastUpdateCheck) currentConfig.LastUpdateCheck = null;
		if (AutoUpdateCheck) currentConfig.AutoUpdateCheck = null;
		if (SignedPolicyStage1RemovalTimes) currentConfig.SignedPolicyStage1RemovalTimes = null;

		// Write the updated configuration back to the JSON file
		WriteUserConfiguration(currentConfig);

		Logger.Write("The specified properties have been removed and set to null in the UserConfigurations.json file.");
	}


	private static UserConfiguration ReadUserConfiguration()
	{
		try
		{
			// Create the WDACConfig folder in Program Files if it doesn't exist
			if (!Directory.Exists(GlobalVars.UserConfigDir))
			{
				_ = Directory.CreateDirectory(GlobalVars.UserConfigDir);
				Logger.Write("The WDACConfig folder in Program Files has been created because it did not exist.");
			}

			// Create User configuration folder in the WDACConfig folder if it doesn't already exist
			string UserConfigDir = Path.Combine(GlobalVars.UserConfigDir, "UserConfigurations");
			if (!Directory.Exists(UserConfigDir))
			{
				_ = Directory.CreateDirectory(UserConfigDir);
				Logger.Write("The WDACConfig folder in Program Files has been created because it did not exist.");
			}

			// Read the JSON file
			string json = File.ReadAllText(GlobalVars.UserConfigJson);
			return ParseJson(json);
		}
		catch (Exception ex)
		{
			// Log the error if JSON is corrupted or any other error occurs
			Logger.Write($"Error reading or parsing the user configuration file: {ex.Message} A new configuration with default values will be created.");

			// Create a new configuration with default values and write it to the file
			UserConfiguration defaultConfig = new(null, null, null, null, null, null, null, null, null);
			WriteUserConfiguration(defaultConfig);

			return defaultConfig;
		}
	}

	/// <summary>
	/// Parses the JSON string and returns a UserConfiguration object
	/// </summary>
	/// <param name="json"></param>
	/// <returns></returns>
	private static UserConfiguration ParseJson(string json)
	{
		using JsonDocument doc = JsonDocument.Parse(json);
		JsonElement root = doc.RootElement;

		return new UserConfiguration(
			TryGetStringProperty(root, nameof(SignedPolicyPath)),
			TryGetStringProperty(root, nameof(UnsignedPolicyPath)),
			TryGetStringProperty(root, nameof(SignToolCustomPath)),
			TryGetStringProperty(root, nameof(CertificateCommonName)),
			TryGetStringProperty(root, nameof(CertificatePath)),
			TryGetGuidProperty(root, nameof(StrictKernelPolicyGUID)),
			TryGetDateTimeProperty(root, nameof(LastUpdateCheck)),
			TryGetBoolProperty(root, nameof(AutoUpdateCheck)),
			TryGetKeyValuePairsProperty(root, nameof(SignedPolicyStage1RemovalTimes))
		);

		static string? TryGetStringProperty(JsonElement root, string propertyName)
		{
			try
			{
				return root.TryGetProperty(propertyName, out var propertyValue) ? propertyValue.GetString() : null;
			}
			catch
			{
				return null;
			}
		}

		static Guid? TryGetGuidProperty(JsonElement root, string propertyName)
		{
			try
			{
				return root.TryGetProperty(propertyName, out var propertyValue) ? Guid.TryParse(propertyValue.GetString(), out var guid) ? guid : null : null;
			}
			catch
			{
				return null;
			}
		}

		static DateTime? TryGetDateTimeProperty(JsonElement root, string propertyName)
		{
			try
			{
				return root.TryGetProperty(propertyName, out var propertyValue) ? propertyValue.GetDateTime() : null;
			}
			catch
			{
				return null;
			}
		}

		static bool? TryGetBoolProperty(JsonElement root, string propertyName)
		{
			try
			{
				return root.TryGetProperty(propertyName, out var propertyValue) ? propertyValue.GetBoolean() : null;
			}
			catch
			{
				return null;
			}
		}

		static Dictionary<string, DateTime>? TryGetKeyValuePairsProperty(JsonElement root, string propertyName)
		{
			try
			{
				return root.TryGetProperty(propertyName, out var propertyValue) && propertyValue.ValueKind == JsonValueKind.Object
					? propertyValue.EnumerateObject().ToDictionary(e => e.Name, e => e.Value.GetDateTime().ToUniversalTime())
					: null;
			}
			catch
			{
				return null;
			}
		}

	}


	/// <summary>
	/// Writes the UserConfiguration object to the JSON file
	/// </summary>
	/// <param name="userConfiguration"></param>
	private static void WriteUserConfiguration(UserConfiguration userConfiguration)
	{
		string jsonString = JsonSerializer.Serialize(userConfiguration, UserConfigurationContext.Default.UserConfiguration);

		// Write the JSON string to the file
		File.WriteAllText(GlobalVars.UserConfigJson, jsonString);
		Logger.Write("The UserConfigurations.json file has been updated successfully.");
	}



	/// <summary>
	/// Adds a new key-value pair to the SignedPolicyStage1RemovalTimes dictionary.
	/// </summary>
	/// <param name="key">The key to add.</param>
	/// <param name="value">The value to associate with the key.</param>
	internal static void AddSignedPolicyStage1RemovalTime(string key, DateTime value)
	{
		// Get the current user configuration
		UserConfiguration currentConfig = ReadUserConfiguration();

		// Initialize the dictionary if it doesn't exist
		currentConfig.SignedPolicyStage1RemovalTimes ??= [];

		// Add the key-value pair to the dictionary
		currentConfig.SignedPolicyStage1RemovalTimes[key] = value; // This will add or update the value for the key

		// Write the updated configuration back to the JSON file
		WriteUserConfiguration(currentConfig);

		Logger.Write($"Key-value pair added to the SignedPolicyStage1RemovalTimes: {key} = {value}");
	}



	/// <summary>
	/// Queries the SignedPolicyStage1RemovalTimes dictionary by key and returns the corresponding value.
	/// </summary>
	/// <param name="key">The key to query.</param>
	/// <returns>The value associated with the key, or null if the key does not exist.</returns>
	internal static DateTime? QuerySignedPolicyStage1RemovalTime(string key)
	{
		// Get the current user configuration
		UserConfiguration currentConfig = ReadUserConfiguration();

		// Return the value if the key exists, otherwise return null
		if (currentConfig.SignedPolicyStage1RemovalTimes is not null && currentConfig.SignedPolicyStage1RemovalTimes.TryGetValue(key, out DateTime value))
		{
			return value;
		}

		// Return null if the key doesn't exist
		return null;
	}



	/// <summary>
	/// Removes a key-value pair from the SignedPolicyStage1RemovalTimes dictionary by key.
	/// </summary>
	/// <param name="key">The key to remove.</param>
	/// <returns>True if the key was successfully removed; false if the key was not found.</returns>
	internal static void RemoveSignedPolicyStage1RemovalTime(string key)
	{
		// Get the current user configuration
		UserConfiguration currentConfig = ReadUserConfiguration();

		// Check if the dictionary exists and contains the key
		if (currentConfig.SignedPolicyStage1RemovalTimes is not null && currentConfig.SignedPolicyStage1RemovalTimes.ContainsKey(key))
		{
			// Remove the key-value pair
			_ = currentConfig.SignedPolicyStage1RemovalTimes.Remove(key);

			// Write the updated configuration back to the JSON file
			WriteUserConfiguration(currentConfig);

			Logger.Write($"Key '{key}' removed from the SignedPolicyStage1RemovalTimes dictionary.");
		}
		else
		{
			Logger.Write($"Key '{key}' not found in the SignedPolicyStage1RemovalTimes dictionary.");
		}
	}

}
