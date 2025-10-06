// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using AppControlManager.IntelGathering;
using AppControlManager.Others;

namespace AppControlManager.Main;

// This is to ensure the Serialize method works when trimming is enabled
// Using source-generated context improves performance
// Embeds the WriteIndented = true configuration into the generated metadata. This means the resulting JSON will be formatted with indentation.
[JsonSerializable(typeof(UserConfiguration), GenerationMode = JsonSourceGenerationMode.Serialization)]
[JsonSourceGenerationOptions(WriteIndented = true)]
internal sealed partial class UserConfigurationContext : JsonSerializerContext
{
}


// Represents an instance of the User configurations JSON settings file
// Maintains the order of the properties when writing to the JSON file
// Includes the methods for interacting with user configurations JSON file
internal sealed partial class UserConfiguration(
		string? signedPolicyPath,
		string? unsignedPolicyPath,
		string? certificateCommonName,
		string? certificatePath,
		Guid? strictKernelPolicyGUID,
		bool? autoUpdateCheck,
		Dictionary<string, DateTime>? signedPolicyStage1RemovalTimes = null
	)
{
	[JsonInclude]
	internal string? SignedPolicyPath { get; set; } = signedPolicyPath;

	[JsonInclude]
	internal string? UnsignedPolicyPath { get; set; } = unsignedPolicyPath;

	[JsonInclude]
	internal string? CertificateCommonName { get; set; } = certificateCommonName;

	[JsonInclude]
	internal string? CertificatePath { get; set; } = certificatePath;

	[JsonInclude]
	internal Guid? StrictKernelPolicyGUID { get; set; } = strictKernelPolicyGUID;

	[JsonInclude]
	internal bool? AutoUpdateCheck { get; set; } = autoUpdateCheck;

	[JsonInclude]
	internal Dictionary<string, DateTime>? SignedPolicyStage1RemovalTimes { get; set; } = signedPolicyStage1RemovalTimes;


	/// <summary>
	/// Sets user configuration settings to the JSON file
	/// By default all params are null, so use named parameters when calling this method for easy invocation
	/// </summary>
	/// <param name="SignedPolicyPath"></param>
	/// <param name="UnsignedPolicyPath"></param>
	/// <param name="CertificateCommonName"></param>
	/// <param name="CertificatePath"></param>
	/// <param name="StrictKernelPolicyGUID"></param>
	/// <param name="AutoUpdateCheck"></param>
	/// <param name="SignedPolicyStage1RemovalTimes"></param>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static UserConfiguration Set(
	string? SignedPolicyPath = null,
	string? UnsignedPolicyPath = null,
	string? CertificateCommonName = null,
	string? CertificatePath = null,
	Guid? StrictKernelPolicyGUID = null,
	bool? AutoUpdateCheck = null,
	Dictionary<string, DateTime>? SignedPolicyStage1RemovalTimes = null
)
	{
		// Validate certificateCommonName
		if (!string.IsNullOrWhiteSpace(CertificateCommonName))
		{
			// Get valid certificate common names
			IEnumerable<string> certCommonNames = CertCNFetcher.GetCertCNs();

			if (!certCommonNames.Contains(CertificateCommonName))
			{
				throw new InvalidOperationException(
					string.Format(
						GlobalVars.GetStr("CertificateCommonNameInvalidErrorMessage"),
						CertificateCommonName));
			}
		}

		// Validate the SignedPolicyPath parameter
		if (!string.IsNullOrWhiteSpace(SignedPolicyPath))
		{
			if (PolicyFileSigningStatusDetection.Check(SignedPolicyPath) is not SignatureStatus.IsSigned)
			{
				throw new InvalidOperationException(
					string.Format(
						GlobalVars.GetStr("PolicyFileNotSignedErrorMessage"),
						SignedPolicyPath));
			}
		}

		// Validate the UnsignedPolicyPath parameter
		if (!string.IsNullOrWhiteSpace(UnsignedPolicyPath))
		{
			if (PolicyFileSigningStatusDetection.Check(UnsignedPolicyPath) is SignatureStatus.IsSigned)
			{
				throw new InvalidOperationException(
					string.Format(
						GlobalVars.GetStr("PolicyFileSignedErrorMessage"),
						UnsignedPolicyPath));
			}
		}

		Logger.Write(GlobalVars.GetStr("ReadingUserConfigurationsFileMessage"));
		UserConfiguration UserConfiguration = ReadUserConfiguration();

		// Modify the properties based on the input
		if (!string.IsNullOrWhiteSpace(SignedPolicyPath)) UserConfiguration.SignedPolicyPath = SignedPolicyPath;
		if (!string.IsNullOrWhiteSpace(UnsignedPolicyPath)) UserConfiguration.UnsignedPolicyPath = UnsignedPolicyPath;
		if (!string.IsNullOrWhiteSpace(CertificateCommonName)) UserConfiguration.CertificateCommonName = CertificateCommonName;
		if (!string.IsNullOrWhiteSpace(CertificatePath)) UserConfiguration.CertificatePath = CertificatePath;
		if (StrictKernelPolicyGUID.HasValue) UserConfiguration.StrictKernelPolicyGUID = StrictKernelPolicyGUID;
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
	/// <param name="CertificateCommonName"></param>
	/// <param name="CertificatePath"></param>
	/// <param name="StrictKernelPolicyGUID"></param>
	/// <param name="AutoUpdateCheck"></param>
	/// <param name="SignedPolicyStage1RemovalTimes"></param>
	internal static void Remove(
	bool SignedPolicyPath = false,
	bool UnsignedPolicyPath = false,
	bool CertificateCommonName = false,
	bool CertificatePath = false,
	bool StrictKernelPolicyGUID = false,
	bool AutoUpdateCheck = false,
	bool SignedPolicyStage1RemovalTimes = false
	)
	{
		// Read the current configuration
		UserConfiguration currentConfig = ReadUserConfiguration();

		// Remove properties by setting them to null based on the specified flags
		if (SignedPolicyPath) currentConfig.SignedPolicyPath = null;
		if (UnsignedPolicyPath) currentConfig.UnsignedPolicyPath = null;
		if (CertificateCommonName) currentConfig.CertificateCommonName = null;
		if (CertificatePath) currentConfig.CertificatePath = null;
		if (StrictKernelPolicyGUID) currentConfig.StrictKernelPolicyGUID = null;
		if (AutoUpdateCheck) currentConfig.AutoUpdateCheck = null;
		if (SignedPolicyStage1RemovalTimes) currentConfig.SignedPolicyStage1RemovalTimes = null;

		// Write the updated configuration back to the JSON file
		WriteUserConfiguration(currentConfig);

		Logger.Write(GlobalVars.GetStr("SpecifiedPropertiesRemovedAndSetToNullMessage"));
	}


	private static UserConfiguration ReadUserConfiguration()
	{
		try
		{
			// Create the AppControl Manager folder in Program Files if it doesn't exist
			if (!Directory.Exists(GlobalVars.UserConfigDir))
			{
				_ = Directory.CreateDirectory(GlobalVars.UserConfigDir);
				Logger.Write(GlobalVars.GetStr("AppControlManagerFolderCreatedMessage"));
			}

			// Create User configuration folder in the AppControl Manager folder if it doesn't already exist
			string UserConfigDir = Path.Combine(GlobalVars.UserConfigDir, "UserConfigurations");
			if (!Directory.Exists(UserConfigDir))
			{
				_ = Directory.CreateDirectory(UserConfigDir);
				Logger.Write(GlobalVars.GetStr("AppControlManagerFolderCreatedMessage"));
			}

			// Read the JSON file
			string json = File.ReadAllText(GlobalVars.UserConfigJson);
			return ParseJson(json);
		}
		catch (Exception ex)
		{
			// Log the error if JSON is corrupted or any other error occurs
			Logger.Write(string.Format(
				GlobalVars.GetStr("ErrorReadingUserConfigMessage"),
				ex.Message));

			// Create a new configuration with default values and write it to the file
			UserConfiguration defaultConfig = new(null, null, null, null, null, null, null);
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
			TryGetStringProperty(root, nameof(CertificateCommonName)),
			TryGetStringProperty(root, nameof(CertificatePath)),
			TryGetGuidProperty(root, nameof(StrictKernelPolicyGUID)),
			TryGetBoolProperty(root, nameof(AutoUpdateCheck)),
			TryGetKeyValuePairsProperty(root, nameof(SignedPolicyStage1RemovalTimes))
		);

		static string? TryGetStringProperty(JsonElement root, string propertyName)
		{
			try
			{
				return root.TryGetProperty(propertyName, out JsonElement propertyValue) ? propertyValue.GetString() : null;
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
				return root.TryGetProperty(propertyName, out JsonElement propertyValue) ? Guid.TryParse(propertyValue.GetString(), out Guid guid) ? guid : null : null;
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
				return root.TryGetProperty(propertyName, out JsonElement propertyValue) ? propertyValue.GetBoolean() : null;
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
				return root.TryGetProperty(propertyName, out JsonElement propertyValue) && propertyValue.ValueKind == JsonValueKind.Object
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
		Logger.Write(GlobalVars.GetStr("UserConfigurationsFileUpdatedSuccessfullyMessage"));
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

		Logger.Write(string.Format(
			GlobalVars.GetStr("KeyValuePairAddedToSignedPolicyStage1RemovalTimesMessage"),
			key,
			value));
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

			Logger.Write(string.Format(
				GlobalVars.GetStr("KeyRemovedFromSignedPolicyStage1RemovalTimesMessage"),
				key));
		}
		else
		{
			Logger.Write(string.Format(
				GlobalVars.GetStr("KeyNotFoundInSignedPolicyStage1RemovalTimesMessage"),
				key));
		}
	}

}
