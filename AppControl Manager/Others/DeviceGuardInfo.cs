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

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AppControlManager.Others;

internal sealed class DeviceGuardInteropClass(
	string? __path,
	string? __nAMESPACE,
	string? __sERVER,
	string? __dERIVATION,
	int? __pROPERTY_COUNT,
	string? __rELPATH,
	string? __dYNASTY,
	string? __sUPERCLASS,
	int? __gENUS,
	List<string>? availableSecurityProperties,
	int? codeIntegrityPolicyEnforcementStatus,
	string? instanceIdentifier,
	List<string>? requiredSecurityProperties,
	List<string>? securityFeaturesEnabled,
	List<string>? securityServicesConfigured,
	List<string>? securityServicesRunning,
	byte? smmIsolationLevel,
	int? usermodeCodeIntegrityPolicyEnforcementStatus,
	string? version,
	int? virtualizationBasedSecurityStatus,
	bool? virtualMachineIsolation,
	List<string>? virtualMachineIsolationProperties
	)
{
	[JsonInclude]
	[JsonPropertyOrder(0)]
	[JsonPropertyName("__PATH")]
	internal string? __PATH { get; } = __path;

	[JsonInclude]
	[JsonPropertyOrder(1)]
	[JsonPropertyName("__NAMESPACE")]
	internal string? __NAMESPACE { get; } = __nAMESPACE;

	[JsonInclude]
	[JsonPropertyOrder(2)]
	[JsonPropertyName("__SERVER")]
	internal string? __SERVER { get; } = __sERVER;

	[JsonInclude]
	[JsonPropertyOrder(3)]
	[JsonPropertyName("__DERIVATION")]
	internal string? __DERIVATION { get; } = __dERIVATION;

	[JsonInclude]
	[JsonPropertyOrder(4)]
	[JsonPropertyName("__PROPERTY_COUNT")]
	internal int? __PROPERTY_COUNT { get; } = __pROPERTY_COUNT;

	[JsonInclude]
	[JsonPropertyOrder(5)]
	[JsonPropertyName("__RELPATH")]
	internal string? __RELPATH { get; } = __rELPATH;

	[JsonInclude]
	[JsonPropertyOrder(6)]
	[JsonPropertyName("__DYNASTY")]
	internal string? __DYNASTY { get; } = __dYNASTY;

	[JsonInclude]
	[JsonPropertyOrder(7)]
	[JsonPropertyName("__SUPERCLASS")]
	internal string? __SUPERCLASS { get; } = __sUPERCLASS;

	[JsonInclude]
	[JsonPropertyOrder(8)]
	[JsonPropertyName("__GENUS")]
	internal int? __GENUS { get; } = __gENUS;

	[JsonInclude]
	[JsonPropertyOrder(9)]
	[JsonPropertyName("AvailableSecurityProperties")]
	internal List<string>? AvailableSecurityProperties { get; } = availableSecurityProperties;

	[JsonInclude]
	[JsonPropertyOrder(10)]
	[JsonPropertyName("CodeIntegrityPolicyEnforcementStatus")]
	internal int? CodeIntegrityPolicyEnforcementStatus { get; } = codeIntegrityPolicyEnforcementStatus;

	[JsonInclude]
	[JsonPropertyOrder(11)]
	[JsonPropertyName("InstanceIdentifier")]
	internal string? InstanceIdentifier { get; } = instanceIdentifier;

	[JsonInclude]
	[JsonPropertyOrder(12)]
	[JsonPropertyName("RequiredSecurityProperties")]
	internal List<string>? RequiredSecurityProperties { get; } = requiredSecurityProperties;

	[JsonInclude]
	[JsonPropertyOrder(13)]
	[JsonPropertyName("SecurityFeaturesEnabled")]
	internal List<string>? SecurityFeaturesEnabled { get; } = securityFeaturesEnabled;

	[JsonInclude]
	[JsonPropertyOrder(14)]
	[JsonPropertyName("SecurityServicesConfigured")]
	internal List<string>? SecurityServicesConfigured { get; } = securityServicesConfigured;

	[JsonInclude]
	[JsonPropertyOrder(15)]
	[JsonPropertyName("SecurityServicesRunning")]
	internal List<string>? SecurityServicesRunning { get; } = securityServicesRunning;

	[JsonInclude]
	[JsonPropertyOrder(16)]
	[JsonPropertyName("SmmIsolationLevel")]
	internal byte? SmmIsolationLevel { get; } = smmIsolationLevel;

	[JsonInclude]
	[JsonPropertyOrder(17)]
	[JsonPropertyName("UsermodeCodeIntegrityPolicyEnforcementStatus")]
	internal int? UsermodeCodeIntegrityPolicyEnforcementStatus { get; } = usermodeCodeIntegrityPolicyEnforcementStatus;

	[JsonInclude]
	[JsonPropertyOrder(18)]
	[JsonPropertyName("Version")]
	internal string? Version { get; } = version;

	[JsonInclude]
	[JsonPropertyOrder(19)]
	[JsonPropertyName("VirtualizationBasedSecurityStatus")]
	internal int? VirtualizationBasedSecurityStatus { get; } = virtualizationBasedSecurityStatus;

	[JsonInclude]
	[JsonPropertyOrder(20)]
	[JsonPropertyName("VirtualMachineIsolation")]
	internal bool? VirtualMachineIsolation { get; } = virtualMachineIsolation;

	[JsonInclude]
	[JsonPropertyOrder(21)]
	[JsonPropertyName("VirtualMachineIsolationProperties")]
	internal List<string>? VirtualMachineIsolationProperties { get; } = virtualMachineIsolationProperties;
}

[JsonSourceGenerationOptions(WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
	PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(DeviceGuardInteropClass))]
internal sealed partial class DeviceGuardJsonContext : JsonSerializerContext
{
}

internal static class DeviceGuardInfo
{

	/// <summary>
	/// Get the Device Guard status information from the Win32_DeviceGuard WMI class
	/// </summary>
	/// <returns></returns>
	internal static DeviceGuardInteropClass GetDeviceGuardStatus()
	{

		string? jsonResult = ProcessStarter.RunCommand(GlobalVars.DeviceGuardWMIRetrieverProcessPath, null) ?? throw new InvalidOperationException($"No JSON output were returned from {GlobalVars.DeviceGuardWMIRetrieverProcessPath}");

		try
		{
			Logger.Write(GlobalVars.GetStr("AttemptingToDeserializeDeviceGuardJsonResultMessage"));

			DeviceGuardInteropClass? deviceGuardResult = JsonSerializer.Deserialize(jsonResult, DeviceGuardJsonContext.Default.DeviceGuardInteropClass);

			return deviceGuardResult is null
					? throw new InvalidOperationException(GlobalVars.GetStr("DeviceGuardDeserializationFailedMessage") + jsonResult)
					: deviceGuardResult;
		}
		catch (JsonException ex)
		{
			throw new InvalidOperationException(GlobalVars.GetStr("DeviceGuardDeserializationFailedMessage") + jsonResult, ex);
		}


		/*

		// Define the WMI query to get the Win32_DeviceGuard class information
		string query = "SELECT UsermodeCodeIntegrityPolicyEnforcementStatus, CodeIntegrityPolicyEnforcementStatus FROM Win32_DeviceGuard";

		// Define the scope (namespace) for the query
		string scope = @"\\.\root\Microsoft\Windows\DeviceGuard";

		// Create a ManagementScope object for the WMI namespace
		ManagementScope managementScope = new(scope);

		// Create an ObjectQuery to specify the WMI query
		ObjectQuery objectQuery = new(query);

		// Create a ManagementObjectSearcher to execute the query
		using (ManagementObjectSearcher searcher = new(managementScope, objectQuery))
		{
			// Execute the query and retrieve the results
			foreach (ManagementObject obj in searcher.Get().Cast<ManagementObject>())
			{
				// Create an instance of the custom class to hold the result
				DeviceGuardStatus status = new()
				{
					// Retrieve the relevant properties and assign them to the class
					UsermodeCodeIntegrityPolicyEnforcementStatus = obj["UsermodeCodeIntegrityPolicyEnforcementStatus"] as uint?,
					CodeIntegrityPolicyEnforcementStatus = obj["CodeIntegrityPolicyEnforcementStatus"] as uint?
				};

				return status;  // Return the first instance
			}
		}

		*/

	}
}
