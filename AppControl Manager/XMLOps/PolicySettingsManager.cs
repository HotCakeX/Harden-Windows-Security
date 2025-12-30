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
using System.Runtime.InteropServices;
using AppControlManager.SiPolicy;

namespace AppControlManager.XMLOps;

internal static class PolicySettingsManager
{
	/// <summary>
	/// Gets the policy name.
	/// </summary>
	/// <param name="PolicyObj"></param>
	/// <param name="PolicyFilePath"></param>
	/// <returns></returns>
	internal static string? GetPolicyName(SiPolicy.SiPolicy? PolicyObj, string? PolicyFilePath)
	{

		SiPolicy.SiPolicy PolicyObjToUse = PolicyObj ?? Management.Initialize(PolicyFilePath, null);

		string? PolicyName = null;

		foreach (Setting item in CollectionsMarshal.AsSpan(PolicyObjToUse.Settings))
		{
			if (string.Equals(item.ValueName, "Name", StringComparison.OrdinalIgnoreCase) &&
				string.Equals(item.Provider, "PolicyInfo", StringComparison.OrdinalIgnoreCase) &&
				string.Equals(item.Key, "Information", StringComparison.OrdinalIgnoreCase))
			{
				if (item.Value.Item is not null)
				{
					PolicyName = (string)item.Value.Item;
					break;
				}
			}
		}

		return PolicyName;
	}

	/// <summary>
	/// Sets a policy name.
	/// </summary>
	/// <param name="PolicyObj"></param>
	/// <param name="name"></param>
	internal static void SetPolicyName(SiPolicy.SiPolicy PolicyObj, string? name)
	{
		if (string.IsNullOrWhiteSpace(name))
			return;

		bool nameSettingFound = false;

		// Set the policy name
		foreach (Setting item in CollectionsMarshal.AsSpan(PolicyObj.Settings))
		{
			if (string.Equals(item.ValueName, "Name", StringComparison.OrdinalIgnoreCase) &&
			string.Equals(item.Provider, "PolicyInfo", StringComparison.OrdinalIgnoreCase) &&
			string.Equals(item.Key, "Information", StringComparison.OrdinalIgnoreCase))
			{
				item.Value.Item = name;

				nameSettingFound = true;

				break;
			}
		}

		// If the Setting node with ValueName="Name" does not exist, create it
		if (!nameSettingFound)
		{
			PolicyObj.Settings ??= [];

			PolicyObj.Settings.Add(new(
				provider: "PolicyInfo",
				key: "Information",
				valueName: "Name",
				value: new SettingValueType(
					item: name
				)
			));
		}
	}

	/// <summary>
	/// Gets the PolicyInfo.
	/// </summary>
	/// <param name="PolicyObj"></param>
	/// <param name="PolicyFilePath"></param>
	/// <returns></returns>
	internal static string? GetPolicyIDInfo(SiPolicy.SiPolicy? PolicyObj, string? PolicyFilePath)
	{

		SiPolicy.SiPolicy PolicyObjToUse = PolicyObj ?? Management.Initialize(PolicyFilePath, null);

		string? PolicyIDInfo = null;

		foreach (Setting item in CollectionsMarshal.AsSpan(PolicyObjToUse.Settings))
		{
			if (string.Equals(item.ValueName, "Id", StringComparison.OrdinalIgnoreCase) &&
				string.Equals(item.Provider, "PolicyInfo", StringComparison.OrdinalIgnoreCase) &&
				string.Equals(item.Key, "Information", StringComparison.OrdinalIgnoreCase))
			{
				if (item.Value.Item is not null)
				{
					PolicyIDInfo = (string)item.Value.Item;

					break;
				}
			}
		}

		return PolicyIDInfo;
	}

	/// <summary>
	/// Sets the policy ID info.
	/// </summary>
	/// <param name="PolicyObj"></param>
	/// <param name="PolicyFilePath"></param>
	internal static void SetPolicyIDInfo(SiPolicy.SiPolicy PolicyObj, string? PolicyIDInfo)
	{
		if (string.IsNullOrWhiteSpace(PolicyIDInfo))
			return;

		bool policyInfoIDSettingFound = false;

		// Set the PolicyInfoID if the setting for it exist
		foreach (Setting item in CollectionsMarshal.AsSpan(PolicyObj.Settings))
		{
			if (string.Equals(item.ValueName, "Id", StringComparison.OrdinalIgnoreCase) &&
			string.Equals(item.Provider, "PolicyInfo", StringComparison.OrdinalIgnoreCase) &&
			string.Equals(item.Key, "Information", StringComparison.OrdinalIgnoreCase))
			{
				item.Value.Item = PolicyIDInfo;

				policyInfoIDSettingFound = true;

				break;
			}
		}

		// If the setting for PolicyInfoID does not exist, create it
		if (!policyInfoIDSettingFound)
		{
			PolicyObj.Settings ??= [];

			PolicyObj.Settings.Add(new(
				provider: "PolicyInfo",
				key: "Information",
				valueName: "Id",
				value: new SettingValueType(
					item: PolicyIDInfo
				)
			));
		}
	}

	/// <summary>
	/// Gets all of the policy settings and return a custom class of them for Policy Editor.
	/// </summary>
	/// <param name="PolicyObj"></param>
	/// <param name="VMRef"></param>
	/// <returns></returns>
	internal static List<AppControlManager.PolicyEditor.PolicySettings> GetPolicySettings(List<Setting>? policySettings, ViewModels.PolicyEditorVM VMRef)
	{
		List<AppControlManager.PolicyEditor.PolicySettings> output = [];

		foreach (Setting item in CollectionsMarshal.AsSpan(policySettings))
		{
			// To prevent Policy Name and Policy Info ID to be displayed in Policy Editor's Custom Settings section
			// Because they have to be modified via the Policy Details Tab only.
			if (string.Equals(item.Provider, "PolicyInfo", StringComparison.OrdinalIgnoreCase) &&
				string.Equals(item.Key, "Information", StringComparison.OrdinalIgnoreCase))
			{
				if (string.Equals(item.ValueName, "Id", StringComparison.OrdinalIgnoreCase) ||
					string.Equals(item.ValueName, "Name", StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}
			}

			try
			{
				output.Add(new AppControlManager.PolicyEditor.PolicySettings(
					parentViewModel: VMRef,
					provider: item.Provider,
					key: item.Key,
					value: item.Value.Item,
					valueStr: item.Value.Item.ToString() ?? string.Empty,
					valueName: item.ValueName,
					type: GetValueType(item.Value)
					));
			}
			catch { }
		}

		return output;
	}

	private static int GetValueType(SettingValueType? type) => type?.Item switch
	{
		byte[] => 0, // (Binary)
		bool => 1, // (Boolean)
		uint => 2, // (DWord)
		string => 3, // (String)
		_ => -1
	};

	// Map the integer index to the actual CLR type
	private static SettingValueType SetValueType(int type, object value) => type switch
	{
		// 0 = byte[]  (Binary)
		0 => new SettingValueType(item: (byte[])value),

		// 1 = bool    (Boolean)
		1 => new SettingValueType(item: Convert.ToBoolean(value)),

		// 2 = uint    (DWord)
		2 => new SettingValueType(item: Convert.ToUInt32(value)),

		// 3 = string  (String)
		3 => new SettingValueType(item: Convert.ToString(value)!),

		_ => throw new ArgumentOutOfRangeException(
				 nameof(type),
				 type,
				 $"Unsupported SettingValueType index: {type}"
			 )
	};

	/// <summary>
	/// Returns unique Setting[] array.
	/// </summary>
	/// <param name="Objects"></param>
	/// <returns></returns>
	internal static List<Setting> ConvertPolicyEditorSettingToSiPolicySetting(
		IEnumerable<AppControlManager.PolicyEditor.PolicySettings> Objects,
		string policyName,
		string? policyInfo)
	{
		List<Setting> output = [];
		HashSet<string> seenKeys = [];

		foreach (AppControlManager.PolicyEditor.PolicySettings item in Objects)
		{
			// To prevent duplicate Name and PolicyIDInfo Setting elements in the policy.
			if (string.Equals(item.Provider, "PolicyInfo", StringComparison.OrdinalIgnoreCase) &&
				string.Equals(item.Key, "Information", StringComparison.OrdinalIgnoreCase))
			{
				if (string.Equals(item.ValueName, "Id", StringComparison.OrdinalIgnoreCase) ||
					string.Equals(item.ValueName, "Name", StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}
			}

			// Create the actual SettingValueType to get the real value for comparison
			SettingValueType settingValue = SetValueType(item.Type, item.ValueStr);

			// Create a unique key based on all identifying properties including the actual value
			string uniqueKey = $"{item.Provider}|{item.Key}|{item.ValueName}|{GetValueString(settingValue)}|{item.Type}";

			if (seenKeys.Add(uniqueKey))
			{
				output.Add(new Setting(
					key: item.Key,
					value: settingValue,
					provider: item.Provider,
					valueName: item.ValueName
				));
			}
		}

		#region Always add these to the Settings list, used by the Policy Editor VM

		Setting newNameSetting = new(
			provider: "PolicyInfo",
			key: "Information",
			valueName: "Name",
			value: new SettingValueType(
				item: policyName
			)
		);

		output.Add(newNameSetting);

		if (policyInfo is not null)
		{
			Setting newPolicyInfoIDSetting = new(
				provider: "PolicyInfo",
				key: "Information",
				valueName: "Id",
				value: new SettingValueType(
					item: policyInfo
				)
			);

			output.Add(newPolicyInfoIDSetting);
		}

		#endregion

		return output;
	}

	private static string GetValueString(SettingValueType? settingValue)
	{
		if (settingValue?.Item is null)
			return "null";

		return settingValue.Item switch
		{
			byte[] bytes => Convert.ToHexString(bytes),
			bool boolean => boolean.ToString(),
			uint number => number.ToString(),
			string text => text,
			_ => settingValue.Item.ToString() ?? "null"
		};
	}

}

