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
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using AppControlManager.ViewModels;
using HardenSystemSecurity.GroupPolicy;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenSystemSecurity.ViewModels;

[JsonSourceGenerationOptions(
	PropertyNameCaseInsensitive = true,
	PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
	WriteIndented = true,
	NumberHandling = JsonNumberHandling.AllowReadingFromString)]
[JsonSerializable(typeof(string[]))]
[JsonSerializable(typeof(uint[]))]
internal sealed partial class ASRArrayJsonContext : JsonSerializerContext
{
}

// https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference#asr-rule-modes
internal enum ASRRuleState : uint
{
	NotConfigured = 0,
	Block = 1,
	Audit = 2,
	Warn = 6
}

internal sealed partial class ASRRuleEntry(RegistryPolicyEntry policyEntry, ASRVM asrVMRef) : ViewModelBase
{
	internal RegistryPolicyEntry PolicyEntry => policyEntry;

	internal ASRRuleState State
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(StateIndex));
			}
		}
	} = ASRRuleState.NotConfigured;

	internal int StateIndex
	{
		get => State switch
		{
			ASRRuleState.NotConfigured => 0,
			ASRRuleState.Block => 1,
			ASRRuleState.Audit => 2,
			ASRRuleState.Warn => 3,
			_ => 0
		};
		set
		{
			ASRRuleState newState = value switch
			{
				0 => ASRRuleState.NotConfigured,
				1 => ASRRuleState.Block,
				2 => ASRRuleState.Audit,
				3 => ASRRuleState.Warn,
				_ => ASRRuleState.NotConfigured
			};

			State = newState;
		}
	}

	internal ASRVM ASRVMRef => asrVMRef;

	internal Visibility HasURL => string.IsNullOrEmpty(PolicyEntry.URL) ? Visibility.Collapsed : Visibility.Visible;

	/// <summary>
	/// Apply this specific ASR rule, event handler for individual Apply buttons.
	/// </summary>
	internal void ApplyRule()
	{
		ASRVMRef.ApplyRule(this);
	}
}

internal sealed partial class ASRVM : ViewModelBase
{
	internal ASRVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		CreateJSONData();
	}

	/// <summary>
	/// The main InfoBar for this VM.
	/// </summary>
	internal readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	internal Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal List<RegistryPolicyEntry> ASRPolicyFromJSON { get; set; } = [];

	internal ObservableCollection<ASRRuleEntry> ASRItemsLVBound = [];

	internal bool ElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ProgressBarVisibility = field ? Visibility.Collapsed : Visibility.Visible;
			}
		}
	} = true;

	internal static readonly string JSONConfigPath = Path.Combine(AppContext.BaseDirectory, "Resources", "AttackSurfaceReductionRules.json");

	/// <summary>
	/// The parent policy that must be always applied when any rule or all rules are being applied and must be removed if all rules are going to be removed and set to NotConfigured.
	/// </summary>
	private static RegistryPolicyEntry? ParentPolicy { get; set; }

	/// <summary>
	/// Create the initial <see cref="ASRRuleEntry"/> data from the JSON file.
	/// </summary>
	private void CreateJSONData()
	{
		ASRPolicyFromJSON = RegistryPolicyEntry.LoadWithFriendlyNameKeyResolve(JSONConfigPath);

		foreach (RegistryPolicyEntry item in ASRPolicyFromJSON)
		{
			// This is a policy that shouldn't be displayed on the UI but always has to be enabled when any other policy is being applied.
			if (string.Equals(item.ValueName, "ExploitGuard_ASR_Rules", StringComparison.OrdinalIgnoreCase))
			{
				ParentPolicy = item;
				continue;
			}

			ASRRuleEntry entry = new(
				policyEntry: item,
				asrVMRef: this);

			// Initialize the state based on the current data in the policy entry
			if (item.Data.Length >= 4)
			{
				uint currentValue = BitConverter.ToUInt32(item.Data.Span);
				entry.State = currentValue switch
				{
					0 => ASRRuleState.NotConfigured,
					1 => ASRRuleState.Block,
					2 => ASRRuleState.Audit,
					6 => ASRRuleState.Warn,
					_ => ASRRuleState.NotConfigured
				};
			}

			ASRItemsLVBound.Add(entry);
			AllASRRules.Add(entry);
		}
	}

	/// <summary>
	/// Retrieves the current ASR rules states from the system
	/// </summary>
	private Dictionary<string, ASRRuleState> RetrieveSystemStates()
	{
		Dictionary<string, ASRRuleState> output = [];

		// Get ASR rule IDs from the system
		string? idsJson = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "get ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference AttackSurfaceReductionRules_Ids");

		if (string.IsNullOrEmpty(idsJson))
		{
			Logger.Write(GlobalVars.GetStr("FailedToRetrieveASRRuleIDs"));
			return output;
		}

		// Get ASR rule actions from the system
		string? actionsJson = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "get ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference AttackSurfaceReductionRules_Actions");

		if (string.IsNullOrEmpty(actionsJson))
		{
			Logger.Write(GlobalVars.GetStr("FailedToRetrieveASRRuleActions"));
			return output;
		}

		// Parse the JSON data
		string[]? ids = JsonSerializer.Deserialize(idsJson, ASRArrayJsonContext.Default.StringArray);
		uint[]? actions = JsonSerializer.Deserialize(actionsJson, ASRArrayJsonContext.Default.UInt32Array);

		if (ids == null || actions == null)
		{
			Logger.Write(GlobalVars.GetStr("FailedToParseASRRulesData"));
			return output;
		}

		if (ids.Length != actions.Length)
		{
			Logger.Write(string.Format(GlobalVars.GetStr("MismatchBetweenIDsAndActionsCount"), ids.Length, actions.Length));
			return output;
		}

		for (int i = 0; i < ids.Length; i++)
		{
			string id = ids[i].ToLowerInvariant();
			uint action = actions[i];

			ASRRuleState state = action switch
			{
				0 => ASRRuleState.NotConfigured,
				1 => ASRRuleState.Block,
				2 => ASRRuleState.Audit,
				6 => ASRRuleState.Warn,
				_ => ASRRuleState.NotConfigured
			};

			output[id] = state;
		}

		Logger.Write(string.Format(GlobalVars.GetStr("SuccessfullyRetrievedASRRuleStates"), output.Count));

		return output;
	}

	/// <summary>
	/// Apply a single ASR rule, event handler for individual Apply buttons.
	/// </summary>
	/// <param name="entry">The ASR rule entry to apply</param>
	internal async void ApplyRule(ASRRuleEntry entry)
	{
		try
		{
			ElementsAreEnabled = false;

			await Task.Run(() =>
			{

				// Convert the state value to appropriate byte array based on registry type
				byte[] stateBytes = entry.PolicyEntry.Type switch
				{
					RegistryValueType.REG_DWORD => BitConverter.GetBytes((uint)entry.State),
					RegistryValueType.REG_SZ => System.Text.Encoding.Unicode.GetBytes(((uint)entry.State).ToString() + "\0"),
					_ => BitConverter.GetBytes((uint)entry.State)
				};

				// Copy of the policy entry with updated data
				RegistryPolicyEntry updatedEntry = new(
					source: entry.PolicyEntry.Source,
					keyName: entry.PolicyEntry.KeyName,
					valueName: entry.PolicyEntry.ValueName,
					type: entry.PolicyEntry.Type,
					size: (uint)stateBytes.Length,
					data: stateBytes,
					hive: entry.PolicyEntry.Hive)
				{
					RegValue = ((uint)entry.State).ToString(),
					policyAction = entry.PolicyEntry.policyAction,
					FriendlyName = entry.PolicyEntry.FriendlyName,
					URL = entry.PolicyEntry.URL,
					Category = entry.PolicyEntry.Category,
					SubCategory = entry.PolicyEntry.SubCategory
				};

				// Also need to ensure the main ASR policy is enabled
				List<RegistryPolicyEntry> policiesToApply = [updatedEntry, ParentPolicy!];

				// Apply the policies to the system
				RegistryPolicyParser.AddPoliciesToSystem(policiesToApply, GroupPolicyContext.Machine);

			});

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("AppliedASRRuleWithState"), entry.PolicyEntry.FriendlyName, entry.State));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Event handler for the ApplyAll button
	/// </summary>
	internal async void ApplyAllRules()
	{
		try
		{
			ElementsAreEnabled = false;

			await Task.Run(() =>
			{

				List<RegistryPolicyEntry> policiesToApply = [ParentPolicy!];

				foreach (ASRRuleEntry entry in ASRItemsLVBound)
				{
					// Convert the state value to appropriate byte array based on registry type
					byte[] stateBytes = entry.PolicyEntry.Type switch
					{
						RegistryValueType.REG_DWORD => BitConverter.GetBytes((uint)entry.State),
						RegistryValueType.REG_SZ => System.Text.Encoding.Unicode.GetBytes(((uint)entry.State).ToString() + "\0"),
						_ => BitConverter.GetBytes((uint)entry.State)
					};

					// Create updated policy entry
					RegistryPolicyEntry updatedEntry = new(
						source: entry.PolicyEntry.Source,
						keyName: entry.PolicyEntry.KeyName,
						valueName: entry.PolicyEntry.ValueName,
						type: entry.PolicyEntry.Type,
						size: (uint)stateBytes.Length,
						data: stateBytes,
						hive: entry.PolicyEntry.Hive)
					{
						RegValue = ((uint)entry.State).ToString(),
						policyAction = entry.PolicyEntry.policyAction,
						FriendlyName = entry.PolicyEntry.FriendlyName,
						URL = entry.PolicyEntry.URL,
						Category = entry.PolicyEntry.Category,
						SubCategory = entry.PolicyEntry.SubCategory
					};

					policiesToApply.Add(updatedEntry);
				}

				RegistryPolicyParser.AddPoliciesToSystem(policiesToApply, GroupPolicyContext.Machine);

			});

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("AppliedASRRulesSuccessfully"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Event handler for the RemoveAll button.
	/// </summary>
	internal async void RemoveAllRules()
	{
		try
		{
			ElementsAreEnabled = false;

			await Task.Run(() => RegistryPolicyParser.RemovePoliciesFromSystem(ASRPolicyFromJSON, GroupPolicyContext.Machine));

			// Reset all UI states to NotConfigured
			foreach (ASRRuleEntry entry in ASRItemsLVBound)
			{
				entry.State = ASRRuleState.NotConfigured;
			}

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("RemovedASRRulesSuccessfully"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Retrieves all ASR rules states from the system and updates the UI to reflect current values.
	/// </summary>
	internal async void RetrieveLatest()
	{
		try
		{
			ElementsAreEnabled = false;

			// Retrieve system states on background thread
			Dictionary<string, ASRRuleState> results = await Task.Run(RetrieveSystemStates);

			int updatedRules = 0;

			// Update UI states based on system values
			foreach (ASRRuleEntry entry in ASRItemsLVBound)
			{
				string ruleId = entry.PolicyEntry.ValueName.ToLowerInvariant();

				if (results.TryGetValue(ruleId, out ASRRuleState systemState))
				{
					entry.State = systemState;
					updatedRules++;
				}
				else
				{
					// Rule not found in system, set to NotConfigured
					entry.State = ASRRuleState.NotConfigured;
				}
			}

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("RetrievedSystemStatesAndUpdatedASRRules"), updatedRules));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("FailedToVerifyASRRules"));
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Bound to the UI for button event handler.
	/// </summary>
	internal async void ApplyRecommended() => await ApplyRecommendedCore();

	/// <summary>
	/// To Apply Recommended configurations for the ASR Rules.
	/// </summary>
	internal async Task ApplyRecommendedCore()
	{
		try
		{
			ElementsAreEnabled = false;

			await Task.Run(() =>
			{
				RegistryPolicyParser.AddPoliciesToSystem(ASRPolicyFromJSON, GroupPolicyContext.Machine);
			});

			// Update UI to reflect the recommended states
			foreach (ASRRuleEntry entry in ASRItemsLVBound)
			{
				if (entry.PolicyEntry.ParsedValue is not null)
				{
					uint recommendedValue = entry.PolicyEntry.ParsedValue switch
					{
						// ASR values are stored as strings in JSON and have Type 1 so they are not int by default. This is how Group policy and system stores their information.
						string strValue when uint.TryParse(strValue, CultureInfo.InvariantCulture, out uint parsedUint) => parsedUint,
						uint uintValue => uintValue,
						_ => 0
					};

					entry.State = recommendedValue switch
					{
						0 => ASRRuleState.NotConfigured,
						1 => ASRRuleState.Block,
						2 => ASRRuleState.Audit,
						6 => ASRRuleState.Warn,
						_ => ASRRuleState.NotConfigured
					};
				}
			}

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("SuccessfullyAppliedRecommendedValuesASRRules"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Search box for the ASR rules.
	/// </summary>
	internal string? SearchKeyword
	{
		get; set
		{
			if (SPT(ref field, value))
				SearchBox_TextChanged();
		}
	}

	/// <summary>
	/// Backing field for all ASR rules to preserve original data during filtering.
	/// </summary>
	internal readonly List<ASRRuleEntry> AllASRRules = [];

	/// <summary>
	/// Event handler for the SearchBox text change
	/// </summary>
	internal void SearchBox_TextChanged()
	{
		string? searchTerm = SearchKeyword?.Trim();

		if (searchTerm is null)
			return;

		// Perform a case-insensitive search in all relevant fields
		List<ASRRuleEntry> filteredResults = AllASRRules.Where(rule =>
			(rule.PolicyEntry.FriendlyName is not null && rule.PolicyEntry.FriendlyName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(rule.PolicyEntry.ValueName is not null && rule.PolicyEntry.ValueName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(rule.PolicyEntry.Category is not null && rule.PolicyEntry.Category.ToString()?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) == true) ||
			(rule.PolicyEntry.SubCategory is not null && rule.PolicyEntry.SubCategory.ToString()?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) == true) ||
			rule.State.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)
		).ToList();

		ASRItemsLVBound.Clear();

		foreach (ASRRuleEntry item in filteredResults)
		{
			ASRItemsLVBound.Add(item);
		}
	}
}
