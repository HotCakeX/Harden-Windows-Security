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
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.ViewModels;
using HardenSystemSecurity.GroupPolicy;
using HardenSystemSecurity.Traverse;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenSystemSecurity.ViewModels;

[JsonSourceGenerationOptions(
	PropertyNameCaseInsensitive = true,
	PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
	WriteIndented = true,
	NumberHandling = JsonNumberHandling.AllowReadingFromString
	)]
[JsonSerializable(typeof(string[]))]
[JsonSerializable(typeof(uint[]))]
internal sealed partial class PrimitiveJSONContext : JsonSerializerContext
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
	[JsonIgnore]
	internal RegistryPolicyEntry PolicyEntry => policyEntry;

	[JsonPropertyOrder(1)]
	[JsonInclude]
	internal ASRRuleState State
	{
		get; set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(StateIndex));
			}
		}
	} = ASRRuleState.NotConfigured;

	[JsonIgnore]
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

	[JsonIgnore]
	internal ASRVM ASRVMRef => asrVMRef;

	[JsonIgnore]
	internal Visibility HasURL => string.IsNullOrEmpty(PolicyEntry.URL) ? Visibility.Collapsed : Visibility.Visible;

	/// <summary>
	/// Used for JSON export only.
	/// </summary>
	[JsonInclude]
	[JsonPropertyOrder(0)]
	internal string? Name => PolicyEntry.FriendlyName;

	/// <summary>
	/// Used for JSON import/export only.
	/// </summary>
	[JsonInclude]
	[JsonPropertyOrder(2)]
	internal Guid ID => PolicyEntry.ID;

	/// <summary>
	/// JSON deserialization constructor.
	/// </summary>
	[JsonConstructor]
	internal ASRRuleEntry(Guid id, ASRRuleState state, string? name) : this(
			policyEntry: new(
				source: Source.Registry,
				keyName: string.Empty,
				valueName: string.Empty,
				type: RegistryValueType.REG_DWORD,
				size: 4,
				data: BitConverter.GetBytes((uint)state),
				hive: Hive.HKLM,
				id: id)
			{
				FriendlyName = name
			},
			asrVMRef: ViewModelProvider.ASRVM) => State = state;

	/// <summary>
	/// Apply this specific ASR rule, event handler for individual Apply buttons.
	/// </summary>
	internal void ApplyRule() => ASRVMRef.ApplyRule(this);
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

			// Initialize the state based on the current data in the policy entry.
			if (item.ParsedValue is not null)
			{
				uint currentValue = item.ParsedValue switch
				{
					string strValue when uint.TryParse(strValue, CultureInfo.InvariantCulture, out uint parsedUint) => parsedUint,
					uint uintValue => uintValue,
					_ => 0
				};

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
		string? idsJson = QuantumRelayHSS.Client.RunCommand(GlobalVars.ComManagerProcessPath, "get ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference AttackSurfaceReductionRules_Ids");

		if (string.IsNullOrEmpty(idsJson))
		{
			Logger.Write(GlobalVars.GetStr("FailedToRetrieveASRRuleIDs"));
			return output;
		}

		// Get ASR rule actions from the system
		string? actionsJson = QuantumRelayHSS.Client.RunCommand(GlobalVars.ComManagerProcessPath, "get ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference AttackSurfaceReductionRules_Actions");

		if (string.IsNullOrEmpty(actionsJson))
		{
			Logger.Write(GlobalVars.GetStr("FailedToRetrieveASRRuleActions"));
			return output;
		}

		// Parse the JSON data
		string[]? ids = JsonSerializer.Deserialize(idsJson, PrimitiveJSONContext.Default.StringArray);
		uint[]? actions = JsonSerializer.Deserialize(actionsJson, PrimitiveJSONContext.Default.UInt32Array);

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
				byte[] stateBytes = GetStateBytes(entry.PolicyEntry.Type, entry.State);

				// Copy of the policy entry with updated data
				RegistryPolicyEntry updatedEntry = new(
					source: entry.PolicyEntry.Source,
					keyName: entry.PolicyEntry.KeyName,
					valueName: entry.PolicyEntry.ValueName,
					type: entry.PolicyEntry.Type,
					size: (uint)stateBytes.Length,
					data: stateBytes,
					hive: entry.PolicyEntry.Hive,
					id: entry.PolicyEntry.ID)
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
					byte[] stateBytes = GetStateBytes(entry.PolicyEntry.Type, entry.State);

					// Create updated policy entry
					RegistryPolicyEntry updatedEntry = new(
						source: entry.PolicyEntry.Source,
						keyName: entry.PolicyEntry.KeyName,
						valueName: entry.PolicyEntry.ValueName,
						type: entry.PolicyEntry.Type,
						size: (uint)stateBytes.Length,
						data: stateBytes,
						hive: entry.PolicyEntry.Hive,
						id: entry.PolicyEntry.ID)
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
	/// Event handler for the UI.
	/// </summary>
	internal async void RetrieveLatest() => await RetrieveLatest_Internal();

	/// <summary>
	/// Retrieves all ASR rules states from the system and updates the UI to reflect current values.
	/// </summary>
	internal async Task RetrieveLatest_Internal()
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

		foreach (ASRRuleEntry item in CollectionsMarshal.AsSpan(filteredResults))
		{
			ASRItemsLVBound.Add(item);
		}
	}

	/// <summary>
	/// Exports the ASR rules to a JSON file
	/// </summary>
	internal async void ExportToJson_Click()
	{
		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			string? saveLocation = FileDialogHelper.ShowSaveFileDialog(GlobalVars.JSONPickerFilter, Generator.GetFileName());

			if (saveLocation is null)
				return;

			Traverse.AttackSurfaceReductionRules results = await GetTraverseData();

			await Task.Run(() =>
			{
				MContainer container = new(
				total: results.Count,
				compliant: results.Score,
				nonCompliant: results.Count - results.Score,
				attackSurfaceReductionRules: results
				);

				MContainerJsonContext.SerializeSingle(container, saveLocation);
			});

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyExportedASRRules"), AllASRRules.Count, saveLocation));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Used for <see cref="Traverse.MContainer"/> data retrieval.
	/// </summary>
	/// <returns></returns>
	internal async Task<Traverse.AttackSurfaceReductionRules> GetTraverseData()
	{
		await RetrieveLatest_Internal();

		return new(items: AllASRRules) { Score = AllASRRules.Count(x => x.State == ASRRuleState.Block) };
	}


	/// <summary>
	/// Applies imported ASR rule states by matching on GUID ID.
	/// Partial sync (synchronizeExact == false):
	///   - Apply only Block/Audit/Warn states.
	///   - Ignore NotConfigured (do not change existing system values).
	/// Full sync (synchronizeExact == true):
	///   - If ALL imported states are NotConfigured: remove all ASR policies (including parent) and set UI states to NotConfigured.
	///   - Otherwise: apply configured states (Block/Audit/Warn) and explicitly write 0 for NotConfigured rules.
	/// The method updates UI state (State) for each matched runtime rule.
	/// </summary>
	/// <param name="imported">Imported rule entries (deserialized) containing ID, State, Name.</param>
	/// <param name="synchronizeExact">True for full synchronization, false for apply-only.</param>
	/// <param name="cancellationToken">Cancellation token.</param>
	internal async Task ApplyImportedStates(List<ASRRuleEntry> imported, bool synchronizeExact, CancellationToken cancellationToken)
	{
		try
		{
			ElementsAreEnabled = false;

			int appliedCount = 0;
			int resetCount = 0;

			// Build runtime map (ID -> ASRRuleEntry) for fast lookup.
			Dictionary<Guid, ASRRuleEntry> runtimeById = new(AllASRRules.Count);
			foreach (ASRRuleEntry runtimeEntry in AllASRRules)
			{
				runtimeById[runtimeEntry.PolicyEntry.ID] = runtimeEntry;
			}

			// Determine if all imported states are NotConfigured (full removal scenario in full sync).
			bool allNotConfigured = true;
			foreach (ASRRuleEntry importedEntry in imported)
			{
				if (importedEntry.State is not ASRRuleState.NotConfigured)
				{
					allNotConfigured = false;
					break;
				}
			}

			// If full sync is used and all imported are NotConfigured, remove all ASR policies, including the parent.
			if (synchronizeExact && allNotConfigured)
			{
				await Task.Run(() =>
				{
					RegistryPolicyParser.RemovePoliciesFromSystem(ASRPolicyFromJSON, GroupPolicyContext.Machine);
				}, cancellationToken);

				_ = Dispatcher.TryEnqueue(() =>
				{
					// Set UI states to NotConfigured.
					foreach (ASRRuleEntry runtimeEntry in AllASRRules)
					{
						runtimeEntry.State = ASRRuleState.NotConfigured;
					}
				});

				MainInfoBar.WriteSuccess("Imported ASR rules: all NotConfigured -> removed all rules.");
				return;
			}

			await Task.Run(() =>
			{
				List<RegistryPolicyEntry> batch = new(imported.Count + 1);
				bool parentNeeded = false;

				foreach (ASRRuleEntry importedEntry in imported)
				{
					cancellationToken.ThrowIfCancellationRequested();

					ASRRuleState desiredState = importedEntry.State;
					ASRRuleEntry runtimeEntry = runtimeById[importedEntry.ID];
					RegistryPolicyEntry runtimePolicy = runtimeEntry.PolicyEntry;

					// Partial sync ignores NotConfigured.
					if (desiredState is ASRRuleState.NotConfigured && !synchronizeExact)
						continue;

					// Build the bytes according to the runtime registry type.
					byte[] stateBytes = GetStateBytes(runtimePolicy.Type, desiredState);

					RegistryPolicyEntry updatedEntry = new(
						source: runtimePolicy.Source,
						keyName: runtimePolicy.KeyName,
						valueName: runtimePolicy.ValueName,
						type: runtimePolicy.Type,
						size: (uint)stateBytes.Length,
						data: stateBytes,
						hive: runtimePolicy.Hive,
						id: runtimePolicy.ID)
					{
						RegValue = ((uint)desiredState).ToString(),
						policyAction = runtimePolicy.policyAction,
						FriendlyName = runtimePolicy.FriendlyName,
						URL = runtimePolicy.URL,
						Category = runtimePolicy.Category,
						SubCategory = runtimePolicy.SubCategory
					};

					batch.Add(updatedEntry);

					if (desiredState != ASRRuleState.NotConfigured)
					{
						appliedCount++;
						parentNeeded = true;
						_ = Dispatcher.TryEnqueue(() =>
						{
							runtimeEntry.State = desiredState;
						});
					}
					else
					{
						// Full sync explicit reset.
						resetCount++;
						_ = Dispatcher.TryEnqueue(() =>
						{
							runtimeEntry.State = ASRRuleState.NotConfigured;
						});
					}
				}

				// Include parent only if at least one rule is configured (Block/Audit/Warn).
				if (parentNeeded)
				{
					batch.Add(ParentPolicy!);
				}

				if (batch.Count > 0)
				{
					RegistryPolicyParser.AddPoliciesToSystem(batch, GroupPolicyContext.Machine);
				}

			}, cancellationToken);

			MainInfoBar.WriteSuccess($"Imported ASR rules applied. Applied={appliedCount}, Reset={resetCount}.");
		}
		catch (OperationCanceledException)
		{
			MainInfoBar.WriteError(new OperationCanceledException("ASR import canceled."));
			throw;
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
			throw;
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	private static byte[] GetStateBytes(RegistryValueType type, ASRRuleState state) => type switch
	{
		RegistryValueType.REG_DWORD => BitConverter.GetBytes((uint)state),
		RegistryValueType.REG_SZ => Encoding.Unicode.GetBytes(((uint)state).ToString() + "\0"),
		_ => BitConverter.GetBytes((uint)state),
	};

}
