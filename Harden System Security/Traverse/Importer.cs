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
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;
using HardenSystemSecurity.ViewModels;

namespace HardenSystemSecurity.Traverse;

internal static class Importer
{
	/// <summary>
	/// Import a <see cref="MContainer"/> JSON file and apply it on the system.
	/// </summary>
	/// <param name="filePath">Path to the exported JSON report.</param>
	/// <param name="synchronizeExact">
	/// If true: apply all MUnits marked applied in the file and remove all MUnits present in the file marked not applied.
	/// If false: only apply items that are marked applied, ignore removals.
	/// </param>
	/// <param name="cancellationToken">Cancellation token.</param>
	/// <exception cref="InvalidOperationException">Thrown when deserialization fails or file content is invalid.</exception>
	internal static async Task ImportAndApplyAsync(
		string filePath,
		bool synchronizeExact,
		CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();

		await Task.Run(async () =>
		{

			string json = await File.ReadAllTextAsync(filePath, cancellationToken);

			cancellationToken.ThrowIfCancellationRequested();

			MContainer container = MContainerJsonContext.DeserializeSingle(json) ?? throw new InvalidOperationException("Failed to deserialize the Traverse report into an MContainer instance.");

			Logger.Write($"Importing system state from '{filePath}' (mode={(synchronizeExact ? "full" : "partial")})...");

			// Accumulators for bulk operations.
			Dictionary<Categories, List<MUnit>> applyByCategory = new(capacity: 32);
			Dictionary<Categories, List<MUnit>> removeByCategory = synchronizeExact
				? new(capacity: 32) : new(capacity: 0);

			int totalMeasuresToApply = 0;
			int totalMeasuresToRemove = 0;

			// Microsoft Security Baseline import
			if (container.MicrosoftSecurityBaseline?.Items.Count > 0)
			{
				Logger.Write($"Importing Microsoft Security Baseline ({container.MicrosoftSecurityBaseline.Items.Count})...");

				await ViewModelProvider.MicrosoftSecurityBaselineVM.ApplyImportedStates(container.MicrosoftSecurityBaseline.Items, synchronizeExact, cancellationToken);

				Logger.Write("Finished importing Microsoft Security Baseline.");
			}

			// Microsoft 365 Apps Security Baseline import
			if (container.Microsoft365AppsSecurityBaseline?.Items.Count > 0)
			{
				Logger.Write($"Importing Microsoft 365 Apps Security Baseline ({container.Microsoft365AppsSecurityBaseline.Items.Count})...");

				await ViewModelProvider.Microsoft365AppsSecurityBaselineVM.ApplyImportedStates(container.Microsoft365AppsSecurityBaseline.Items, synchronizeExact, cancellationToken);

				Logger.Write("Finished importing Microsoft 365 Apps Security Baseline.");
			}

			// ASR rules import section
			if (container.AttackSurfaceReductionRules?.Items.Count > 0)
			{
				Logger.Write($"Importing Attack Surface Reduction Rules ({container.AttackSurfaceReductionRules.Items.Count})...");

				await ViewModelProvider.ASRVM.ApplyImportedStates(container.AttackSurfaceReductionRules.Items, synchronizeExact, cancellationToken);

				Logger.Write("Finished importing Attack Surface Reduction Rules.");
			}

			// Collect from each MUnit-based category. Non-MUnit categories are ignored here.
			CollectCategory(container.MicrosoftDefender?.Items, applyByCategory, removeByCategory, synchronizeExact, ref totalMeasuresToApply, ref totalMeasuresToRemove);
			CollectCategory(container.BitLockerSettings?.Items, applyByCategory, removeByCategory, synchronizeExact, ref totalMeasuresToApply, ref totalMeasuresToRemove);
			CollectCategory(container.TLSSecurity?.Items, applyByCategory, removeByCategory, synchronizeExact, ref totalMeasuresToApply, ref totalMeasuresToRemove);
			CollectCategory(container.LockScreen?.Items, applyByCategory, removeByCategory, synchronizeExact, ref totalMeasuresToApply, ref totalMeasuresToRemove);
			CollectCategory(container.UserAccountControl?.Items, applyByCategory, removeByCategory, synchronizeExact, ref totalMeasuresToApply, ref totalMeasuresToRemove);
			CollectCategory(container.DeviceGuard?.Items, applyByCategory, removeByCategory, synchronizeExact, ref totalMeasuresToApply, ref totalMeasuresToRemove);
			CollectCategory(container.WindowsFirewall?.Items, applyByCategory, removeByCategory, synchronizeExact, ref totalMeasuresToApply, ref totalMeasuresToRemove);
			CollectCategory(container.WindowsNetworking?.Items, applyByCategory, removeByCategory, synchronizeExact, ref totalMeasuresToApply, ref totalMeasuresToRemove);
			CollectCategory(container.MiscellaneousConfigurations?.Items, applyByCategory, removeByCategory, synchronizeExact, ref totalMeasuresToApply, ref totalMeasuresToRemove);
			CollectCategory(container.WindowsUpdateConfigurations?.Items, applyByCategory, removeByCategory, synchronizeExact, ref totalMeasuresToApply, ref totalMeasuresToRemove);
			CollectCategory(container.EdgeBrowserConfigurations?.Items, applyByCategory, removeByCategory, synchronizeExact, ref totalMeasuresToApply, ref totalMeasuresToRemove);
			CollectCategory(container.NonAdminCommands?.Items, applyByCategory, removeByCategory, synchronizeExact, ref totalMeasuresToApply, ref totalMeasuresToRemove);
			CollectCategory(container.MSFTSecBaselines_OptionalOverrides?.Items, applyByCategory, removeByCategory, synchronizeExact, ref totalMeasuresToApply, ref totalMeasuresToRemove);

			// Early exit if there is nothing else (MUnits) to do.
			if (applyByCategory.Count == 0 && removeByCategory.Count == 0)
				return;

			Logger.Write(string.Format(
				GlobalVars.GetStr("ImportOperationBeginApplyCountMsg"),
				applyByCategory.Count, totalMeasuresToApply)
				);

			// Intra-Category Conflict Resolution
			// We need to track which registry keys are being targeted to prevent double-writes (conflicts) within the same category or across categories.
			HashSet<string> targetedRegistryKeys = new(StringComparer.OrdinalIgnoreCase);

			// Sort categories by execution priority
			List<KeyValuePair<Categories, List<MUnit>>> sortedApplyCategories = [.. applyByCategory.OrderBy(kv => CategoryProcessorFactory.GetExecutionPriority(kv.Key))];

			// Apply phase: Sort keys by priority in ascending order to match the Factory logic.
			foreach (KeyValuePair<Categories, List<MUnit>> kvp in sortedApplyCategories)
			{
				cancellationToken.ThrowIfCancellationRequested();

				List<MUnit> finalApplyList = new(kvp.Value.Count);

				foreach (MUnit mUnit in CollectionsMarshal.AsSpan(kvp.Value))
				{
					// If it's a JSON-based policy, we check for conflicts
					if (mUnit.JsonPolicyId != null)
					{
						// If we haven't targeted this key yet, add it.
						if (targetedRegistryKeys.Add(mUnit.JsonPolicyId))
						{
							finalApplyList.Add(mUnit);
						}
						else
						{
							// This key was already claimed by a higher priority category or
							// an earlier item in this same list.
							// Since this logic processes "Applies" (true), the first one wins.
							Logger.Write($"Skipping duplicate apply target during import: {mUnit.JsonPolicyId}");
						}
					}
					else
					{
						// Non-JSON based MUnits don't conflict via Registry Key ID
						finalApplyList.Add(mUnit);
					}
				}

				if (finalApplyList.Count == 0)
					continue;

				IMUnitListViewModel viewModel = ResolveViewModel(kvp.Key);

				Logger.Write(string.Format(
					GlobalVars.GetStr("ImportOperationIndividualApplyOperationMsg"),
					finalApplyList.Count, kvp.Key)
					);

				await MUnit.ProcessMUnitsWithBulkOperations(
					viewModel,
					finalApplyList,
					MUnitOperation.Apply,
					cancellationToken);
			}

			// Remove phase only if synchronizeExact requested.
			if (synchronizeExact)
			{
				Logger.Write(string.Format(
					GlobalVars.GetStr("ImportOperationBeginRemoveCountMsg"),
					removeByCategory.Count, totalMeasuresToRemove)
					);

				List<KeyValuePair<Categories, List<MUnit>>> sortedRemoveCategories = [.. removeByCategory.OrderBy(kv => CategoryProcessorFactory.GetExecutionPriority(kv.Key))];

				foreach (KeyValuePair<Categories, List<MUnit>> kvp in sortedRemoveCategories)
				{
					cancellationToken.ThrowIfCancellationRequested();

					List<MUnit> finalRemoveList = new(kvp.Value.Count);

					foreach (MUnit mUnit in CollectionsMarshal.AsSpan(kvp.Value))
					{
						if (mUnit.JsonPolicyId != null)
						{
							// If we are about to Remove a policy (set to default/delete), we obviously must ensure
							// that we didn't just Apply it in the loop above.
							if (targetedRegistryKeys.Contains(mUnit.JsonPolicyId))
							{
								// This key was targeted for Application. Do Not remove it.
								continue;
							}

							finalRemoveList.Add(mUnit);
						}
						else
						{
							finalRemoveList.Add(mUnit);
						}
					}

					if (finalRemoveList.Count == 0)
						continue;

					IMUnitListViewModel viewModel = ResolveViewModel(kvp.Key);

					Logger.Write(string.Format(
						GlobalVars.GetStr("ImportOperationIndividualRemoveOperationMsg"),
						finalRemoveList.Count, kvp.Key)
						);

					await MUnit.ProcessMUnitsWithBulkOperations(
						viewModel,
						finalRemoveList,
						MUnitOperation.Remove,
						cancellationToken);
				}
			}

		}, cancellationToken);

		if (Logger.CliRequested)
			Logger.Write(GlobalVars.GetStr("SystemStateRestorationFinishedMsg"));
	}

	/// <summary>
	/// Collect both apply and (optional) remove candidates from one category's imported items.
	/// </summary>
	private static void CollectCategory(
		IEnumerable<MUnit>? importedItems,
		Dictionary<Categories, List<MUnit>> applyAccumulator,
		Dictionary<Categories, List<MUnit>> removeAccumulator,
		bool synchronizeExact,
		ref int totalMeasuresToApply,
		ref int totalMeasuresToRemove)
	{
		if (importedItems == null)
			return;

		foreach (MUnit imported in importedItems)
		{
			// Try to match by ID
			if (!MUnitCatalog.All.TryGetValue(imported.ID, out MUnit? runtimeMUnit))
				continue; // Unknown or outdated item, skip.

			// Apply logic: Imported IsApplied == true
			if (imported.IsApplied == true)
			{
				ref List<MUnit>? applyListRef = ref CollectionsMarshal.GetValueRefOrAddDefault(applyAccumulator, runtimeMUnit.Category, out _);
				applyListRef ??= new(64);
				applyListRef.Add(runtimeMUnit);
				totalMeasuresToApply++;
			}

			// Remove logic (only when synchronizeExact == true):
			// Imported IsApplied != true (false or null treated as not applied)
			if (synchronizeExact && imported.IsApplied != true)
			{
				ref List<MUnit>? removeListRef = ref CollectionsMarshal.GetValueRefOrAddDefault(removeAccumulator, runtimeMUnit.Category, out _);
				removeListRef ??= new(64);
				removeListRef.Add(runtimeMUnit);
				totalMeasuresToRemove++;
			}
		}
	}

	/// <summary>
	/// Resolves the appropriate IMUnitListViewModel for a given category.
	/// </summary>
	/// <param name="category">The MUnit category.</param>
	/// <returns>The ViewModel that manages that category.</returns>
	/// <exception cref="InvalidOperationException">If the category is not MUnit based or unsupported here.</exception>
	private static IMUnitListViewModel ResolveViewModel(Categories category)
	{
		return category switch
		{
			Categories.MicrosoftDefender => ViewModelProvider.MicrosoftDefenderVM,
			Categories.BitLockerSettings => ViewModelProvider.BitLockerVM,
			Categories.TLSSecurity => ViewModelProvider.TLSVM,
			Categories.LockScreen => ViewModelProvider.LockScreenVM,
			Categories.UserAccountControl => ViewModelProvider.UACVM,
			Categories.DeviceGuard => ViewModelProvider.DeviceGuardVM,
			Categories.WindowsFirewall => ViewModelProvider.WindowsFirewallVM,
			Categories.WindowsNetworking => ViewModelProvider.WindowsNetworkingVM,
			Categories.MiscellaneousConfigurations => ViewModelProvider.MiscellaneousConfigsVM,
			Categories.WindowsUpdateConfigurations => ViewModelProvider.WindowsUpdateVM,
			Categories.EdgeBrowserConfigurations => ViewModelProvider.EdgeVM,
			Categories.NonAdminCommands => ViewModelProvider.NonAdminVM,
			Categories.MSFTSecBaselines_OptionalOverrides => ViewModelProvider.MicrosoftBaseLinesOverridesVM,
			_ => throw new InvalidOperationException($"Category '{category}' is not supported for MUnit import/apply workflow.")
		};
	}
}
