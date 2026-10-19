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
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using CommonCore.GroupPolicy;
using HardenSystemSecurity.ViewModels;

namespace HardenSystemSecurity.Helpers;

/// <summary>
/// Factory for creating category processors. Used by the <see cref="Pages.Protect"/>.
/// </summary>
internal static class CategoryProcessorFactory
{
	/// <summary>
	/// Get the appropriate processor for a category.
	/// </summary>
	/// <param name="category">The category to get processor for</param>
	/// <returns>Category processor instance</returns>
	internal static ICategoryProcessor GetProcessor(Categories category) => category switch
	{
		Categories.MicrosoftSecurityBaseline => new MicrosoftSecurityBaselineProcessor(),
		Categories.MSFTSecBaselines_OptionalOverrides => new MUnitCategoryProcessor(Categories.MSFTSecBaselines_OptionalOverrides, "ProtectCategory_MSFTSecBaselineOverrides"),
		Categories.Microsoft365AppsSecurityBaseline => new Microsoft365AppsSecurityBaselineProcessor(),
		Categories.MicrosoftDefender => new MUnitCategoryProcessor(Categories.MicrosoftDefender, "ProtectCategory_MSFTDefender"),
		Categories.AttackSurfaceReductionRules => new AttackSurfaceReductionRulesProcessor(),
		Categories.BitLockerSettings => new MUnitCategoryProcessor(Categories.BitLockerSettings, "ProtectCategory_BitLocker"),
		Categories.TLSSecurity => new MUnitCategoryProcessor(Categories.TLSSecurity, "ProtectCategory_TLS"),
		Categories.LockScreen => new MUnitCategoryProcessor(Categories.LockScreen, "ProtectCategory_LockScreen"),
		Categories.UserAccountControl => new MUnitCategoryProcessor(Categories.UserAccountControl, "ProtectCategory_UAC"),
		Categories.DeviceGuard => new MUnitCategoryProcessor(Categories.DeviceGuard, "ProtectCategory_DeviceGuard"),
		Categories.WindowsFirewall => new MUnitCategoryProcessor(Categories.WindowsFirewall, "ProtectCategory_WindowsFirewall"),
		Categories.OptionalWindowsFeatures => new OptionalWindowsFeaturesProcessor(),
		Categories.WindowsNetworking => new MUnitCategoryProcessor(Categories.WindowsNetworking, "ProtectCategory_WindowsNetworking"),
		Categories.MiscellaneousConfigurations => new MUnitCategoryProcessor(Categories.MiscellaneousConfigurations, "ProtectCategory_MiscellaneousConfig"),
		Categories.WindowsUpdateConfigurations => new MUnitCategoryProcessor(Categories.WindowsUpdateConfigurations, "ProtectCategory_WindowsUpdate"),
		Categories.EdgeBrowserConfigurations => new MUnitCategoryProcessor(Categories.EdgeBrowserConfigurations, "ProtectCategory_Edge"),
		Categories.CertificateChecking => throw new InvalidOperationException("Certificate Checking must be interacted with manually."),
		Categories.CountryIPBlocking => new CountryIPBlockingProcessor(),
		Categories.NonAdminCommands => new MUnitCategoryProcessor(Categories.NonAdminCommands, "ProtectCategory_NonAdmin"),
		_ => throw new ArgumentException($"Unknown category: {category}", nameof(category))
	};

	/// <summary>
	/// Single source of truth for mapping MUnit-based categories to the ViewModels that own their MUnits.
	/// Only the ViewModel of the requested category is instantiated.
	/// </summary>
	/// <param name="category">The category to get the ViewModel for.</param>
	/// <returns>The ViewModel that manages the category, or null if the category is not MUnit-based.</returns>
	internal static IMUnitListViewModel? GetMUnitViewModel(Categories category) => category switch
	{
		Categories.MSFTSecBaselines_OptionalOverrides => ViewModelProvider.MicrosoftBaseLinesOverridesVM,
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
		_ => null
	};

	/// <summary>
	/// Helper to make sure in the ProtectVM's Intents and Presets flows:
	/// - <see cref="Categories.MicrosoftSecurityBaseline"/> runs first
	/// - <see cref="Categories.Microsoft365AppsSecurityBaseline"/> runs right after
	/// - <see cref="Categories.MSFTSecBaselines_OptionalOverrides"/> runs last
	/// Lower numbers run earlier; higher numbers run later.
	/// Default priority for all others is 0.
	/// Maintains deterministic ordering among the "first" group by using distinct negative priorities.
	/// </summary>
	internal static int GetExecutionPriority(Categories category) => category switch
	{
		Categories.MicrosoftSecurityBaseline => -1000,         // Apply first
		Categories.Microsoft365AppsSecurityBaseline => -900,   // Apply second
		Categories.MSFTSecBaselines_OptionalOverrides => 1000, // Apply last
		_ => 0                                                 // Default priority
	};

	#region Custom processor

	private sealed class MicrosoftSecurityBaselineProcessor : ICategoryProcessor
	{
		public Categories Category => Categories.MicrosoftSecurityBaseline;
		public string CategoryDisplayName => Atlas.GetStr("ProtectCategory_MSFTSecBaseline");

		public async Task ApplyAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null)
		{
			await ViewModelProvider.MicrosoftSecurityBaselineVM.ApplyInternal(selectedIntent);
		}

		public async Task RemoveAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null)
		{
			await ViewModelProvider.MicrosoftSecurityBaselineVM.RemoveInternal();
		}

		public async Task VerifyAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null)
		{
			await ViewModelProvider.MicrosoftSecurityBaselineVM.VerifyInternal();
		}
	}

	private sealed class Microsoft365AppsSecurityBaselineProcessor : ICategoryProcessor
	{
		public Categories Category => Categories.Microsoft365AppsSecurityBaseline;
		public string CategoryDisplayName => Atlas.GetStr("ProtectCategory_MSFT365AppsSecBaseline");

		public async Task ApplyAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null)
		{
			await ViewModelProvider.Microsoft365AppsSecurityBaselineVM.ApplyInternal();
		}

		public async Task RemoveAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null)
		{
			await ViewModelProvider.Microsoft365AppsSecurityBaselineVM.RemoveInternal();
		}

		public async Task VerifyAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null)
		{
			await ViewModelProvider.Microsoft365AppsSecurityBaselineVM.VerifyInternal();
		}
	}

	// These are the ViewModels that don't use MUnit and have custom logics.

	private sealed class OptionalWindowsFeaturesProcessor : ICategoryProcessor
	{
		public Categories Category => Categories.OptionalWindowsFeatures;
		public string CategoryDisplayName => Atlas.GetStr("ProtectCategory_OptionalWinFeatures");

		public async Task ApplyAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null)
		{
			// Ensure the ListView's collection is loaded first. Not strictly needed for the other method
			// But improves user experience.
			await ViewModelProvider.OptionalWindowsFeaturesVM.EnsureRecommendedItemsRetrievedAndGroupAsync();

			bool includeEnablements = selectedSubCategories?.Contains(SubCategories.OptionalWindowsFeatures_IncludeEnablements) ?? false;

			await ViewModelProvider.OptionalWindowsFeaturesVM.ApplySecurityHardening(includeEnablements);
		}

		public async Task RemoveAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null)
		{
			// Ensure the ListView's collection is loaded first. Not strictly needed for the other method
			// But improves user experience.
			await ViewModelProvider.OptionalWindowsFeaturesVM.EnsureRecommendedItemsRetrievedAndGroupAsync();

			bool includeEnablements = selectedSubCategories?.Contains(SubCategories.OptionalWindowsFeatures_IncludeEnablements) ?? false;

			await ViewModelProvider.OptionalWindowsFeaturesVM.RemoveSecurityHardening(includeEnablements);
		}

		public async Task VerifyAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null)
		{
			// Ensure the ListView's collection is loaded first. Not strictly needed for the other method
			// But improves user experience.
			await ViewModelProvider.OptionalWindowsFeaturesVM.EnsureRecommendedItemsRetrievedAndGroupAsync();
			_ = await ViewModelProvider.OptionalWindowsFeaturesVM.VerifySecurityHardening();
		}
	}

	private sealed class AttackSurfaceReductionRulesProcessor : ICategoryProcessor
	{
		public Categories Category => Categories.AttackSurfaceReductionRules;
		public string CategoryDisplayName => Atlas.GetStr("ProtectCategory_ASRRules");

		public async Task ApplyAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null)
		{
			CancellationToken token = cancellationToken ?? CancellationToken.None;

			// If no intent filter is provided, use the VM's built-in "Apply Recommended" flow.
			if (selectedIntent == null)
			{
				await ViewModelProvider.ASRVM.ApplyRecommendedCore();
				return;
			}

			// Intent-aware subset application:
			// - include Parent policy "ExploitGuard_ASR_Rules"
			// - include entries whose DeviceIntents contains Intent.All (when any selected)
			// - include entries intersecting with selected intents
			List<RegistryPolicyEntry> all = ViewModelProvider.ASRVM.ASRPolicyFromJSON;
			if (all.Count == 0)
			{
				return;
			}

			List<RegistryPolicyEntry> subset = new(capacity: all.Count);

			// Parent policy must always be included for apply
			foreach (RegistryPolicyEntry entry in CollectionsMarshal.AsSpan(all))
			{
				if (entry.ValueName != null &&
					entry.ValueName.Equals("ExploitGuard_ASR_Rules", StringComparison.OrdinalIgnoreCase))
				{
					subset.Add(entry);
					break;
				}
			}

			foreach (RegistryPolicyEntry entry in CollectionsMarshal.AsSpan(all))
			{
				// Skip parent (already added)
				if (entry.ValueName != null &&
					entry.ValueName.Equals("ExploitGuard_ASR_Rules", StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}

				// Require intents
				if (entry.DeviceIntents == null || entry.DeviceIntents.Count == 0)
				{
					continue;
				}

				// Include Intent.All when any selection exists
				if (entry.DeviceIntents.Any(di => di == Intent.All))
				{
					subset.Add(entry);
					continue;
				}

				// Include if intersects
				bool intersects = entry.DeviceIntents.Any(s => s == selectedIntent);
				if (intersects)
				{
					subset.Add(entry);
				}
			}

			if (subset.Count == 0)
			{
				return;
			}

			await Task.Run(() =>
			{
				RegistryPolicyParser.AddPoliciesToSystem(subset, GroupPolicyContext.Machine);
			}, token);
		}

		public async Task RemoveAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null)
		{
			CancellationToken token = cancellationToken ?? CancellationToken.None;

			// If no intent filter is provided, remove everything through the VM flow.
			if (selectedIntent == null)
			{
				await Task.Run(ViewModelProvider.ASRVM.RemoveAllRules, token);
				return;
			}

			List<RegistryPolicyEntry> all = ViewModelProvider.ASRVM.ASRPolicyFromJSON;
			if (all.Count == 0)
			{
				return;
			}

			// Build a subset of rules to remove, excluding the parent policy key.
			List<RegistryPolicyEntry> subset = new(capacity: all.Count);

			foreach (RegistryPolicyEntry entry in CollectionsMarshal.AsSpan(all))
			{
				// Skip parent (only remove rules subset)
				if (entry.ValueName != null &&
					entry.ValueName.Equals("ExploitGuard_ASR_Rules", StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}

				if (entry.DeviceIntents == null || entry.DeviceIntents.Count == 0)
				{
					continue;
				}

				if (entry.DeviceIntents.Any(di => di == Intent.All))
				{
					subset.Add(entry);
					continue;
				}

				bool intersects = entry.DeviceIntents.Any(s => s == selectedIntent);
				if (intersects)
				{
					subset.Add(entry);
				}
			}

			if (subset.Count == 0)
			{
				return;
			}

			await Task.Run(() =>
			{
				RegistryPolicyParser.RemovePoliciesFromSystem(subset, GroupPolicyContext.Machine);
			}, token);
		}

		public async Task VerifyAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null)
		{
			// For verification, reuse the VM's "retrieve latest" which updates the UI state.
			CancellationToken token = cancellationToken ?? CancellationToken.None;
			await Task.Run(ViewModelProvider.ASRVM.RetrieveLatest, token);
		}
	}

	private sealed class CountryIPBlockingProcessor : ICategoryProcessor
	{
		public Categories Category => Categories.CountryIPBlocking;
		public string CategoryDisplayName => Atlas.GetStr("ProtectCategory_CountryIPBlock");

		public async Task ApplyAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null)
		{
			await ViewModelProvider.CountryIPBlockingVM.AddSSOT();
		}

		public async Task RemoveAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null)
		{
			await ViewModelProvider.CountryIPBlockingVM.RemoveSSOT();
		}

		public async Task VerifyAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null)
		{
			// Will have to implement verification.
		}
	}

	#endregion
}
