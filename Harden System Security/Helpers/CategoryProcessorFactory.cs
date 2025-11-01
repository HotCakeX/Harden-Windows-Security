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
using System.Threading;
using System.Threading.Tasks;
using HardenSystemSecurity.DeviceIntents;
using HardenSystemSecurity.GroupPolicy;
using HardenSystemSecurity.Protect;
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
	internal static ICategoryProcessor GetProcessor(Categories category)
	{
		return category switch
		{
			Categories.MicrosoftSecurityBaseline => new MicrosoftSecurityBaselineProcessor(),
			Categories.MSFTSecBaselines_OptionalOverrides => new MicrosoftSecurityBaselineOverridesProcessor(),
			Categories.Microsoft365AppsSecurityBaseline => new Microsoft365AppsSecurityBaselineProcessor(),
			Categories.MicrosoftDefender => new MicrosoftDefenderProcessor(),
			Categories.AttackSurfaceReductionRules => new AttackSurfaceReductionRulesProcessor(),
			Categories.BitLockerSettings => new BitLockerSettingsProcessor(),
			Categories.TLSSecurity => new TLSSecurityProcessor(),
			Categories.LockScreen => new LockScreenProcessor(),
			Categories.UserAccountControl => new UserAccountControlProcessor(),
			Categories.DeviceGuard => new DeviceGuardProcessor(),
			Categories.WindowsFirewall => new WindowsFirewallProcessor(),
			Categories.OptionalWindowsFeatures => new OptionalWindowsFeaturesProcessor(),
			Categories.WindowsNetworking => new WindowsNetworkingProcessor(),
			Categories.MiscellaneousConfigurations => new MiscellaneousConfigurationsProcessor(),
			Categories.WindowsUpdateConfigurations => new WindowsUpdateConfigurationsProcessor(),
			Categories.EdgeBrowserConfigurations => new EdgeBrowserConfigurationsProcessor(),
			Categories.CertificateChecking => throw new InvalidOperationException("Certificate Checking must be interacted with manually."),
			Categories.CountryIPBlocking => new CountryIPBlockingProcessor(),
			Categories.NonAdminCommands => new NonAdminCommandsProcessor(),
			_ => throw new ArgumentException($"Unknown category: {category}", nameof(category))
		};
	}

	/// <summary>
	/// Helper to make sure in the ProtectVM's Intents and Presets flows:
	/// - <see cref="Categories.MicrosoftSecurityBaseline"/> runs first
	/// - <see cref="Categories.Microsoft365AppsSecurityBaseline"/> runs right after
	/// - <see cref="Categories.MSFTSecBaselines_OptionalOverrides"/> runs last
	/// Lower numbers run earlier; higher numbers run later.
	/// Default priority for all others is 0.
	/// </summary>
	internal static int GetExecutionPriority(Categories category)
	{
		// Maintain deterministic ordering among the "first" group by using distinct negative priorities.
		return category switch
		{
			Categories.MicrosoftSecurityBaseline => -1000,                // Apply first
			Categories.Microsoft365AppsSecurityBaseline => -900,          // Apply second
			Categories.MSFTSecBaselines_OptionalOverrides => 1000,        // Apply last
			_ => 0                                                        // Default priority
		};
	}

	#region Concrete processor implementations for MUnit-based categories

	private sealed class MicrosoftSecurityBaselineOverridesProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.MSFTSecBaselines_OptionalOverrides;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_MSFTSecBaselineOverrides");
		protected override IMUnitListViewModel ViewModel => ViewModelProvider.MicrosoftBaseLinesOverridesVM;

		// Using the ViewModel so Protect flows include everything the VM defines (JSON + programmatic MUnits),
		// and also benefit from any specialized registrations/dependencies the VM wires.
		protected override List<MUnit> AllMUnits => ViewModelProvider.MicrosoftBaseLinesOverridesVM.AllMUnits;
	}

	private sealed class MicrosoftDefenderProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.MicrosoftDefender;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_MSFTDefender");
		protected override IMUnitListViewModel ViewModel => ViewModelProvider.MicrosoftDefenderVM;

		// Using the ViewModel so Protect flows include everything the VM defines (JSON + programmatic MUnits),
		// and also benefit from any specialized registrations/dependencies the VM wires.
		protected override List<MUnit> AllMUnits => ViewModelProvider.MicrosoftDefenderVM.AllMUnits;
	}

	private sealed class BitLockerSettingsProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.BitLockerSettings;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_BitLocker");
		protected override IMUnitListViewModel ViewModel => ViewModelProvider.BitLockerVM;

		// Using the ViewModel so Protect flows include everything the VM defines (JSON + programmatic MUnits),
		// and also benefit from any specialized registrations/dependencies the VM wires.
		protected override List<MUnit> AllMUnits => ViewModelProvider.BitLockerVM.AllMUnits;
	}

	private sealed class TLSSecurityProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.TLSSecurity;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_TLS");
		protected override IMUnitListViewModel ViewModel => ViewModelProvider.TLSVM;

		// Using the ViewModel so Protect flows include everything the VM defines (JSON + programmatic MUnits),
		// and also benefit from any specialized registrations/dependencies the VM wires.
		protected override List<MUnit> AllMUnits => ViewModelProvider.TLSVM.AllMUnits;
	}

	private sealed class LockScreenProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.LockScreen;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_LockScreen");
		protected override IMUnitListViewModel ViewModel => ViewModelProvider.LockScreenVM;

		// Using the ViewModel so Protect flows include everything the VM defines (JSON + programmatic MUnits),
		// and also benefit from any specialized registrations/dependencies the VM wires.
		protected override List<MUnit> AllMUnits => ViewModelProvider.LockScreenVM.AllMUnits;
	}

	private sealed class UserAccountControlProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.UserAccountControl;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_UAC");
		protected override IMUnitListViewModel ViewModel => ViewModelProvider.UACVM;

		// Use the ViewModel's CreateAllMUnits so both JSON and programmatic MUnits
		// and all specialized registrations/dependencies are included for Protect flows.
		protected override List<MUnit> AllMUnits => ViewModelProvider.UACVM.AllMUnits;
	}

	private sealed class DeviceGuardProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.DeviceGuard;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_DeviceGuard");
		protected override IMUnitListViewModel ViewModel => ViewModelProvider.DeviceGuardVM;

		// Using the ViewModel so Protect flows include everything the VM defines (JSON + programmatic MUnits),
		// and also benefit from any specialized registrations/dependencies the VM wires.
		protected override List<MUnit> AllMUnits => ViewModelProvider.DeviceGuardVM.AllMUnits;
	}

	private sealed class WindowsFirewallProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.WindowsFirewall;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_WindowsFirewall");
		protected override IMUnitListViewModel ViewModel => ViewModelProvider.WindowsFirewallVM;

		// Using the ViewModel so Protect flows include everything the VM defines (JSON + programmatic MUnits),
		// and also benefit from any specialized registrations/dependencies the VM wires.
		protected override List<MUnit> AllMUnits => ViewModelProvider.WindowsFirewallVM.AllMUnits;
	}

	private sealed class WindowsNetworkingProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.WindowsNetworking;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_WindowsNetworking");
		protected override IMUnitListViewModel ViewModel => ViewModelProvider.WindowsNetworkingVM;

		// Using the ViewModel so Protect flows include everything the VM defines (JSON + programmatic MUnits),
		// and also benefit from any specialized registrations/dependencies the VM wires.
		protected override List<MUnit> AllMUnits => ViewModelProvider.WindowsNetworkingVM.AllMUnits;
	}

	private sealed class MiscellaneousConfigurationsProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.MiscellaneousConfigurations;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_MiscellaneousConfig");
		protected override IMUnitListViewModel ViewModel => ViewModelProvider.MiscellaneousConfigsVM;

		// Using the ViewModel so Protect flows include everything the VM defines (JSON + programmatic MUnits),
		// and also benefit from any specialized registrations/dependencies the VM wires.
		protected override List<MUnit> AllMUnits => ViewModelProvider.MiscellaneousConfigsVM.AllMUnits;
	}

	private sealed class WindowsUpdateConfigurationsProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.WindowsUpdateConfigurations;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_WindowsUpdate");
		protected override IMUnitListViewModel ViewModel => ViewModelProvider.WindowsUpdateVM;

		// Using the ViewModel so Protect flows include everything the VM defines (JSON + programmatic MUnits),
		// and also benefit from any specialized registrations/dependencies the VM wires.
		protected override List<MUnit> AllMUnits => ViewModelProvider.WindowsUpdateVM.AllMUnits;
	}

	private sealed class EdgeBrowserConfigurationsProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.EdgeBrowserConfigurations;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_Edge");
		protected override IMUnitListViewModel ViewModel => ViewModelProvider.EdgeVM;

		// Using the ViewModel so Protect flows include everything the VM defines (JSON + programmatic MUnits),
		// and also benefit from any specialized registrations/dependencies the VM wires.
		protected override List<MUnit> AllMUnits => ViewModelProvider.EdgeVM.AllMUnits;
	}

	private sealed class NonAdminCommandsProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.NonAdminCommands;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_NonAdmin");
		protected override IMUnitListViewModel ViewModel => ViewModelProvider.NonAdminVM;

		// Using the ViewModel so Protect flows include everything the VM defines (JSON + programmatic MUnits),
		// and also benefit from any specialized registrations/dependencies the VM wires.
		protected override List<MUnit> AllMUnits => ViewModelProvider.NonAdminVM.AllMUnits;
	}

	#endregion

	#region Custom processor for Optional Windows Features

	private sealed class MicrosoftSecurityBaselineProcessor : ICategoryProcessor
	{
		public Categories Category => Categories.MicrosoftSecurityBaseline;
		public string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_MSFTSecBaseline");

		public async Task ApplyAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null)
		{
			await ViewModelProvider.MicrosoftSecurityBaselineVM.ApplyInternal();
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
		public string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_MSFT365AppsSecBaseline");

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
		public string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_OptionalWinFeatures");

		public async Task ApplyAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null)
		{
			// Ensure the ListView's collection is loaded first. Not strictly needed for the other method
			// But improves user experience.
			await ViewModelProvider.OptionalWindowsFeaturesVM.EnsureRecommendedItemsRetrievedAndGroupAsync();
			await ViewModelProvider.OptionalWindowsFeaturesVM.ApplySecurityHardening();
		}

		public async Task RemoveAllAsync(List<SubCategories>? selectedSubCategories = null, Intent? selectedIntent = null, CancellationToken? cancellationToken = null)
		{
			// Ensure the ListView's collection is loaded first. Not strictly needed for the other method
			// But improves user experience.
			await ViewModelProvider.OptionalWindowsFeaturesVM.EnsureRecommendedItemsRetrievedAndGroupAsync();
			await ViewModelProvider.OptionalWindowsFeaturesVM.RemoveSecurityHardening();
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
		public string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_ASRRules");

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
			if (all == null || all.Count == 0)
			{
				return;
			}

			List<RegistryPolicyEntry> subset = new(capacity: all.Count);

			// Parent policy must always be included for apply
			foreach (RegistryPolicyEntry entry in all)
			{
				if (entry.ValueName != null &&
					entry.ValueName.Equals("ExploitGuard_ASR_Rules", StringComparison.OrdinalIgnoreCase))
				{
					subset.Add(entry);
					break;
				}
			}

			foreach (RegistryPolicyEntry entry in all)
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
			if (all == null || all.Count == 0)
			{
				return;
			}

			// Build a subset of rules to remove, excluding the parent policy key.
			List<RegistryPolicyEntry> subset = new(capacity: all.Count);

			foreach (RegistryPolicyEntry entry in all)
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
		public string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_CountryIPBlock");

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
