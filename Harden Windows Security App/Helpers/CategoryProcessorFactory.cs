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
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.Others;
using HardenWindowsSecurity.Protect;
using HardenWindowsSecurity.ViewModels;

namespace HardenWindowsSecurity.Helpers;

/// <summary>
/// Factory for creating category processors. Used by the main Protect page.
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
			Categories.CertificateChecking => new CertificateCheckingProcessor(),
			Categories.CountryIPBlocking => new CountryIPBlockingProcessor(),
			Categories.NonAdminCommands => new NonAdminCommandsProcessor(),
			_ => throw new ArgumentException($"Unknown category: {category}", nameof(category))
		};
	}

	#region Concrete processor implementations for MUnit-based categories

	private sealed class MicrosoftSecurityBaselineProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.MicrosoftSecurityBaseline;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_MSFTSecBaseline");
		protected override List<MUnit> CreateAllMUnits() => MUnit.CreateMUnitsFromPolicies(Categories.MicrosoftSecurityBaseline);
	}

	private sealed class Microsoft365AppsSecurityBaselineProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.Microsoft365AppsSecurityBaseline;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_MSFT365AppsSecBaseline");
		protected override List<MUnit> CreateAllMUnits() => MUnit.CreateMUnitsFromPolicies(Categories.Microsoft365AppsSecurityBaseline);
	}

	private sealed class MicrosoftDefenderProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.MicrosoftDefender;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_MSFTDefender");
		protected override List<MUnit> CreateAllMUnits() => MUnit.CreateMUnitsFromPolicies(Categories.MicrosoftDefender);
	}

	private sealed class BitLockerSettingsProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.BitLockerSettings;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_BitLocker");
		protected override List<MUnit> CreateAllMUnits() => MUnit.CreateMUnitsFromPolicies(Categories.BitLockerSettings);
	}

	private sealed class TLSSecurityProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.TLSSecurity;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_TLS");
		protected override List<MUnit> CreateAllMUnits() => MUnit.CreateMUnitsFromPolicies(Categories.TLSSecurity);
	}

	private sealed class LockScreenProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.LockScreen;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_LockScreen");
		protected override List<MUnit> CreateAllMUnits() => MUnit.CreateMUnitsFromPolicies(Categories.LockScreen);
	}

	private sealed class UserAccountControlProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.UserAccountControl;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_UAC");
		protected override List<MUnit> CreateAllMUnits() => MUnit.CreateMUnitsFromPolicies(Categories.UserAccountControl);
	}

	private sealed class DeviceGuardProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.DeviceGuard;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_DeviceGuard");
		protected override List<MUnit> CreateAllMUnits() => MUnit.CreateMUnitsFromPolicies(Categories.DeviceGuard);
	}

	private sealed class WindowsFirewallProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.WindowsFirewall;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_WindowsFirewall");
		protected override List<MUnit> CreateAllMUnits() => MUnit.CreateMUnitsFromPolicies(Categories.WindowsFirewall);
	}

	private sealed class WindowsNetworkingProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.WindowsNetworking;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_WindowsNetworking");
		protected override List<MUnit> CreateAllMUnits() => MUnit.CreateMUnitsFromPolicies(Categories.WindowsNetworking);
	}

	private sealed class MiscellaneousConfigurationsProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.MiscellaneousConfigurations;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_MiscellaneousConfig");
		protected override List<MUnit> CreateAllMUnits() => MUnit.CreateMUnitsFromPolicies(Categories.MiscellaneousConfigurations);
	}

	private sealed class WindowsUpdateConfigurationsProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.WindowsUpdateConfigurations;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_WindowsUpdate");
		protected override List<MUnit> CreateAllMUnits() => MUnit.CreateMUnitsFromPolicies(Categories.WindowsUpdateConfigurations);
	}

	private sealed class EdgeBrowserConfigurationsProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.EdgeBrowserConfigurations;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_Edge");
		protected override List<MUnit> CreateAllMUnits() => MUnit.CreateMUnitsFromPolicies(Categories.EdgeBrowserConfigurations);
	}

	private sealed class CertificateCheckingProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.CertificateChecking;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_CertificateCheck");
		protected override List<MUnit> CreateAllMUnits() => MUnit.CreateMUnitsFromPolicies(Categories.CertificateChecking);
	}

	private sealed class CountryIPBlockingProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.CountryIPBlocking;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_CountryIPBlock");
		protected override List<MUnit> CreateAllMUnits() => MUnit.CreateMUnitsFromPolicies(Categories.CountryIPBlocking);
	}

	private sealed class NonAdminCommandsProcessor : MUnitCategoryProcessor
	{
		public override Categories Category => Categories.NonAdminCommands;
		public override string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_NonAdmin");
		protected override List<MUnit> CreateAllMUnits() => MUnit.CreateMUnitsFromPolicies(Categories.NonAdminCommands);
	}

	#endregion

	#region Custom processor for Optional Windows Features

	// These are the ViewModels that don't use MUnit and have custom logics.

	private sealed class OptionalWindowsFeaturesProcessor : ICategoryProcessor
	{
		public Categories Category => Categories.OptionalWindowsFeatures;
		public string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_OptionalWinFeatures");

		public async Task ApplyAllAsync(List<SubCategories>? selectedSubCategories = null, CancellationToken? cancellationToken = null)
		{
			OptionalWindowsFeaturesVM optionalVM = ViewModelProvider.OptionalWindowsFeaturesVM;
			await optionalVM.ApplySecurityHardening();
		}

		public async Task RemoveAllAsync(List<SubCategories>? selectedSubCategories = null, CancellationToken? cancellationToken = null)
		{
			OptionalWindowsFeaturesVM optionalVM = ViewModelProvider.OptionalWindowsFeaturesVM;
			await optionalVM.RemoveSecurityHardening();
		}

		public async Task VerifyAllAsync(List<SubCategories>? selectedSubCategories = null, CancellationToken? cancellationToken = null)
		{
			OptionalWindowsFeaturesVM optionalVM = ViewModelProvider.OptionalWindowsFeaturesVM;
			_ = await optionalVM.VerifySecurityHardening();
		}
	}

	private sealed class AttackSurfaceReductionRulesProcessor : ICategoryProcessor
	{
		public Categories Category => Categories.AttackSurfaceReductionRules;
		public string CategoryDisplayName => GlobalVars.GetStr("ProtectCategory_ASRRules");

		public async Task ApplyAllAsync(List<SubCategories>? selectedSubCategories = null, CancellationToken? cancellationToken = null)
		{
			ASRVM asrVM = ViewModelProvider.ASRVM;
			await Task.Run(asrVM.ApplyRecommended, cancellationToken ?? CancellationToken.None);
		}

		public async Task RemoveAllAsync(List<SubCategories>? selectedSubCategories = null, CancellationToken? cancellationToken = null)
		{
			ASRVM asrVM = ViewModelProvider.ASRVM;
			await Task.Run(asrVM.RemoveAllRules, cancellationToken ?? CancellationToken.None);
		}

		public async Task VerifyAllAsync(List<SubCategories>? selectedSubCategories = null, CancellationToken? cancellationToken = null)
		{
			ASRVM asrVM = ViewModelProvider.ASRVM;
			await Task.Run(asrVM.RetrieveLatest, cancellationToken ?? CancellationToken.None);
		}
	}

	#endregion

}
