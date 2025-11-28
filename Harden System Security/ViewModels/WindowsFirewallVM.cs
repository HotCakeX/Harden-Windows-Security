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
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class WindowsFirewallVM : MUnitListViewModelBase
{
	[SetsRequiredMembers]
	internal WindowsFirewallVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		// Initializing the cancellable buttons
		ApplyAllCancellableButton = new(GlobalVars.GetStr("ApplyAllButtonText/Text"));
		RemoveAllCancellableButton = new(GlobalVars.GetStr("RemoveAllButtonText/Text"));
		VerifyAllCancellableButton = new(GlobalVars.GetStr("VerifyAllButtonText"));

		IMUnitListViewModel.CreateUIValuesCategories(this);
	}

	/// <summary>
	/// Creates all MUnits for this ViewModel.
	/// </summary>
	private static readonly Lazy<List<MUnit>> LazyCatalog =
		new(() =>
		{
			List<MUnit> temp = MUnit.CreateMUnitsFromPolicies(Categories.WindowsFirewall);
			temp.AddRange(CreateUnits());
			return temp;

		}, LazyThreadSafetyMode.ExecutionAndPublication);

	/// <summary>
	/// Create <see cref="MUnit"/> that is not for Group Policies.
	/// </summary>
	internal static List<MUnit> CreateUnits()
	{
		List<MUnit> temp = [];

		temp.Add(new(
			category: Categories.WindowsFirewall,
			name: GlobalVars.GetSecurityStr("mDNSInboundBlocking-WindowsFirewall"),

			applyStrategy: new DefaultApply(() =>
			{
				_ = QuantumRelayHSS.Client.RunCommand(GlobalVars.ComManagerProcessPath, "firewallmdns set false");
			}),

			verifyStrategy: new DefaultVerify(() =>
			{
				string result = QuantumRelayHSS.Client.RunCommand(GlobalVars.ComManagerProcessPath, "firewallmdns status");

				if (bool.TryParse(result, out bool actualResult))
				{
					return actualResult;
				}

				return false;
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				_ = QuantumRelayHSS.Client.RunCommand(GlobalVars.ComManagerProcessPath, "firewallmdns set true");
			}),

			url: "https://techcommunity.microsoft.com/t5/networking-blog/mdns-in-the-enterprise/ba-p/3275777",

			deviceIntents: [
				DeviceIntents.Intent.Business,
				DeviceIntents.Intent.SpecializedAccessWorkstation,
				DeviceIntents.Intent.PrivilegedAccessWorkstation
			],

			id: new("019abc74-7e26-7825-b763-6a7577ee5d87")
		));

		temp.Add(new(
			category: Categories.WindowsFirewall,
			name: GlobalVars.GetSecurityStr("SetAllNetworkLocationsPublic-WindowsFirewall"),

			applyStrategy: new DefaultApply(() =>
			{
				_ = QuantumRelayHSS.Client.RunCommand(GlobalVars.ComManagerProcessPath, "networkprofiles set 0");
			}),

			verifyStrategy: new DefaultVerify(() =>
			{
				string result = QuantumRelayHSS.Client.RunCommand(GlobalVars.ComManagerProcessPath, "networkprofiles status");

				if (bool.TryParse(result, out bool actualResult))
				{
					return actualResult;
				}

				return false;
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				_ = QuantumRelayHSS.Client.RunCommand(GlobalVars.ComManagerProcessPath, "networkprofiles set 1");
			}),

			url: "https://support.microsoft.com/en-us/windows/make-a-wi-fi-network-public-or-private-in-windows-0460117d-8d3e-a7ac-f003-7a0da607448d",

			deviceIntents: [
				DeviceIntents.Intent.Business,
				DeviceIntents.Intent.SpecializedAccessWorkstation,
				DeviceIntents.Intent.PrivilegedAccessWorkstation
			],

			id: new("019abec8-2702-7fa7-9db2-404dd3647126")
		));

		return temp;
	}

	/// <summary>
	/// Gets the current catalog of all MUnits for this ViewModel.
	/// </summary>
	public override List<MUnit> AllMUnits => LazyCatalog.Value;
}
