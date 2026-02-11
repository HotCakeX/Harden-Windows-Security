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
using System.Linq;
using System.Threading;
using CommonCore.GroupPolicy;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;
using CommonCore.SecurityPolicy;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class MicrosoftBaseLinesOverridesVM : MUnitListViewModelBase
{
	[SetsRequiredMembers]
	internal MicrosoftBaseLinesOverridesVM()
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
			// Create MUnits from Group Policies.
			List<MUnit> temp = MUnit.CreateMUnitsFromPolicies(Categories.MSFTSecBaselines_OptionalOverrides);

			#region Create MUnit that is not for Group Policies.

			temp.Add(new(
				category: Categories.MSFTSecBaselines_OptionalOverrides,
				name: GlobalVars.GetSecurityStr("SeDenyRemoteInteractiveLogonRight-OptionalOverrides"),

				applyStrategy: new DefaultApply(() =>
				{
					Dictionary<string, string[]> SeDenyRemoteInteractiveLogonRight = new() {

						// Anonymous logon, NetworkService, Guests
						{"SeDenyRemoteInteractiveLogonRight", ["*S-1-5-7", "*S-1-5-32-546", "*S-1-5-20"] }
					};

					SecurityPolicyWriter.SetPrivilegeRights(SeDenyRemoteInteractiveLogonRight);
				}),

				verifyStrategy: new DefaultVerify(() =>
				{
					// Get current privilege rights of the system.
					Dictionary<string, string[]> currentPrivileges = SecurityPolicyReader.GetPrivilegeRights();

					string[] targetPrivileges = ["*S-1-5-7", "*S-1-5-32-546", "*S-1-5-20"];

					if (currentPrivileges.TryGetValue("SeDenyRemoteInteractiveLogonRight", out string[]? privsOutput))
					{
						return privsOutput.Length == targetPrivileges.Length &&
							   privsOutput.All(expected => targetPrivileges.Contains(expected, StringComparer.OrdinalIgnoreCase));
					}

					return false;
				}),

				removeStrategy: new DefaultRemove(() =>
				{
					Dictionary<string, string[]> SeDenyRemoteInteractiveLogonRight = new() {

						// By default it has None.
						{"SeDenyRemoteInteractiveLogonRight", [] }
					};

					SecurityPolicyWriter.SetPrivilegeRights(SeDenyRemoteInteractiveLogonRight);
				}),

				url: "https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/deny-log-on-through-remote-desktop-services",

				deviceIntents: [
					Intent.Development,
					Intent.Gaming,
					Intent.School
				],

				id: new("019b2afa-abd8-7b8f-8136-de0baf0d50fc")
			));

			#endregion

			return temp;

		}, LazyThreadSafetyMode.ExecutionAndPublication);

	/// <summary>
	/// Gets the current catalog of all MUnits for this ViewModel.
	/// </summary>
	public override List<MUnit> AllMUnits => LazyCatalog.Value;
}
