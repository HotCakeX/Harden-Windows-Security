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
using System.Diagnostics.CodeAnalysis;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class LockScreenVM : MUnitListViewModelBase
{
	[SetsRequiredMembers]
	internal LockScreenVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			null, null);

		// Initializing the cancellable buttons
		ApplyAllCancellableButton = new(GlobalVars.GetStr("ApplyAllButtonText/Text"));
		RemoveAllCancellableButton = new(GlobalVars.GetStr("RemoveAllButtonText/Text"));
		VerifyAllCancellableButton = new(GlobalVars.GetStr("VerifyAllButtonText"));

		IMUnitListViewModel.CreateUIValuesCategories(this);
	}

	/// <summary>
	/// Creates all MUnits for this ViewModel.
	/// </summary>
	/// <returns>List of all MUnits for this ViewModel</returns>
	public override List<MUnit> CreateAllMUnits()
	{
		List<MUnit> temp = MUnit.CreateMUnitsFromPolicies(Categories.LockScreen);
		temp.AddRange(CreateUnits());
		return temp;
	}

	/// <summary>
	/// Create <see cref="MUnit"/> that is not for Group Policies.
	/// </summary>
	internal List<MUnit> CreateUnits()
	{
		List<MUnit> temp = [];

		temp.Add(new(
			category: Categories.LockScreen,
			name: GlobalVars.GetSecurityStr("LockoutBadCount-LockScreen"),

			applyStrategy: new DefaultApply(() =>
			{
				SecurityPolicy.SecurityPolicyWriter.SetLockoutBadCount(5);
			}),

			verifyStrategy: new DefaultVerify(() =>
			{
				SecurityPolicy.SystemAccessInfo states = SecurityPolicy.SecurityPolicyReader.GetSystemAccess();

				// Consider anything less than 5 as valid.
				return states.LockoutBadCount <= 5;
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				SecurityPolicy.SecurityPolicyWriter.SetLockoutBadCount(10);
			}),

			url: "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold"
		));


		temp.Add(new(
			category: Categories.LockScreen,
			name: GlobalVars.GetSecurityStr("ResetLockoutCount-LockScreen"),

			applyStrategy: new DefaultApply(() =>
			{
				// Requires SetLockoutDuration to be applied first otherwise throws error: 87
				SecurityPolicy.SecurityPolicyWriter.SetLockoutDuration(1440);
				SecurityPolicy.SecurityPolicyWriter.SetResetLockoutCount(1440);
			}),

			verifyStrategy: new DefaultVerify(() =>
			{
				SecurityPolicy.SystemAccessInfo states = SecurityPolicy.SecurityPolicyReader.GetSystemAccess();

				return states.ResetLockoutCount == 1440;
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				SecurityPolicy.SecurityPolicyWriter.SetResetLockoutCount(10);
			}),

			url: "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/reset-account-lockout-counter-after"
		));

		temp.Add(new(
			category: Categories.LockScreen,
			name: GlobalVars.GetSecurityStr("LockoutDuration-LockScreen"),

			applyStrategy: new DefaultApply(() =>
			{
				SecurityPolicy.SecurityPolicyWriter.SetLockoutDuration(1440);
			}),

			verifyStrategy: new DefaultVerify(() =>
			{
				SecurityPolicy.SystemAccessInfo states = SecurityPolicy.SecurityPolicyReader.GetSystemAccess();

				return states.LockoutDuration == 1440;
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				SecurityPolicy.SecurityPolicyWriter.SetLockoutDuration(10);
			}),

			url: "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration"
		));

		return temp;
	}

}
