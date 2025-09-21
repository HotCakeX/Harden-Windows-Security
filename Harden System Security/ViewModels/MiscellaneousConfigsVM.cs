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
using System.Collections.ObjectModel;
using System.IO;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;
using HardenSystemSecurity.SecurityPolicy;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class MiscellaneousConfigsVM : ViewModelBase, IMUnitListViewModel
{
	internal MiscellaneousConfigsVM()
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
	/// The main InfoBar for this VM.
	/// </summary>
	public InfoBarSettings MainInfoBar { get; }

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	public Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	public bool ElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ProgressBarVisibility = field ? Visibility.Collapsed : Visibility.Visible;
			}
		}
	} = true;

	/// <summary>
	/// Items Source of the ListView.
	/// </summary>
	public ObservableCollection<GroupInfoListForMUnit> ListViewItemsSource { get; set => SP(ref field, value); } = [];

	public List<GroupInfoListForMUnit> ListViewItemsSourceBackingField { get; set; } = [];

	/// <summary>
	/// Selected Items list in the ListView.
	/// </summary>
	public List<MUnit> ItemsSourceSelectedItems { get; set; } = [];

	/// <summary>
	/// Search keyword for ListView.
	/// </summary>
	public string? SearchKeyword { get; set; }

	/// <summary>
	/// Initialization details for the Apply All button
	/// </summary>
	public AnimatedCancellableButtonInitializer ApplyAllCancellableButton { get; }

	/// <summary>
	/// Initialization details for the Remove All button
	/// </summary>
	public AnimatedCancellableButtonInitializer RemoveAllCancellableButton { get; }

	/// <summary>
	/// Initialization details for the Verify All button
	/// </summary>
	public AnimatedCancellableButtonInitializer VerifyAllCancellableButton { get; }

	/// <summary>
	/// Total number of items loaded (all MUnits)
	/// </summary>
	public int TotalItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of items currently displayed after filtering
	/// </summary>
	public int FilteredItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of currently selected items
	/// </summary>
	public int SelectedItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of items with Undetermined status (N/A state)
	/// </summary>
	public int UndeterminedItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of items with Applied status
	/// </summary>
	public int AppliedItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of items with NotApplied status
	/// </summary>
	public int NotAppliedItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Persisted status filter toggles for this ViewModel.
	/// </summary>
	public bool ShowApplied { get; set => SP(ref field, value); } = true;
	public bool ShowNotApplied { get; set => SP(ref field, value); } = true;
	public bool ShowUndetermined { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Creates all MUnits for this ViewModel.
	/// </summary>
	/// <returns>List of all MUnits for this ViewModel</returns>
	public List<MUnit> CreateAllMUnits()
	{
		List<MUnit> units = CreateUnits();

		units.AddRange(MUnit.CreateMUnitsFromPolicies(Categories.MiscellaneousConfigurations));

		return units;
	}


	/// <summary>
	/// Create <see cref="MUnit"/> that is not for Group Policies.
	/// </summary>
	internal List<MUnit> CreateUnits()
	{
		List<MUnit> output = [];

		{
			string OldCustomEventViewsPath = Path.Combine(GlobalVars.SystemDrive, "ProgramData", "Microsoft", "Event Viewer", "Views", "Hardening Script");
			string NewCustomEventViewsPath = Path.Combine(GlobalVars.SystemDrive, "ProgramData", "Microsoft", "Event Viewer", "Views", "HardenSystemSecurity");
			string SourceDirectory = Path.Combine(AppContext.BaseDirectory, "Resources", "EventViewerCustomViews");

			// Create custom event viewer views
			output.Add(new(
				category: Categories.MiscellaneousConfigurations,
				name: GlobalVars.GetSecurityStr("CreateCustomEventViewerViews-Miscellaneous"),

				applyStrategy: new DefaultApply(() =>
				{
					// Delete the old directory that belongs to the deprecated module
					if (Directory.Exists(OldCustomEventViewsPath))
					{
						Directory.Delete(OldCustomEventViewsPath, true);
					}

					// Create the new directory if it doesn't exist
					if (!Directory.Exists(NewCustomEventViewsPath))
					{
						_ = Directory.CreateDirectory(NewCustomEventViewsPath);
					}

					foreach (string file in Directory.GetFiles(SourceDirectory))
					{
						File.Copy(file, Path.Combine(NewCustomEventViewsPath, Path.GetFileName(file)), true);
					}
				}),

				verifyStrategy: new DefaultVerify(() =>
				{
					if (!Directory.Exists(NewCustomEventViewsPath))
					{
						return false;
					}

					string[] sourceFiles = Directory.GetFiles(SourceDirectory);

					foreach (string sourceFile in sourceFiles)
					{
						string destinationFile = Path.Combine(NewCustomEventViewsPath, Path.GetFileName(sourceFile));
						if (!File.Exists(destinationFile))
						{
							return false;
						}
					}

					return true;
				}),

				removeStrategy: new DefaultRemove(() =>
				{
					if (Directory.Exists(NewCustomEventViewsPath))
					{
						Directory.Delete(NewCustomEventViewsPath, true);
					}
				})
			));
		}

		// Secure SSH Client MACs
		output.Add(new(
				category: Categories.MiscellaneousConfigurations,
				name: GlobalVars.GetSecurityStr("SecureSSHMACs-Miscellaneous"),
				applyStrategy: new DefaultApply(SSHConfigurations.SecureMACs),
				verifyStrategy: new DefaultVerify(SSHConfigurations.TestSecureMACs),
				removeStrategy: new DefaultRemove(SSHConfigurations.RemoveSecureMACs),
				url: @"https://learn.microsoft.com/windows-server/administration/OpenSSH/openssh-server-configuration#openssh-configuration-files"
			));

		{
			Guid subcategoryGuid = new("0CCE921C-69AE-11D9-BED3-505054503030");

			// Makes sure auditing for the "Other Logon/Logoff Events" subcategory under the Logon/Logoff category is enabled
			// For tracking Lock screen unlocks and locks
			output.Add(new(
				category: Categories.MiscellaneousConfigurations,
				name: GlobalVars.GetSecurityStr("EnableOtherLogonLogOffAudit-Miscellaneous"),

				applyStrategy: new DefaultApply(() =>
				{
					AuditPrivilegeHelper.EnsurePrivileges();

					AUDIT_POLICY_INFORMATION policy = new()
					{
						AuditSubCategoryGuid = subcategoryGuid,
						AuditCategoryGuid = AuditPolicyManager.GetCategoryGuidForSubcategory(subcategoryGuid),
						AuditingInformation = (uint)(AuditBitFlags.POLICY_AUDIT_EVENT_SUCCESS | AuditBitFlags.POLICY_AUDIT_EVENT_FAILURE) // 3
					};

					AUDIT_POLICY_INFORMATION[] policies = [policy];
					AuditPolicyManager.SetAuditPolicies(policies);
				}),

				verifyStrategy: new DefaultVerify(() =>
				{
					AuditPrivilegeHelper.EnsurePrivileges();

					Dictionary<Guid, uint> current = AuditPolicyManager.GetSpecificAuditPolicies(
						[subcategoryGuid]);

					uint expected = (uint)(AuditBitFlags.POLICY_AUDIT_EVENT_SUCCESS | AuditBitFlags.POLICY_AUDIT_EVENT_FAILURE); // 3

					if (current.TryGetValue(subcategoryGuid, out uint value))
					{
						return value == expected;
					}

					return false;
				}),

				// set the subcategory to No Auditing (0)
				removeStrategy: new DefaultRemove(() =>
				{
					AuditPrivilegeHelper.EnsurePrivileges();

					AUDIT_POLICY_INFORMATION policy = new()
					{
						AuditSubCategoryGuid = subcategoryGuid,
						AuditCategoryGuid = AuditPolicyManager.GetCategoryGuidForSubcategory(subcategoryGuid),
						AuditingInformation = 0 // No Auditing
					};

					AUDIT_POLICY_INFORMATION[] policies = [policy];
					AuditPolicyManager.SetAuditPolicies(policies);
				})
			));
		}

		return output;
	}

}
