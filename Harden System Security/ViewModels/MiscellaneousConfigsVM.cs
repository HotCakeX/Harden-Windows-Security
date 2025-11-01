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
using System.IO;
using System.Threading;
using HardenSystemSecurity.GroupPolicy;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;
using HardenSystemSecurity.SecurityPolicy;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class MiscellaneousConfigsVM : MUnitListViewModelBase
{
	[SetsRequiredMembers]
	internal MiscellaneousConfigsVM()
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
			// Register specialized strategies.
			RegisterSpecializedStrategies();

			List<MUnit> units = CreateUnits();

			units.AddRange(MUnit.CreateMUnitsFromPolicies(Categories.MiscellaneousConfigurations));

			return units;
		}, LazyThreadSafetyMode.ExecutionAndPublication);

	/// <summary>
	/// Gets the current catalog of all MUnits for this ViewModel.
	/// </summary>
	public override List<MUnit> AllMUnits => LazyCatalog.Value;

	/// <summary>
	/// Create <see cref="MUnit"/> that is not for Group Policies.
	/// </summary>
	internal static List<MUnit> CreateUnits()
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
				}),

				deviceIntents: [
					DeviceIntents.Intent.All
				]
			));
		}

		// Secure SSH Client MACs
		output.Add(new(
				category: Categories.MiscellaneousConfigurations,
				name: GlobalVars.GetSecurityStr("SecureSSHMACs-Miscellaneous"),
				applyStrategy: new DefaultApply(SSHConfigurations.SecureMACs),
				verifyStrategy: new DefaultVerify(SSHConfigurations.TestSecureMACs),
				removeStrategy: new DefaultRemove(SSHConfigurations.RemoveSecureMACs),
				url: @"https://learn.microsoft.com/windows-server/administration/OpenSSH/openssh-server-configuration#openssh-configuration-files",
				deviceIntents: [
					DeviceIntents.Intent.SpecializedAccessWorkstation,
					DeviceIntents.Intent.PrivilegedAccessWorkstation,
					DeviceIntents.Intent.School,
					DeviceIntents.Intent.Business
				]
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
				}),

				deviceIntents: [
					DeviceIntents.Intent.SpecializedAccessWorkstation,
					DeviceIntents.Intent.PrivilegedAccessWorkstation,
					DeviceIntents.Intent.School,
					DeviceIntents.Intent.Business
				]
			));
		}

		return output;
	}

	/// <summary>
	/// Registers specialized strategies for specific policies.
	/// </summary>
	private static void RegisterSpecializedStrategies()
	{
		// Register specialized remove strategy for EnableSvchostMitigationPolicy.
		SpecializedStrategiesRegistry.RegisterSpecializedRemove(
			"System\\CurrentControlSet\\Control\\SCMConfig|EnableSvchostMitigationPolicy",
			new EnableSvchostMitigationPolicyPostRemoveCleanup()
		);

		// Register specialized remove strategy for LongPathsEnabled.
		SpecializedStrategiesRegistry.RegisterSpecializedRemove(
			"System\\CurrentControlSet\\Control\\FileSystem|LongPathsEnabled",
			new LongPathsEnabledPostRemoveCleanup()
		);
	}

	/// <summary>
	/// Specialized remove strategy that runs after the main remove operation.
	/// Because the original policy is Group Policy, defined in JSON, and it's a tattooed policy so setting the policy to Not-Configured state won't automatically reset the registry key associated with the policy.
	/// This cleanup step ensures the registry key is removed (which is setting it to 0 in this case) after the main removal operation.
	/// </summary>
	private sealed class EnableSvchostMitigationPolicyPostRemoveCleanup : ISpecializedRemoveStrategy
	{
		public ExecutionTiming Timing => ExecutionTiming.After;

		public void Remove()
		{
			RegistryManager.Manager.EditRegistry(new(
				source: Source.Registry,
				keyName: "System\\CurrentControlSet\\Control\\SCMConfig",
				valueName: "EnableSvchostMitigationPolicy",
				type: RegistryValueType.REG_DWORD,
				size: 4,
				data: ReadOnlyMemory<byte>.Empty,
				hive: Hive.HKLM)
			{
				RegValue = "0",
				policyAction = PolicyAction.Apply
			});
		}
	}

	/// <summary>
	/// Specialized remove strategy that runs after the main remove operation.
	/// Because the original policy is Group Policy, defined in JSON, and it's a tattooed policy so setting the policy to Not-Configured state won't automatically reset the registry key associated with the policy.
	/// This cleanup step ensures the registry key is removed after the main removal operation.
	/// </summary>
	private sealed class LongPathsEnabledPostRemoveCleanup : ISpecializedRemoveStrategy
	{
		public ExecutionTiming Timing => ExecutionTiming.After;

		public void Remove()
		{
			RegistryManager.Manager.EditRegistry(new(
				source: Source.Registry,
				keyName: "System\\CurrentControlSet\\Control\\FileSystem",
				valueName: "LongPathsEnabled",
				type: RegistryValueType.REG_DWORD,
				size: 4,
				data: ReadOnlyMemory<byte>.Empty,
				hive: Hive.HKLM)
			{
				RegValue = "0",
				policyAction = PolicyAction.Apply
			});
		}
	}

}
