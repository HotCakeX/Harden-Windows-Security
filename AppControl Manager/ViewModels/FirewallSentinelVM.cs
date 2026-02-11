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
using System.Globalization;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using AppControlManager.XMLOps;
using CommonCore.GroupPolicy;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

internal sealed partial class FirewallSentinelVM : ViewModelBase
{
	internal FirewallSentinelVM() => MainInfoBar = new InfoBarSettings(
		() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
		() => MainInfoBarMessage, value => MainInfoBarMessage = value,
		() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
		() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
		Dispatcher,
		() => MainInfoBarTitle, value => MainInfoBarTitle = value);

	private readonly InfoBarSettings MainInfoBar;

	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); } = true;
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal string? MainInfoBarTitle { get; set => SP(ref field, value); }

	/// <summary>
	/// Gets or sets the visibility state of the progress ring.
	/// </summary>
	internal Visibility ProgressRingVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	/// <summary>
	/// Enables/Disables the UI elements during an ongoing operation.
	/// </summary>
	internal bool ElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				MainInfoBarIsClosable = field;
				ProgressRingVisibility = field ? Visibility.Collapsed : Visibility.Visible;
			}
		}
	} = true;

	/// <summary>
	/// Where Firewall backup files are held.
	/// </summary>
	private static readonly string FirewallBackupDirectory = Directory.CreateDirectory(Path.Combine(Microsoft.Windows.Storage.ApplicationData.GetDefault().LocalCachePath, "FirewallBackup")).FullName;

	/// <summary>
	/// Location of the Persistent Store firewall backup.
	/// </summary>
	private static readonly string PersistentStoreOriginalFile = Path.Combine(FirewallBackupDirectory, "PersistentStoreOriginal.wfw");

	/// <summary>
	/// Location of the GPO store backup.
	/// </summary>
	private static readonly string GPOStoreOriginalFile = Path.Combine(FirewallBackupDirectory, "GPOStoreOriginal.wfw");

	/// <summary>
	/// The App ID Tag to use for the deployed policy.
	/// </summary>
	internal string? AppIDTagTouse { get; set => SPT(ref field, value); } = "AppControlManagerTag";

	/// <summary>
	/// Name of the main firewall rule created for App ID Tagging.
	/// </summary>
	internal string? AppIDTagFirewallRuleName { get; set => SPT(ref field, value); } = "AppIDTaggingPolicy";

	/// <summary>
	/// Description of the main firewall rule created for App ID Tagging.
	/// </summary>
	internal string? AppIDTagFirewallRuleDescription { get; set => SPT(ref field, value); } = "Created by AppControl Manager for App ID Tagging.";

	/// <summary>
	/// Name of the App ID Tagging App Control policy.
	/// </summary>
	internal string? AppIDTagPolicyName { get; set => SPT(ref field, value); } = "App ID Tagging Policy";

	/// <summary>
	/// Firewall related policies to apply to the system.
	/// </summary>
	private static readonly Lazy<List<RegistryPolicyEntry>> FirewallPolicies = new(() =>
	{
		List<RegistryPolicyEntry> policies = [];

		// Set Policy Version
		policies.Add(new RegistryPolicyEntry(
			source: Source.GroupPolicy,
			keyName: @"SOFTWARE\Policies\Microsoft\WindowsFirewall",
			valueName: "PolicyVersion",
			type: RegistryValueType.REG_DWORD,
			size: 4,
			data: new byte[] { 0x21, 0x02, 0x00, 0x00 },
			hive: Hive.HKLM,
			id: new("019a97ba-275a-774d-a8c5-318a2652c0b0"))
		{
			RegValue = "545",
			policyAction = PolicyAction.Apply
		});

		// Block local policy merge for Domain Profile
		policies.Add(new RegistryPolicyEntry(
			source: Source.GroupPolicy,
			keyName: @"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile",
			valueName: "AllowLocalPolicyMerge",
			type: RegistryValueType.REG_DWORD,
			size: 4,
			data: new byte[] { 0x00, 0x00, 0x00, 0x00 },
			hive: Hive.HKLM,
			id: new("019a97ba-275a-774d-a8c5-318a2652c0b0"))
		{
			RegValue = "0",
			policyAction = PolicyAction.Apply
		});

		// Set default outbound action for domain profile to block
		policies.Add(new RegistryPolicyEntry(
			source: Source.GroupPolicy,
			keyName: @"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile",
			valueName: "DefaultOutboundAction",
			type: RegistryValueType.REG_DWORD,
			size: 4,
			data: new byte[] { 0x01, 0x00, 0x00, 0x00 },
			hive: Hive.HKLM,
			id: new("019a97ba-275a-774d-a8c5-318a2652c0b0"))
		{
			RegValue = "1",
			policyAction = PolicyAction.Apply
		});

		// Enable firewall for the domain profile
		policies.Add(new RegistryPolicyEntry(
			source: Source.GroupPolicy,
			keyName: @"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile",
			valueName: "EnableFirewall",
			type: RegistryValueType.REG_DWORD,
			size: 4,
			data: new byte[] { 0x01, 0x00, 0x00, 0x00 },
			hive: Hive.HKLM,
			id: new("019a97ba-275a-774d-a8c5-318a2652c0b0"))
		{
			RegValue = "1",
			policyAction = PolicyAction.Apply,
			FriendlyName = "Windows Defender Firewall: Protect all network connections"
		});

		// Set default inbound action for domain profile to block
		policies.Add(new RegistryPolicyEntry(
			source: Source.GroupPolicy,
			keyName: @"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile",
			valueName: "DefaultInboundAction",
			type: RegistryValueType.REG_DWORD,
			size: 4,
			data: new byte[] { 0x01, 0x00, 0x00, 0x00 },
			hive: Hive.HKLM,
			id: new("019a97ba-275a-774d-a8c5-318a2652c0b0"))
		{
			RegValue = "1",
			policyAction = PolicyAction.Apply
		});

		// block local policy merge for the private profile
		policies.Add(new RegistryPolicyEntry(
			source: Source.GroupPolicy,
			keyName: @"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile",
			valueName: "AllowLocalPolicyMerge",
			type: RegistryValueType.REG_DWORD,
			size: 4,
			data: new byte[] { 0x00, 0x00, 0x00, 0x00 },
			hive: Hive.HKLM,
			id: new("019a97ba-275a-774d-a8c5-318a2652c0b0"))
		{
			RegValue = "0",
			policyAction = PolicyAction.Apply
		});

		// set the outbound action for private profile to block
		policies.Add(new RegistryPolicyEntry(
			source: Source.GroupPolicy,
			keyName: @"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile",
			valueName: "DefaultOutboundAction",
			type: RegistryValueType.REG_DWORD,
			size: 4,
			data: new byte[] { 0x01, 0x00, 0x00, 0x00 },
			hive: Hive.HKLM,
			id: new("019a97ba-275a-774d-a8c5-318a2652c0b0"))
		{
			RegValue = "1",
			policyAction = PolicyAction.Apply
		});

		// enable firewall for private profile
		policies.Add(new RegistryPolicyEntry(
			source: Source.GroupPolicy,
			keyName: @"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile",
			valueName: "EnableFirewall",
			type: RegistryValueType.REG_DWORD,
			size: 4,
			data: new byte[] { 0x01, 0x00, 0x00, 0x00 },
			hive: Hive.HKLM,
			id: new("019a97ba-275a-774d-a8c5-318a2652c0b0"))
		{
			RegValue = "1",
			policyAction = PolicyAction.Apply
		});

		// set inbound action for private profile to block
		policies.Add(new RegistryPolicyEntry(
			source: Source.GroupPolicy,
			keyName: @"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile",
			valueName: "DefaultInboundAction",
			type: RegistryValueType.REG_DWORD,
			size: 4,
			data: new byte[] { 0x01, 0x00, 0x00, 0x00 },
			hive: Hive.HKLM,
			id: new("019a97ba-275a-774d-a8c5-318a2652c0b0"))
		{
			RegValue = "1",
			policyAction = PolicyAction.Apply
		});

		// block local policy merge for the public profile
		policies.Add(new RegistryPolicyEntry(
			source: Source.GroupPolicy,
			keyName: @"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile",
			valueName: "AllowLocalPolicyMerge",
			type: RegistryValueType.REG_DWORD,
			size: 4,
			data: new byte[] { 0x00, 0x00, 0x00, 0x00 },
			hive: Hive.HKLM,
			id: new("019a97ba-275a-774d-a8c5-318a2652c0b0"))
		{
			RegValue = "0",
			policyAction = PolicyAction.Apply
		});

		// set outbound action for public profile to block
		policies.Add(new RegistryPolicyEntry(
			source: Source.GroupPolicy,
			keyName: @"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile",
			valueName: "DefaultOutboundAction",
			type: RegistryValueType.REG_DWORD,
			size: 4,
			data: new byte[] { 0x01, 0x00, 0x00, 0x00 },
			hive: Hive.HKLM,
			id: new("019a97ba-275a-774d-a8c5-318a2652c0b0"))
		{
			RegValue = "1",
			policyAction = PolicyAction.Apply
		});

		// enable firewall for public profile
		policies.Add(new RegistryPolicyEntry(
			source: Source.GroupPolicy,
			keyName: @"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile",
			valueName: "EnableFirewall",
			type: RegistryValueType.REG_DWORD,
			size: 4,
			data: new byte[] { 0x01, 0x00, 0x00, 0x00 },
			hive: Hive.HKLM,
			id: new("019a97ba-275a-774d-a8c5-318a2652c0b0"))
		{
			RegValue = "1",
			policyAction = PolicyAction.Apply
		});

		// set inbound action for public profile to block
		policies.Add(new RegistryPolicyEntry(
			source: Source.GroupPolicy,
			keyName: @"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile",
			valueName: "DefaultInboundAction",
			type: RegistryValueType.REG_DWORD,
			size: 4,
			data: new byte[] { 0x01, 0x00, 0x00, 0x00 },
			hive: Hive.HKLM,
			id: new("019a97ba-275a-774d-a8c5-318a2652c0b0"))
		{
			RegValue = "1",
			policyAction = PolicyAction.Apply
		});

		return policies;
	});

	/// <summary>
	/// Event handler for the UI button to restore the firewall configurations.
	/// </summary>
	internal async void RestoreFirewall()
	{
		try
		{
			ElementsAreEnabled = false;

			await Task.Run(() =>
			{

				MainInfoBar.WriteInfo("Restoring Firewall configurations...");

				if (Path.Exists(PersistentStoreOriginalFile))
				{
					// Delete all firewall rules from the Persistent Store
					Firewall.DeleteAllFirewallRules(store: FW_STORE_TYPE.LOCAL);

					// Import rules from backup to the Persistent Store
					Firewall.ImportFirewallPolicy(PersistentStoreOriginalFile, false);
				}
				else
				{
					MainInfoBar.WriteWarning("No backup found for the Persistent Store firewall rules. Skipping restoration for it.");
				}

				if (Path.Exists(GPOStoreOriginalFile))
				{
					// Delete all firewall rules from the GPO Store
					Firewall.DeleteAllFirewallRules(store: FW_STORE_TYPE.GPO);

					// Import rules from backup to the GPO Store
					Firewall.ImportFirewallPolicy(GPOStoreOriginalFile, true);
				}
				else
				{
					MainInfoBar.WriteWarning("No backup found for the GPO Store firewall rules. Skipping restoration for it.");
				}

				// Remove the Firewall related Group policies
				RegistryPolicyParser.RemovePoliciesFromSystem(FirewallPolicies.Value, GroupPolicyContext.Machine);
			});

			MainInfoBar.WriteSuccess("Successfully restored the firewall configurations.");
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
	/// Opens the directory where firewall backup files are located.
	/// </summary>
	internal async void OpenBackupDirectory()
	{
		try
		{
			await OpenFileInDefaultFileHandler(FirewallBackupDirectory);
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Event handler for the UI button to delete the backups.
	/// </summary>
	internal void ClearBackups()
	{
		if (Path.Exists(PersistentStoreOriginalFile))
		{
			File.Delete(PersistentStoreOriginalFile);
		}

		if (Path.Exists(GPOStoreOriginalFile))
		{
			File.Delete(GPOStoreOriginalFile);
		}
	}

	internal async void ConfigureFirewallForDefaultWindows() => await SetFirewall(mode: 0);
	internal async void ConfigureFirewallForAllowMicrosoft() => await SetFirewall(mode: 1);
	internal async void ConfigureFirewallForSignedAndReputable() => await SetFirewall(mode: 2);

	/// <summary>
	/// Configures the system and firewall for different modes of App ID Tagging.
	/// </summary>
	/// <param name="mode"></param>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	/// <exception cref="ArgumentOutOfRangeException"></exception>
	private async Task SetFirewall(int mode)
	{
		if (string.IsNullOrWhiteSpace(AppIDTagTouse))
		{
			throw new InvalidOperationException("You need to enter an AppID Tag to use for the deployed policy.");
		}

		try
		{
			ElementsAreEnabled = false;

			MainInfoBar.WriteInfo("Configuring the system");

			await Task.Run(async () =>
			{
				// Export rules from Persistent Store
				Firewall.ExportFirewallPolicy(PersistentStoreOriginalFile, false);

				// Export rules from GPO Store
				Firewall.ExportFirewallPolicy(GPOStoreOriginalFile, true);

				// Delete all firewall rules from the Persistent Store
				Firewall.DeleteAllFirewallRules(store: FW_STORE_TYPE.LOCAL);

				// Add Persistent Store's rules to the GPO store
				Firewall.ImportFirewallPolicy(PersistentStoreOriginalFile, true);

				// Add the AppID Tagging policy for outbound rules
				// Allows App Control policies to authorize user-mode executables that carry our tag
				Logger.Write(ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, $"""firewallprogram "{AppIDTagFirewallRuleName}" outbound allow "{AppIDTagFirewallRuleDescription}" --appid "{AppIDTagTouse}" """));

				// Add System to outbound allow rule
				// Required because AppID Tags only apply to User-Mode executables and System is kernel-mode and doesn't apply to it.
				// Without this, things such as ping commands don't work.
				Logger.Write(ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, $"""firewallprogram "Allow SYSTEM process" outbound allow "Allows System Process for outbound communications. Created by the AppControl Manager for App ID Tagging." --program "System" """));

				// Add Svchost.exe outbound allow rule
				// Without this, installation from the Microsoft Store for apps that require service installation, such as Harden System Security, fail.
				Logger.Write(ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, $"""firewallprogram "Allow Svhost process" outbound allow "Allows Service Host Process for outbound communications. Created by the AppControl Manager for App ID Tagging." --program "%SystemRoot%\system32\svchost.exe" """));

				#region Group Policies

				// Set Group Policies
				RegistryPolicyParser.AddPoliciesToSystem(FirewallPolicies.Value, GroupPolicyContext.Machine);

				#endregion Group Policies

				PolicyFileRepresent policy = mode switch
				{
					0 => BasePolicyCreator.BuildDefaultWindows(
						IsAudit: false,
						LogSize: 0,
						deploy: false,
						RequireEVSigners: false,
						EnableScriptEnforcement: true,
						TestMode: false,
						deployAppControlSupplementalPolicy: false,
						PolicyIDToUse: null,
						DeployMicrosoftRecommendedBlockRules: false,
						IsAppIDTagging: false // Don't need it to add tags for us because we are going to modify the policy here
					),
					1 => BasePolicyCreator.BuildAllowMSFT(
						IsAudit: false,
						LogSize: 0,
						deploy: false,
						RequireEVSigners: false,
						EnableScriptEnforcement: true,
						TestMode: false,
						deployAppControlSupplementalPolicy: false,
						PolicyIDToUse: null,
						DeployMicrosoftRecommendedBlockRules: false,
						IsAppIDTagging: false
					),
					2 => await BasePolicyCreator.BuildSignedAndReputable(
						IsAudit: false,
						LogSize: 0,
						deploy: false,
						RequireEVSigners: false,
						EnableScriptEnforcement: true,
						TestMode: false,
						deployAppControlSupplementalPolicy: false,
						PolicyIDToUse: null,
						DeployMicrosoftRecommendedBlockRules: false
					),
					_ => throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unexpected mode value")
				};

				// Convert it to AppIDTagging policy

				Dictionary<string, string> tags = [];
				tags[AppIDTagTouse] = "True";

				policy.PolicyObj = AppIDTagging.Convert(policy.PolicyObj);
				policy.PolicyObj = AppIDTagging.AddTags(policy.PolicyObj, tags);

				// Set the App ID Tagging policy name
				policy.PolicyObj = SetCiPolicyInfo.Set(policy.PolicyObj, null, AppIDTagPolicyName, null);

				// Deploy the App ID Tagging policy to the system
				CiToolHelper.UpdatePolicy(Management.ConvertXMLToBinary(policy.PolicyObj));

				// Assign the created policy to the Sidebar
				ViewModelProvider.MainWindowVM.AssignToSidebar(policy);

				MainInfoBar.WriteSuccess("Successfully configured the system");
			});
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
}
