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

using System.Collections.Frozen;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using AppControlManager.XMLOps;
using CommonCore.GroupPolicy;
using CommonCore.IncrementalCollection;
using CommonCore.SecurityPolicy;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

internal sealed partial class FirewallSentinelVM : ViewModelBase, IDisposable
{
	internal FirewallSentinelVM()
	{
		MainInfoBar = new InfoBarSettings(
		() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
		() => MainInfoBarMessage, value => MainInfoBarMessage = value,
		() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
		() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
		Dispatcher,
		() => MainInfoBarTitle, value => MainInfoBarTitle = value);

		// Subscribe to the Sidebar Library's collection changed event to keep the list in sync real-time
		ViewModelProvider.MainWindowVM.SidebarPoliciesLibrary.CollectionChanged += SidebarPoliciesLibrary_CollectionChanged;

		// Initialize the list of policies
		FilterPolicies();


		FilesAndFoldersProgressRingValueProgress = new Progress<double>(p => FilesAndFoldersProgressRingValue = p);

		// InfoBar manager for the FilesAndFolders section
		FilesAndFoldersInfoBar = new InfoBarSettings(
			() => FilesAndFoldersInfoBarIsOpen, value => FilesAndFoldersInfoBarIsOpen = value,
			() => FilesAndFoldersInfoBarMessage, value => FilesAndFoldersInfoBarMessage = value,
			() => FilesAndFoldersInfoBarSeverity, value => FilesAndFoldersInfoBarSeverity = value,
			() => FilesAndFoldersInfoBarIsClosable, value => FilesAndFoldersInfoBarIsClosable = value,
			Dispatcher,
			() => FilesAndFoldersInfoBarTitle, value => FilesAndFoldersInfoBarTitle = value);

		FilesAndFoldersCancellableButton = new(GlobalVars.GetStr("ExpandPinnedPolicyButton/Content"));

		// InfoBar manager for the CertificatesBased section
		CertificatesBasedInfoBar = new InfoBarSettings(
			() => CertificatesBasedInfoBarIsOpen, value => CertificatesBasedInfoBarIsOpen = value,
			() => CertificatesBasedInfoBarMessage, value => CertificatesBasedInfoBarMessage = value,
			() => CertificatesBasedInfoBarSeverity, value => CertificatesBasedInfoBarSeverity = value,
			() => CertificatesBasedInfoBarIsClosable, value => CertificatesBasedInfoBarIsClosable = value,
			Dispatcher,
			() => CertificatesBasedInfoBarTitle, value => CertificatesBasedInfoBarTitle = value);

		// InfoBar manager for the CustomFilePathRules section
		CustomFilePathRulesInfoBar = new InfoBarSettings(
			() => CustomFilePathRulesInfoBarIsOpen, value => CustomFilePathRulesInfoBarIsOpen = value,
			() => CustomFilePathRulesInfoBarMessage, value => CustomFilePathRulesInfoBarMessage = value,
			() => CustomFilePathRulesInfoBarSeverity, value => CustomFilePathRulesInfoBarSeverity = value,
			() => CustomFilePathRulesInfoBarIsClosable, value => CustomFilePathRulesInfoBarIsClosable = value,
			Dispatcher,
			() => CustomFilePathRulesInfoBarTitle, value => CustomFilePathRulesInfoBarTitle = value);

		PatternBasedFileRuleCancellableButton = new(GlobalVars.GetStr("ExpandPinnedPolicyButton/Content"));


		// Initialize the column manager for the Blocked Packets ListView
		FirewallColumnManager = new ListViewColumnManager<FirewallEvent>(
		[
			new("TimeCreated", GlobalVars.GetStr("TimeCreatedHeader/Text"), x => x.TimeCreated?.ToString(), useRawHeader: true),
			new("Application", "Application", x => x.Application, useRawHeader: true),
			new("Direction", "Direction", x => x.Direction, useRawHeader: true),
			new("Protocol", "Protocol", x => x.Protocol, useRawHeader: true),
			new("SourceAddress", "Source Address", x => x.SourceAddress, useRawHeader: true),
			new("SourcePort", "Source Port", x => x.SourcePort, useRawHeader: true),
			new("DestAddress", "Destination Address", x => x.DestAddress, useRawHeader: true),
			new("DestPort", "Destination Port", x => x.DestPort, useRawHeader: true),
			new("ProcessId", "Process ID", x => x.ProcessId, useRawHeader: true),
			new("FilterOrigin", "Filter Origin", x => x.FilterOrigin, useRawHeader: true),
			new("UserID", "User ID", x => x.UserID, defaultVisibility: Visibility.Collapsed, useRawHeader: true),
			new("LayerName", "Layer Name", x => x.LayerName, useRawHeader: true),
			new("Interface", "Interface", x => x.Interface, defaultVisibility: Visibility.Collapsed, useRawHeader: true)
		]);

		// To adjust the initial width of the columns for the Firewall Events section, giving them nice paddings.
		FirewallColumnManager.CalculateColumnWidths(BlockedPackets);
	}

	// Unsubscribe when the ViewModel is disposed
	public void Dispose()
	{
		ViewModelProvider.MainWindowVM.SidebarPoliciesLibrary.CollectionChanged -= SidebarPoliciesLibrary_CollectionChanged;

		// Ensure we stop monitoring when navigating away or disposing
		if (IsRealTimeMonitoring)
		{
			GetFirewallLogs.StopRealTimeMonitoring();
		}
	}

	/// <summary>
	/// Event handler for when the Sidebar Library collection changes.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SidebarPoliciesLibrary_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e) =>
			FilterPolicies();

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
	internal string? AppIDTagPolicyName { get; set => SPT(ref field, value); } = "Firewall Policy";

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
		// Ask for user confirmation
		using ContentDialogV2 dialog = new()
		{
			Title = "Restore Firewall Configuration",
			Content = new TextBlock
			{
				Text = "Are you sure you want to restore the default Windows Firewall configurations? This will revert any changes made by the Firewall Sentinel and restore the firewall rules from the backups if they exist.",
				TextWrapping = TextWrapping.Wrap
			},
			PrimaryButtonText = "Restore",
			CloseButtonText = "Cancel",
			DefaultButton = ContentDialogButton.Close
		};

		ContentDialogResult result = await dialog.ShowAsync();

		if (result != ContentDialogResult.Primary)
		{
			return;
		}

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

				DeletePinnedPolicy();
			});

			MainInfoBar.WriteSuccess("Successfully restored the system configurations.");
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
	internal async void ClearBackups()
	{
		try
		{
			// Ask for user confirmation
			using ContentDialogV2 dialog = new()
			{
				Title = "Delete Backups",
				Content = new TextBlock
				{
					Text = "Are you sure you want to delete the firewall backup files? This action cannot be undone. You will lose the ability to revert the firewall rules to their original states.",
					TextWrapping = TextWrapping.Wrap
				},
				PrimaryButtonText = "Delete",
				CloseButtonText = "Cancel",
				DefaultButton = ContentDialogButton.Close
			};

			ContentDialogResult result = await dialog.ShowAsync();

			if (result != ContentDialogResult.Primary)
			{
				return;
			}

			if (Path.Exists(PersistentStoreOriginalFile))
			{
				File.Delete(PersistentStoreOriginalFile);
			}

			if (Path.Exists(GPOStoreOriginalFile))
			{
				File.Delete(GPOStoreOriginalFile);
			}

			MainInfoBar.WriteSuccess("Successfully deleted the firewall rules backup files.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Removes the Pinned App ID Tagging policy from the system and unpins it.
	/// </summary>
	private void DeletePinnedPolicy()
	{
		// If there is a pinned App ID Tagging policy
		if (PinnedPolicy is not null)
		{
			// Get all Base/AppIDTagging policies currently deployed on the system
			List<CiPolicyInfo> currentPolicies = CiToolHelper.GetPolicies(false, true, false);

			string trimmedPolicyID = PinnedPolicy.PolicyID.Trim('"', '{', '}');

			// Make sure the Pinned policy is already deployed on the system
			if (currentPolicies.Any(x => string.Equals(x.PolicyID, trimmedPolicyID, StringComparison.OrdinalIgnoreCase) && x.IsOnDisk))
			{
				// Remove the Pinned App ID Tagging policy from the system
				CiToolHelper.RemovePolicy(trimmedPolicyID);
			}

			// Remove the pinned policy
			_ = Dispatcher.TryEnqueue(() =>
			{
				PinnedPolicy = null;
			});
		}
	}

	internal async void ConfigureFirewallForDefaultWindows(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) => await SetFirewall(mode: 0, sender);
	internal async void ConfigureFirewallForAllowMicrosoft(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) => await SetFirewall(mode: 1, sender);
	internal async void ConfigureFirewallForSignedAndReputable(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) => await SetFirewall(mode: 2, sender);

	/// <summary>
	/// Configures the system and firewall for different modes of App ID Tagging.
	/// </summary>
	/// <param name="mode"></param>
	/// <param name="sender"></param>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	/// <exception cref="ArgumentOutOfRangeException"></exception>
	private async Task SetFirewall(int mode, object sender)
	{
		if (string.IsNullOrWhiteSpace(AppIDTagTouse))
		{
			throw new InvalidOperationException("You need to enter an AppID Tag to use for the deployed policy.");
		}

		// Determine the profile name for the dialog
		string profileName = mode switch
		{
			0 => "Default Windows",
			1 => "Allow Microsoft",
			2 => "Signed & Reputable",
			_ => "Unknown"
		};

		// Ask for user confirmation
		using ContentDialogV2 dialog = new()
		{
			Title = $"Apply {profileName} Profile",
			Content = new TextBlock
			{
				Text = $"Are you sure you want to apply the '{profileName}' profile? This will modify your firewall configurations and system.",
				TextWrapping = TextWrapping.Wrap
			},
			PrimaryButtonText = "Apply",
			CloseButtonText = "Cancel",
			DefaultButton = ContentDialogButton.Close
		};

		ContentDialogResult result = await dialog.ShowAsync();

		if (result != ContentDialogResult.Primary)
		{
			return;
		}

		// Check if a pinned policy exists or backups exist, and warn the user
		bool isPinnedPolicyPresent = PinnedPolicy is not null;
		bool areBackupsPresent = Path.Exists(PersistentStoreOriginalFile) || Path.Exists(GPOStoreOriginalFile);

		if (isPinnedPolicyPresent || areBackupsPresent)
		{
			StringBuilder warningMessage = new();

			if (isPinnedPolicyPresent)
			{
				_ = warningMessage.AppendLine($"• The currently pinned policy '{PinnedPolicy!.PolicyIdentifier}' will be replaced.");
			}

			if (areBackupsPresent)
			{
				_ = warningMessage.AppendLine("• Existing firewall backup files will be overwritten. (You can use the 'Open Backup Location' button and copy the backup files to somewhere else first before proceeding.)");
			}

			_ = warningMessage.AppendLine();
			_ = warningMessage.Append("Do you want to proceed?");

			using ContentDialogV2 overwriteDialog = new()
			{
				Title = "Overwrite Warning",
				Content = new TextBlock
				{
					Text = warningMessage.ToString(),
					TextWrapping = TextWrapping.Wrap
				},
				PrimaryButtonText = "Yes, Overwrite",
				CloseButtonText = "Cancel",
				DefaultButton = ContentDialogButton.Close
			};

			ContentDialogResult overwriteResult = await overwriteDialog.ShowAsync();

			if (overwriteResult != ContentDialogResult.Primary)
			{
				return;
			}
		}

		try
		{
			ElementsAreEnabled = false;

			MainInfoBar.WriteInfo("Configuring the system, please wait");

			await Task.Run(async () =>
			{
				// Remove the pinned policy if deployed
				DeletePinnedPolicy();

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

				MainWindow.TriggerTransferIconAnimationStatic((UIElement)sender);

				// Pin the policy in the UI
				_ = Dispatcher.TryEnqueue(() =>
				{
					PinnedPolicy = policy;
				});

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

	#region Policy Pinning Logic

	/// <summary>
	/// The collection of policies bound to the ComboBox, filtered by the search text.
	/// </summary>
	internal readonly RangedObservableCollection<PolicyFileRepresent> FilteredPolicies = [];

	/// <summary>
	/// The policy selected in the combobox.
	/// </summary>
	internal PolicyFileRepresent? SelectedComboBoxPolicy
	{
		get; set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(IsPinButtonEnabled));
			}
		}
	}

	/// <summary>
	/// The policy currently pinned by the user.
	/// </summary>
	internal PolicyFileRepresent? PinnedPolicy
	{
		get; set
		{
			if (SP(ref field, value))
			{
				// Save the ID of the pinned policy to the settings. If null, empty string will be saved.
				GlobalVars.Settings.FirewallSentinelPinnedPolicyID = value?.PolicyID ?? string.Empty;

				// Update helper properties for UI binding
				OnPropertyChanged(nameof(IsPolicyPinned));
				OnPropertyChanged(nameof(PinnedPolicyVisibility));
				OnPropertyChanged(nameof(PinnedPolicyPlaceholderVisibility));
			}
		}
	}

	/// <summary>
	/// Returns True if a policy is currently pinned.
	/// </summary>
	internal bool IsPolicyPinned => PinnedPolicy is not null;

	/// <summary>
	/// Returns True if a policy is selected in the combobox and can be pinned.
	/// </summary>
	internal bool IsPinButtonEnabled => SelectedComboBoxPolicy is not null;

	/// <summary>
	/// Returns Visible if a policy is pinned, Collapsed otherwise.
	/// </summary>
	internal Visibility PinnedPolicyVisibility => PinnedPolicy is not null ? Visibility.Visible : Visibility.Collapsed;

	/// <summary>
	/// Returns Visible if NO policy is pinned, Collapsed otherwise.
	/// </summary>
	internal Visibility PinnedPolicyPlaceholderVisibility => PinnedPolicy is null ? Visibility.Visible : Visibility.Collapsed;

	/// <summary>
	/// The text used to filter the policies in the ComboBox.
	/// </summary>
	internal string? PolicySearchText
	{
		get; set
		{
			if (SP(ref field, value))
			{
				FilterPolicies();
			}
		}
	}

	/// <summary>
	/// Filters the available policies based on the search text and updates the UI list.
	/// Also attempts to resolve the PinnedPolicy if it's currently null but an ID is saved.
	/// </summary>
	private void FilterPolicies()
	{
		FilteredPolicies.Clear();

		// Access the Sidebar Library directly
		IEnumerable<PolicyFileRepresent> source = ViewModelProvider.MainWindowVM.SidebarPoliciesLibrary.Where(x => x.PolicyObj.PolicyType is PolicyType.AppIDTaggingPolicy);

		IEnumerable<PolicyFileRepresent> results;

		if (string.IsNullOrWhiteSpace(PolicySearchText))
		{
			results = source;
		}
		else
		{
			string term = PolicySearchText.Trim();
			results = source.Where(p =>
				p.PolicyIdentifier.Contains(term, StringComparison.OrdinalIgnoreCase) ||
				p.PolicyID.Contains(term, StringComparison.OrdinalIgnoreCase) ||
				p.PolicyObj.FriendlyName is not null && p.PolicyObj.FriendlyName.Contains(term, StringComparison.OrdinalIgnoreCase)
			);
		}

		FilteredPolicies.AddRange(results);

		// Auto-select the first result in the ComboBox if the user is searching and results exist
		if (!string.IsNullOrWhiteSpace(PolicySearchText) && FilteredPolicies.Count > 0)
		{
			SelectedComboBoxPolicy = FilteredPolicies[0];
		}

		// Try to restore the pinned policy from the library if it hasn't been found yet
		if (PinnedPolicy is null && !string.IsNullOrEmpty(GlobalVars.Settings.FirewallSentinelPinnedPolicyID))
		{
			PolicyFileRepresent? matchedPolicy = source.FirstOrDefault(p =>
				string.Equals(p.PolicyID, GlobalVars.Settings.FirewallSentinelPinnedPolicyID, StringComparison.OrdinalIgnoreCase));

			if (matchedPolicy is not null)
			{
				PinnedPolicy = matchedPolicy;
			}
		}
	}

	/// <summary>
	/// Takes the currently selected item from the ComboBox and pins it.
	/// </summary>
	internal void PinSelectedPolicy()
	{
		if (SelectedComboBoxPolicy is not null)
		{
			PinnedPolicy = SelectedComboBoxPolicy;
		}
	}

	/// <summary>
	/// Clears the currently pinned policy.
	/// </summary>
	internal void ClearPinnedPolicy() => PinnedPolicy = null;

	#endregion


	#region Rule Creation Section


	#region Files and Folders scan

	// A Progress<double> so Report() callbacks run on the UI thread
	internal IProgress<double> FilesAndFoldersProgressRingValueProgress;
	internal double FilesAndFoldersProgressRingValue { get; set => SP(ref field, value); }

	/// <summary>
	/// Whether the Settings Expander for the Files and Folders section is expanded.
	/// </summary>
	internal bool FilesAndFoldersSettingsExpanderIsExpanded { get; set => SP(ref field, value); }

	/// <summary>
	/// Selected File Paths
	/// </summary>
	internal readonly UniqueStringObservableCollection filesAndFoldersFilePaths = [];

	/// <summary>
	/// Selected Folder Paths
	/// </summary>
	internal readonly UniqueStringObservableCollection filesAndFoldersFolderPaths = [];

	/// <summary>
	/// Whether the UI elements for Files and Folders section are enabled or disabled.
	/// </summary>
	internal bool FilesAndFoldersElementsAreEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Whether the policy should be deployed.
	/// </summary>
	internal bool FilesAndFoldersDeployButton { get; set => SP(ref field, value); }

	internal Visibility FilesAndFoldersBrowseForFilesSettingsCardVisibility { get; set => SP(ref field, value); } = Visibility.Visible;

	internal bool FilesAndFoldersInfoBarIsOpen { get; set => SP(ref field, value); }
	internal bool FilesAndFoldersInfoBarIsClosable { get; set => SP(ref field, value); }
	internal string? FilesAndFoldersInfoBarMessage { get; set => SP(ref field, value); }
	internal string? FilesAndFoldersInfoBarTitle { get; set => SP(ref field, value); }
	internal InfoBarSeverity FilesAndFoldersInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;

	private readonly InfoBarSettings FilesAndFoldersInfoBar;

	internal ScanLevelsComboBoxType FilesAndFoldersScanLevelComboBoxSelectedItem
	{
		get; set
		{
			if (SP(ref field, value))
			{
				// For Wildcard file path rules, only folder paths should be used
				FilesAndFoldersBrowseForFilesSettingsCardVisibility = field.Level is ScanLevels.WildCardFolderPath ? Visibility.Collapsed : Visibility.Visible;
			}
		}
	} = DefaultScanLevel;

	internal double FilesAndFoldersScalabilityRadialGaugeValue
	{
		get; set
		{
			if (SP(ref field, value))
			{
				FilesAndFoldersScalabilityButtonContent = GlobalVars.GetStr("Scalability") + field;
			}
		}
	} = 2;

	/// <summary>
	/// The content of the button that has the RadialGauge inside it.
	/// </summary>
	internal string FilesAndFoldersScalabilityButtonContent { get; set => SP(ref field, value); } = GlobalVars.GetStr("Scalability") + "2";

	internal Visibility FilesAndFoldersInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	/// <summary>
	/// Initialization details for the main Create button for the Files and Folders section
	/// </summary>
	internal readonly AnimatedCancellableButtonInitializer FilesAndFoldersCancellableButton;

	/// <summary>
	/// Button to clear the list of selected file paths
	/// </summary>
	internal void FilesAndFoldersBrowseForFilesButton_Flyout_Clear_Click() => filesAndFoldersFilePaths.Clear();

	/// <summary>
	/// Button to clear the list of selected folder paths
	/// </summary>
	internal void FilesAndFoldersBrowseForFoldersButton_Flyout_Clear_Click() => filesAndFoldersFolderPaths.Clear();

	/// <summary>
	/// Browse for Exe Files - Button Click
	/// </summary>
	internal void FilesAndFoldersBrowseForFilesButton_Click()
	{
		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.ExecutablesPickerFilter);

		foreach (string file in CollectionsMarshal.AsSpan(selectedFiles))
		{
			filesAndFoldersFilePaths.Add(file);
		}
	}

	/// <summary>
	/// Browse for Folders - Button Click
	/// </summary>
	internal void FilesAndFoldersBrowseForFoldersButton_Click()
	{
		List<string> selectedDirectories = FileDialogHelper.ShowMultipleDirectoryPickerDialog();

		foreach (string dir in CollectionsMarshal.AsSpan(selectedDirectories))
		{
			filesAndFoldersFolderPaths.Add(dir);
		}
	}

	/// <summary>
	/// Opens a policy editor for files and folders using a specified supplemental policy path.
	/// </summary>
	internal async void OpenInPolicyEditor_FilesAndFolders() => await ViewModelProvider.PolicyEditorVM.OpenInPolicyEditor(PinnedPolicy);

	internal async void OpenInDefaultFileHandler_FilesAndFolders() => await OpenInDefaultFileHandler(PinnedPolicy);

	/// <summary>
	/// Main button's event handler for files and folders rules creation.
	/// </summary>
	internal async void CreateFilesAndFoldersSupplementalPolicyButton_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
	{
		FilesAndFoldersInfoBarActionButtonVisibility = Visibility.Collapsed;

		FilesAndFoldersSettingsExpanderIsExpanded = true;

		// Reset the progress ring from previous runs or in case an error occurred
		FilesAndFoldersProgressRingValue = 0;

		if (PinnedPolicy is null)
		{
			FilesAndFoldersInfoBar.WriteWarning("The Pinned App ID Tagging policy does not exist.");
			return;
		}

		if (filesAndFoldersFilePaths.Count is 0 && filesAndFoldersFolderPaths.Count is 0)
		{
			FilesAndFoldersInfoBar.WriteWarning(GlobalVars.GetStr("NoFilesOrFoldersSelected"), GlobalVars.GetStr("SelectFilesOrFoldersTitle"));
			return;
		}

		// All validation passed - NOW we set button state to indicate operation starting

		bool errorsOccurred = false;

		FilesAndFoldersCancellableButton.Begin();

		try
		{
			FilesAndFoldersElementsAreEnabled = false;

			FilesAndFoldersInfoBar.WriteInfo(string.Format(
				GlobalVars.GetStr("FindingAllAppControlFilesMessage"),
				filesAndFoldersFilePaths.Count,
				filesAndFoldersFolderPaths.Count
			));

			FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

			await Task.Run(async () =>
			{
				IEnumerable<FileIdentity> LocalFilesResults = [];

				// Do the following steps only if Wildcard paths aren't going to be used because then only the selected folder paths are needed
				if (FilesAndFoldersScanLevelComboBoxSelectedItem.Level is not ScanLevels.WildCardFolderPath)
				{
					// Collect all exes only from the user selected directories and files
					(IEnumerable<string>, int) DetectedFilesInSelectedDirectories = FileUtility.GetFilesFast(filesAndFoldersFolderPaths, filesAndFoldersFilePaths, [".exe"], FilesAndFoldersCancellableButton.Cts?.Token);

					// Make sure there are AppControl compatible files
					if (DetectedFilesInSelectedDirectories.Item2 is 0)
					{
						FilesAndFoldersInfoBar.WriteInfo(
							GlobalVars.GetStr("NoCompatibleFilesDetectedSubtitle"),
							GlobalVars.GetStr("NoCompatibleFilesTitle"));

						errorsOccurred = true;
						return;
					}

					FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

					FilesAndFoldersInfoBar.WriteInfo(string.Format(
					GlobalVars.GetStr("ScanningTotalAppControlFilesMessage"),
					DetectedFilesInSelectedDirectories.Item2));

					// Scan all of the detected files from the user selected directories
					LocalFilesResults = LocalFilesScan.Scan(
						DetectedFilesInSelectedDirectories,
						(ushort)FilesAndFoldersScalabilityRadialGaugeValue,
						FilesAndFoldersProgressRingValueProgress,
						FilesAndFoldersCancellableButton.Cts?.Token);

					FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

					FilesAndFoldersInfoBar.WriteInfo(GlobalVars.GetStr("ScanCompletedCreatingSupplementalPolicyMessage"));
				}

				FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: [.. LocalFilesResults], level: FilesAndFoldersScanLevelComboBoxSelectedItem.Level, folderPaths: filesAndFoldersFolderPaths.UniqueItems);

				FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// Create a new SiPolicy object with the data package.
				SiPolicy.SiPolicy policyObj = Master.Initiate(DataPackage, SiPolicyIntel.Authorization.Allow);

				FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// Merge the new supplemental policy with the Pinned App ID Tagging Policy
				PinnedPolicy.PolicyObj = Merger.Merge(PinnedPolicy.PolicyObj, [policyObj]);

				// Assign the created policy to the Sidebar
				ViewModelProvider.MainWindowVM.AssignToSidebar(PinnedPolicy);

				MainWindow.TriggerTransferIconAnimationStatic((UIElement)sender);

				FilesAndFoldersCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// If user selected to deploy the policy
				if (FilesAndFoldersDeployButton)
				{
					FilesAndFoldersInfoBar.WriteInfo(GlobalVars.GetStr("DeployingThePolicy"));

					CiToolHelper.UpdatePolicy(Management.ConvertXMLToBinary(PinnedPolicy.PolicyObj));
				}
			});

		}
		catch (Exception ex)
		{
			HandleExceptions(ex, ref errorsOccurred, ref FilesAndFoldersCancellableButton.wasCancelled, FilesAndFoldersInfoBar, GlobalVars.GetStr("ErrorOccurredCreatingPolicy"));
		}
		finally
		{
			if (FilesAndFoldersCancellableButton.wasCancelled)
			{
				FilesAndFoldersInfoBar.WriteWarning(GlobalVars.GetStr("OperationCancelledByUser"));
			}
			else if (!errorsOccurred)
			{
				FilesAndFoldersInfoBar.WriteSuccess("Successfully updated the Pinned App ID Tagging policy");
				FilesAndFoldersInfoBarActionButtonVisibility = Visibility.Visible;
			}

			FilesAndFoldersCancellableButton.End();

			FilesAndFoldersInfoBarIsClosable = true;

			FilesAndFoldersElementsAreEnabled = true;
		}
	}

	#endregion

	#region Certificates scan

	internal Visibility CertificatesInfoBarActionButtonVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	internal bool CertificatesBasedInfoBarIsOpen { get; set => SP(ref field, value); }
	internal bool CertificatesBasedInfoBarIsClosable { get; set => SP(ref field, value); }
	internal string? CertificatesBasedInfoBarMessage { get; set => SP(ref field, value); }
	internal string? CertificatesBasedInfoBarTitle { get; set => SP(ref field, value); }
	internal InfoBarSeverity CertificatesBasedInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;

	private readonly InfoBarSettings CertificatesBasedInfoBar;

	/// <summary>
	/// Whether the Settings Expander for the Certificates Based section is expanded.
	/// </summary>
	internal bool CertificatesBasedSettingsExpanderIsExpanded { get; set => SP(ref field, value); }

	/// <summary>
	/// Selected Certificate File Paths
	/// </summary>
	internal readonly UniqueStringObservableCollection CertificatesBasedCertFilePaths = [];

	/// <summary>
	/// Whether the policy should be deployed or not.
	/// </summary>
	internal bool CertificatesBasedDeployButton { get; set => SP(ref field, value); }

	/// <summary>
	/// Whether the UI elements for Certificates Based section are enabled or disabled.
	/// </summary>
	internal bool CertificatesBasedElementsAreEnabled { get; set => SP(ref field, value); } = true;

	internal void CertificatesBrowseForCertsButton_Click()
	{
		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.CertificatePickerFilter);

		foreach (string file in CollectionsMarshal.AsSpan(selectedFiles))
		{
			CertificatesBasedCertFilePaths.Add(file);
		}
	}

	/// <summary>
	/// Event handler for the UI to clear the selected certificates file paths.
	/// </summary>
	internal void CertificatesBasedCertFilePaths_Flyout_Clear_Click() => CertificatesBasedCertFilePaths.Clear();

	/// <summary>
	/// Main Button - Creates the Certificates-based Supplemental policy
	/// </summary>
	internal async void CreateCertificatesSupplementalPolicyButton_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
	{
		bool errorsOccurred = false;

		CertificatesBasedSettingsExpanderIsExpanded = true;

		CertificatesInfoBarActionButtonVisibility = Visibility.Collapsed;

		if (PinnedPolicy is null)
		{
			CertificatesBasedInfoBar.WriteWarning("The Pinned App ID Tagging policy does not exist.");
			return;
		}

		if (CertificatesBasedCertFilePaths.Count is 0)
		{
			CertificatesBasedInfoBar.WriteWarning(GlobalVars.GetStr("SelectCertificatesSubtitle"),
				GlobalVars.GetStr("SelectCertificatesTitle"));
			return;
		}

		try
		{
			CertificatesBasedElementsAreEnabled = false;

			CertificatesBasedInfoBar.WriteInfo(string.Format(
				GlobalVars.GetStr("CreatingCertificatesPolicyMessage"),
				CertificatesBasedCertFilePaths.Count
			));

			await Task.Run(() =>
			{
				List<CertificateSignerCreator> certificateResults = [];

				foreach (string certificate in CertificatesBasedCertFilePaths.UniqueItems)
				{
					// Create a certificate object from the .cer file
					using X509Certificate2 CertObject = X509CertificateLoader.LoadCertificateFromFile(certificate);

					// Create rule for the certificate based on the first element in its chain
					certificateResults.Add(new CertificateSignerCreator(
					   CertificateHelper.GetTBSCertificate(CertObject),
						CryptoAPI.GetNameString(CertObject.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false),
						 SiPolicyIntel.SSType.UserMode // Only User Mode for App ID Tagging.
					));
				}

				if (certificateResults.Count == 0)
				{
					CertificatesBasedInfoBar.WriteWarning(GlobalVars.GetStr("NoCertificateDetailsFoundCreatingPolicy"));
					errorsOccurred = true;
					return;
				}

				// Generating signer rules
				SiPolicy.SiPolicy? policyObj = CustomPolicyCreator.CreateEmpty();
				policyObj = NewCertificateSignerRules.CreateAllow(policyObj, certificateResults);

				// Merge the new supplemental policy with the Pinned App ID Tagging Policy
				PinnedPolicy.PolicyObj = Merger.Merge(PinnedPolicy.PolicyObj, [policyObj]);

				// Assign the created policy to the Sidebar
				ViewModelProvider.MainWindowVM.AssignToSidebar(PinnedPolicy);

				MainWindow.TriggerTransferIconAnimationStatic((UIElement)sender);

				// If user selected to deploy the policy
				if (CertificatesBasedDeployButton)
				{
					CertificatesBasedInfoBar.WriteInfo(GlobalVars.GetStr("DeployingThePolicy"));

					CiToolHelper.UpdatePolicy(Management.ConvertXMLToBinary(PinnedPolicy.PolicyObj));
				}
			});
		}
		catch (Exception ex)
		{
			CertificatesBasedInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorOccurredCreatingPolicy"));
			errorsOccurred = true;
		}
		finally
		{
			if (!errorsOccurred)
			{
				CertificatesBasedInfoBar.WriteSuccess("Successfully updated the Pinned App ID Tagging policy");

				CertificatesInfoBarActionButtonVisibility = Visibility.Visible;
			}

			CertificatesBasedElementsAreEnabled = true;

			CertificatesBasedInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Opens a policy editor for Certificates using a specified supplemental policy path.
	/// </summary>
	internal async void OpenInPolicyEditor_Certificates() => await ViewModelProvider.PolicyEditorVM.OpenInPolicyEditor(PinnedPolicy);

	internal async void OpenInDefaultFileHandler_Certificates() => await OpenInDefaultFileHandler(PinnedPolicy);

	#endregion


	#region Custom Pattern-based File Rule

	/// <summary>
	/// Whether the UI elements for the Custom File Path Rules section are enabled or disabled.
	/// </summary>
	internal bool CustomFilePathRulesElementsAreEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Whether the Settings Expander for the Custom File Path Rules section is expanded.
	/// </summary>
	internal bool CustomFilePathRulesSettingsExpanderIsExpanded { get; set => SP(ref field, value); }

	internal Visibility CustomFilePathRulesInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool CustomFilePathRulesInfoBarIsOpen { get; set => SP(ref field, value); }
	internal bool CustomFilePathRulesInfoBarIsClosable { get; set => SP(ref field, value); }
	internal string? CustomFilePathRulesInfoBarMessage { get; set => SP(ref field, value); }
	internal string? CustomFilePathRulesInfoBarTitle { get; set => SP(ref field, value); }
	internal InfoBarSeverity CustomFilePathRulesInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;

	private readonly InfoBarSettings CustomFilePathRulesInfoBar;

	/// <summary>
	/// The custom pattern used for file rule.
	/// </summary>
	internal string? SupplementalPolicyCustomPatternBasedCustomPatternTextBox { get; set => SPT(ref field, value); }

	/// <summary>
	/// Whether the supplemental policy should be deployed at the end.
	/// </summary>
	internal bool CustomPatternBasedFileRuleBasedDeployButton { get; set => SP(ref field, value); }

	/// <summary>
	/// Initialization details for the main Create button for the Pattern Based FileRule section
	/// </summary>
	internal readonly AnimatedCancellableButtonInitializer PatternBasedFileRuleCancellableButton;

	/// <summary>
	/// Event handler for the main button - to create Supplemental pattern based File path policy
	/// </summary>
	internal async void CreateCustomPatternBasedFileRuleSupplementalPolicyButton_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
	{

		CustomFilePathRulesSettingsExpanderIsExpanded = true;

		CustomFilePathRulesInfoBarActionButtonVisibility = Visibility.Collapsed;

		if (PinnedPolicy is null)
		{
			CustomFilePathRulesInfoBar.WriteWarning("The Pinned App ID Tagging policy does not exist.");
			return;
		}

		if (string.IsNullOrWhiteSpace(SupplementalPolicyCustomPatternBasedCustomPatternTextBox))
		{
			CustomFilePathRulesInfoBar.WriteWarning(GlobalVars.GetStr("EnterCustomPatternSubtitle"),
				GlobalVars.GetStr("EnterCustomPatternTitle"));
			return;
		}

		// All validation passed - NOW we set button state to indicate operation starting

		bool errorsOccurred = false;

		PatternBasedFileRuleCancellableButton.Begin();

		try
		{
			CustomFilePathRulesElementsAreEnabled = false;

			CustomFilePathRulesInfoBar.WriteInfo(GlobalVars.GetStr("CreatingPatternBasedFileRuleMessage"));

			CustomFilePathRulesInfoBarIsClosable = false;

			PatternBasedFileRuleCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

			await Task.Run(() =>
			{
				PatternBasedFileRuleCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: null, level: ScanLevels.CustomFileRulePattern, folderPaths: null, customFileRulePatterns: [SupplementalPolicyCustomPatternBasedCustomPatternTextBox]);

				// Create a new SiPolicy object with the data package.
				SiPolicy.SiPolicy policyObj = Master.Initiate(DataPackage, SiPolicyIntel.Authorization.Allow);

				PatternBasedFileRuleCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// Merge the new supplemental policy with the Pinned App ID Tagging Policy
				PinnedPolicy.PolicyObj = Merger.Merge(PinnedPolicy.PolicyObj, [policyObj]);

				// Assign the created policy to the Sidebar
				ViewModelProvider.MainWindowVM.AssignToSidebar(PinnedPolicy);

				MainWindow.TriggerTransferIconAnimationStatic((UIElement)sender);

				PatternBasedFileRuleCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				// If user selected to deploy the policy
				if (CustomPatternBasedFileRuleBasedDeployButton)
				{
					CustomFilePathRulesInfoBar.WriteInfo(GlobalVars.GetStr("DeployingThePolicy"));

					CiToolHelper.UpdatePolicy(Management.ConvertXMLToBinary(PinnedPolicy.PolicyObj));
				}
			});
		}
		catch (Exception ex)
		{
			HandleExceptions(ex, ref errorsOccurred, ref PatternBasedFileRuleCancellableButton.wasCancelled, CustomFilePathRulesInfoBar, GlobalVars.GetStr("ErrorOccurredCreatingPolicy"));
		}
		finally
		{
			if (PatternBasedFileRuleCancellableButton.wasCancelled)
			{
				CustomFilePathRulesInfoBar.WriteWarning(GlobalVars.GetStr("OperationCancelledByUser"));
			}
			else if (!errorsOccurred)
			{
				CustomFilePathRulesInfoBar.WriteSuccess("Successfully updated the Pinned App ID Tagging policy");

				CustomFilePathRulesInfoBarActionButtonVisibility = Visibility.Visible;
			}

			PatternBasedFileRuleCancellableButton.End();

			CustomFilePathRulesElementsAreEnabled = true;

			CustomFilePathRulesInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Event handler to display the content dialog for more info about patterns
	/// </summary>
	internal async void SupplementalPolicyCustomPatternBasedFileRuleSettingsCard_Click()
	{
		// Instantiate the Content Dialog
		CustomUIElements.CustomPatternBasedFilePath customDialog = new();

		GlobalVars.CurrentlyOpenContentDialog = customDialog;

		// Show the dialog
		_ = await customDialog.ShowAsync();
	}

	/// <summary>
	/// Opens a policy editor for CustomPatternBasedFileRule using a specified supplemental policy path.
	/// </summary>
	internal async void OpenInPolicyEditor_CustomPatternBasedFileRule() => await ViewModelProvider.PolicyEditorVM.OpenInPolicyEditor(PinnedPolicy);

	internal async void OpenInDefaultFileHandler_CustomPatternBasedFileRule() => await OpenInDefaultFileHandler(PinnedPolicy);

	#endregion


	#endregion


	#region Blocked Packets Logic

	/// <summary>
	/// The ObservableCollection bound to the ListView in the UI.
	/// </summary>
	internal readonly RangedObservableCollection<FirewallEvent> BlockedPackets = [];

	/// <summary>
	/// Store all outputs for searching/filtering.
	/// </summary>
	internal readonly List<FirewallEvent> AllBlockedPackets = [];

	/// <summary>
	/// Manages columns for the Firewall logs ListView.
	/// </summary>
	internal ListViewColumnManager<FirewallEvent> FirewallColumnManager { get; }

	internal string? BlockedPacketsSearchBoxText
	{
		get; set
		{
			if (SP(ref field, value))
			{
				FilterBlockedPackets();
			}
		}
	}

	/// <summary>
	/// Determines if the destination IP addresses should be resolved to their hostnames during log scanning.
	/// </summary>
	internal bool IsResolveDestinationAddressesEnabled { get; set => SP(ref field, value); }

	internal bool BlockedPacketsScanProgressRingIsActive { get; set => SP(ref field, value); }
	internal Visibility BlockedPacketsScanProgressRingVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool FirewallEventsSectionElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(IsScanLogsButtonEnabled));
			}
		}
	} = true;

	/// <summary>
	/// Controls the enabled state of the Scan Logs button.
	/// Mutually exclusive with Real-Time Monitoring.
	/// </summary>
	internal bool IsScanLogsButtonEnabled => FirewallEventsSectionElementsAreEnabled && !IsRealTimeMonitoring;

	/// <summary>
	/// Fetches the blocked packets logs and updates the UI.
	/// </summary>
	internal async void GetBlockedPacketsLogs_Click()
	{
		try
		{
			FirewallEventsSectionElementsAreEnabled = false;
			BlockedPacketsScanProgressRingVisibility = Visibility.Visible;
			BlockedPacketsScanProgressRingIsActive = true;

			BlockedPackets.Clear();
			AllBlockedPackets.Clear();

			List<FirewallEvent> events = await GetFirewallLogs.GetBlockedPackets(IsResolveDestinationAddressesEnabled);

			AllBlockedPackets.AddRange(events);

			// Apply search filter (if any) and populate the ObservableCollection
			FilterBlockedPackets();

			// Calculate column widths for the newly added data
			FirewallColumnManager.CalculateColumnWidths(BlockedPackets);
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			BlockedPacketsScanProgressRingIsActive = false;
			BlockedPacketsScanProgressRingVisibility = Visibility.Collapsed;
			FirewallEventsSectionElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Filters the blocked packets based on search text.
	/// </summary>
	private void FilterBlockedPackets()
	{
		IEnumerable<FirewallEvent> filtered = AllBlockedPackets;

		if (!string.IsNullOrWhiteSpace(BlockedPacketsSearchBoxText))
		{
			string term = BlockedPacketsSearchBoxText.Trim();
			filtered = filtered.Where(x => IsPacketMatchingFilter(x, term));
		}

		BlockedPackets.Clear();
		BlockedPackets.AddRange(filtered);
	}

	/// <summary>
	/// Checks if a single packet matches the filter term.
	/// </summary>
	/// <param name="x"></param>
	/// <param name="term"></param>
	/// <returns></returns>
	private static bool IsPacketMatchingFilter(FirewallEvent x, string term)
	{
		return (x.Application != null && x.Application.Contains(term, StringComparison.OrdinalIgnoreCase)) ||
			   (x.DestAddress != null && x.DestAddress.Contains(term, StringComparison.OrdinalIgnoreCase)) ||
			   (x.SourceAddress != null && x.SourceAddress.Contains(term, StringComparison.OrdinalIgnoreCase)) ||
			   (x.DestPort != null && x.DestPort.Contains(term, StringComparison.OrdinalIgnoreCase)) ||
			   (x.SourcePort != null && x.SourcePort.Contains(term, StringComparison.OrdinalIgnoreCase)) ||
			   (x.Protocol != null && x.Protocol.Contains(term, StringComparison.OrdinalIgnoreCase)) ||
			   (x.Direction != null && x.Direction.Contains(term, StringComparison.OrdinalIgnoreCase)) ||
			   (x.FilterOrigin != null && x.FilterOrigin.Contains(term, StringComparison.OrdinalIgnoreCase)) ||
			   (x.ProcessId != null && x.ProcessId.Contains(term, StringComparison.OrdinalIgnoreCase));
	}

	/// <summary>
	/// Clears the displayed logs.
	/// </summary>
	internal void ClearBlockedPacketsLogs_Click()
	{
		BlockedPackets.Clear();
		AllBlockedPackets.Clear();
		FirewallColumnManager.CalculateColumnWidths(BlockedPackets);
	}

	internal void BlockedPacketsListView_SelectAll_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.FirewallBlockedLogs);
		ListViewHelper.SelectAll(lv);
	}

	internal void BlockedPacketsListView_DeSelectAll_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.FirewallBlockedLogs);
		lv?.SelectedItems.Clear();
	}

	private static readonly FrozenDictionary<string, (string Label, Func<FirewallEvent, object?> Getter)> FirewallEventsColumnMappings = new Dictionary<string, (string Label, Func<FirewallEvent, object?> Getter)>()
			{
				{ "TimeCreated", (GlobalVars.GetStr("TimeCreatedHeader/Text"), x => x.TimeCreated) },
				{ "Application", ("Application", x => x.Application) },
				{ "Direction", ("Direction", x => x.Direction) },
				{ "Protocol", ("Protocol", x => x.Protocol) },
				{ "SourceAddress", ("Source Address", x => x.SourceAddress) },
				{ "SourcePort", ("Source Port", x => x.SourcePort) },
				{ "DestAddress", ("Destination Address", x => x.DestAddress) },
				{ "DestPort", ("Destination Port", x => x.DestPort) },
				{ "ProcessId", ("Process ID", x => x.ProcessId) },
				{ "FilterOrigin", ("Filter Origin", x => x.FilterOrigin) },
				{ "UserID", ("User ID", x => x.UserID) },
				{ "LayerName", ("Layer Name", x => x.LayerName) },
				{ "Interface", ("Interface", x => x.Interface) }
			}.ToFrozenDictionary();

	internal void BlockedPacketsListViewFlyoutMenuCopy_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.FirewallBlockedLogs);
		if (lv is null) return;

		if (lv.SelectedItems.Count > 0)
		{
			ListViewHelper.ConvertRowToText<FirewallEvent>(lv.SelectedItems, FirewallEventsColumnMappings);
		}
	}

	// Guid for "Filtering Platform Packet Drop" subcategory
	private static readonly Guid PacketDropSubCategoryGuid = new("0CCE9225-69AE-11D9-BED3-505054503030");

	// Guid for "Object Access" category
	private static readonly Guid ObjectAccessCategoryGuid = new("69979848-797A-11D9-BED3-505054503030");

	// Event handler for the UI.
	internal async void EnablePacketDropAuditing_Click() => await EnablePacketDropAuditing();

	/// <summary>
	/// Enables Packet Drop Auditing for Failure events.
	/// </summary>
	private async Task EnablePacketDropAuditing()
	{
		try
		{
			FirewallEventsSectionElementsAreEnabled = false;

			await Task.Run(() =>
			{
				AUDIT_POLICY_INFORMATION auditPolicy = new()
				{
					AuditSubCategoryGuid = PacketDropSubCategoryGuid,
					AuditCategoryGuid = ObjectAccessCategoryGuid,
					// Enable Failure (0x2)
					AuditingInformation = (uint)AuditBitFlags.POLICY_AUDIT_EVENT_FAILURE
				};

				AuditPolicyManager.SetAuditPolicies([auditPolicy]);
			});
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			FirewallEventsSectionElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Disables Packet Drop Auditing.
	/// </summary>
	internal async void DisablePacketDropAuditing_Click()
	{
		try
		{
			FirewallEventsSectionElementsAreEnabled = false;

			await Task.Run(() =>
			{
				AUDIT_POLICY_INFORMATION auditPolicy = new()
				{
					AuditSubCategoryGuid = PacketDropSubCategoryGuid,
					AuditCategoryGuid = ObjectAccessCategoryGuid,
					// Disable all (0x0)
					AuditingInformation = (uint)AuditBitFlags.POLICY_AUDIT_EVENT_NONE
				};

				AuditPolicyManager.SetAuditPolicies([auditPolicy]);
			});
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			FirewallEventsSectionElementsAreEnabled = true;
		}
	}

	#endregion

	#region Real-Time Monitoring

	internal bool IsRealTimeMonitoring
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ToggleRealTimeMonitoringState(value);
				OnPropertyChanged(nameof(IsScanLogsButtonEnabled));
			}
		}
	}

	internal string RealTimeMonitoringButtonText => IsRealTimeMonitoring ? GlobalVars.GetStr("StopLiveMonitor") : GlobalVars.GetStr("StartLiveMonitor");
	internal string RealTimeMonitoringButtonIcon => IsRealTimeMonitoring ? "\uE71A" : "\uE768"; // Stop / Play icons

	/// <summary>
	/// Toggles the Real-Time monitoring state.
	/// </summary>
	/// <param name="enable">True to enable monitoring, false to disable.</param>
	private async void ToggleRealTimeMonitoringState(bool enable)
	{
		try
		{
			if (enable)
			{
				// Make sure auditing is enabled on the system first
				await EnablePacketDropAuditing();

				GetFirewallLogs.StartRealTimeMonitoring(IsResolveDestinationAddressesEnabled, (fwEvent) =>
				{
					_ = Dispatcher.TryEnqueue(() =>
					{
						// Add to the main storage
						AllBlockedPackets.Add(fwEvent);

						// Check if we should display it based on current filter text
						if (string.IsNullOrWhiteSpace(BlockedPacketsSearchBoxText) ||
							IsPacketMatchingFilter(fwEvent, BlockedPacketsSearchBoxText.Trim()))
						{
							// Insert at the top for real-time feed effect
							BlockedPackets.Insert(0, fwEvent);

							FirewallColumnManager.CalculateColumnWidths(BlockedPackets);
						}
					});
				});

			}
			else
			{
				GetFirewallLogs.StopRealTimeMonitoring();
			}

			OnPropertyChanged(nameof(RealTimeMonitoringButtonText));
			OnPropertyChanged(nameof(RealTimeMonitoringButtonIcon));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
			IsRealTimeMonitoring = false; // Revert state on failure
		}
	}

	#endregion
}
