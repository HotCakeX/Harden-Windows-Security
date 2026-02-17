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
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.Others;
using CommonCore.GroupPolicy;
using CommonCore.IncrementalCollection;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;

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

		ComputeColumnWidths();
	}

	/// <summary>
	/// Creates all MUnits for this ViewModel.
	/// </summary>
	private static readonly Lazy<List<MUnit>> LazyCatalog =
		new(() =>
		{
			// Create MUnits from Group Policies.
			List<MUnit> temp = MUnit.CreateMUnitsFromPolicies(Categories.WindowsFirewall);

			#region Create MUnits that are not from Group Policies.

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
					Intent.Business,
					Intent.SpecializedAccessWorkstation,
					Intent.PrivilegedAccessWorkstation
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
					Intent.Business,
					Intent.SpecializedAccessWorkstation,
					Intent.PrivilegedAccessWorkstation
				],

				id: new("019abec8-2702-7fa7-9db2-404dd3647126")
			));

			#endregion

			return temp;

		}, LazyThreadSafetyMode.ExecutionAndPublication);

	/// <summary>
	/// Gets the current catalog of all MUnits for this ViewModel.
	/// </summary>
	public override List<MUnit> AllMUnits => LazyCatalog.Value;

	#region Windows Firewall Management

	/// <summary>
	/// Controls the visibility of the progress ring in the Firewall Management tab.
	/// </summary>
	internal Visibility ManagementProgressVisibility { get; private set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool FirewallDirectionInbound { get; set => SP(ref field, value); }
	internal bool FirewallDirectionOutbound { get; set => SP(ref field, value); }
	internal bool FirewallDirectionBoth { get; set => SP(ref field, value); } = true;

	internal bool FirewallActionAllow { get; set => SP(ref field, value); }
	internal bool FirewallActionBlock { get; set => SP(ref field, value); } = true;

	internal bool FirewallStoreGPO { get; set => SP(ref field, value); } = true;
	internal bool FirewallStorePersistentStore { get; set => SP(ref field, value); }

	/// <summary>
	/// The list of executable files selected by the user for firewall rule management.
	/// </summary>
	internal readonly UniqueStringObservableCollection SelectedFiles = [];

	// Column widths
	internal GridLength FWRuleColWidth1 { get; set => SP(ref field, value); }
	internal GridLength FWRuleColWidth2 { get; set => SP(ref field, value); }
	internal GridLength FWRuleColWidth3 { get; set => SP(ref field, value); }

	/// <summary>
	/// UI Search box value for firewall rules list.
	/// </summary>
	internal string? FirewallRulesSearchText
	{
		get; set
		{
			if (SPT(ref field, value))
			{
				FirewallRulesSearchTextChanged();
			}
		}
	}

	/// <summary>
	/// Compute dynamic column widths.
	/// </summary>
	private void ComputeColumnWidths()
	{
		double w1 = ListViewHelper.MeasureText(GlobalVars.GetStr("NameHeader/Text"));
		double w2 = ListViewHelper.MeasureText(GlobalVars.GetStr("DirectionHeader/Text"));
		double w3 = ListViewHelper.MeasureText(GlobalVars.GetStr("ActionHeader/Text"));

		foreach (FirewallRule v in FirewallRules)
		{
			w1 = ListViewHelper.MeasureText(v.DisplayString, w1);
			w2 = ListViewHelper.MeasureText(v.Direction, w2);
			w3 = ListViewHelper.MeasureText(v.Action, w3);
		}

		FWRuleColWidth1 = new(w1);
		FWRuleColWidth2 = new(w2);
		FWRuleColWidth3 = new(w3);
	}

	internal readonly RangedObservableCollection<FirewallRule> FirewallRules = [];
	private readonly List<FirewallRule> AllFirewallRules = [];

	/// <summary>
	/// Used to keep sort direction and last-sorted column.
	/// </summary>
	private ListViewHelper.SortState SortState { get; set; } = new();

	/// <summary>
	/// Controls whether the UI elements for the Firewall Management tab are enabled or disabled.
	/// </summary>
	internal bool ManagementUIIsEnabled
	{
		get; set
		{
			if (SP(ref field, value))
				ManagementProgressVisibility = value ? Visibility.Collapsed : Visibility.Visible;
		}
	} = true;

	/// <summary>
	/// Event handler to prevent the MenuFlyout to automatically close immediately after selecting a checkbox or any button in it
	/// </summary>
	internal void MenuFlyout_Closing(FlyoutBase sender, FlyoutBaseClosingEventArgs args)
	{
		if (sender is MenuFlyoutV2 { IsPointerOver: true })
		{
			args.Cancel = true;
		}
	}

	/// <summary>
	/// Event handler for the UI button to select files.
	/// </summary>
	internal async void SelectFiles()
	{
		try
		{
			ManagementUIIsEnabled = false;

			List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.ExecutablesPickerFilter);

			if (selectedFiles.Count > 0)
			{
				foreach (string item in CollectionsMarshal.AsSpan(selectedFiles))
				{
					SelectedFiles.Add(item);
				}
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ManagementUIIsEnabled = true;
		}
	}

	/// <summary>
	/// Event handler for the UI button to select folders.
	/// </summary>
	internal async void SelectFolders()
	{
		try
		{
			ManagementUIIsEnabled = false;

			List<string> selectedDirectories = FileDialogHelper.ShowMultipleDirectoryPickerDialog();

			if (selectedDirectories.Count == 0)
				return;

			await Task.Run(() =>
			{
				// Get all of the .exe files in the folders user selected.
				(IEnumerable<string>, int) detectedCatFiles = FileUtility.GetFilesFast(selectedDirectories, null, [".exe"]);

				_ = Dispatcher.TryEnqueue(() =>
				{
					foreach (string item in detectedCatFiles.Item1)
					{
						SelectedFiles.Add(item);
					}
				});

				MainInfoBar.WriteInfo($"Detected {detectedCatFiles.Item2} executable files in the folders you selected.");
			});
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ManagementUIIsEnabled = true;
			MainInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Clears the list of selected files.
	/// </summary>
	internal void ClearSelectedFiles() => SelectedFiles.Clear();

	/// <summary>
	/// Event handler for the UI button to create firewall rules for the selected files.
	/// </summary>
	internal async void CreateFirewallRules()
	{
		try
		{
			ManagementUIIsEnabled = false;

			if (SelectedFiles.Count == 0)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("WindowsFirewallNoFilesSelectedWarningMessage"));
				return;
			}

			await Task.Run(() =>
			{
				foreach (string file in SelectedFiles)
				{
					string ruleNameInbound = $"{(FirewallActionBlock ? "Blocking" : "Allowing")}-{file}-Inbound";
					string ruleNameOutbound = $"{(FirewallActionBlock ? "Blocking" : "Allowing")}-{file}-Outbound";

					string action = FirewallActionBlock ? "block" : "allow";
					string store = FirewallStoreGPO ? "localhost" : "PersistentStore";

					MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("WindowsFirewallCreateRuleForMessage"), file));

					if (FirewallDirectionInbound)
					{
						Logger.Write(QuantumRelayHSS.Client.RunCommand(GlobalVars.ComManagerProcessPath, $"""firewallprogram "{ruleNameInbound}" inbound {action} "{ruleNameInbound}" --program "{file}" --store "{store}" """));
					}
					else if (FirewallDirectionOutbound)
					{
						Logger.Write(QuantumRelayHSS.Client.RunCommand(GlobalVars.ComManagerProcessPath, $"""firewallprogram "{ruleNameOutbound}" outbound {action} "{ruleNameOutbound}" --program "{file}" --store "{store}" """));
					}
					else if (FirewallDirectionBoth)
					{
						Logger.Write(QuantumRelayHSS.Client.RunCommand(GlobalVars.ComManagerProcessPath, $"""firewallprogram "{ruleNameInbound}" inbound {action} "{ruleNameInbound}" --program "{file}" --store "{store}" """));
						Logger.Write(QuantumRelayHSS.Client.RunCommand(GlobalVars.ComManagerProcessPath, $"""firewallprogram "{ruleNameOutbound}" outbound {action} "{ruleNameOutbound}" --program "{file}" --store "{store}" """));
					}
				}

				// Update policies to take effect immediately
				CSEMgr.RegisterCSEGuids();
			});

			await RetrieveFirewallRules_internal();

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("WindowsFirewallRulesCreatedSuccessMessage"), SelectedFiles.Count));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ManagementUIIsEnabled = true;
		}
	}

	/// <summary>
	/// List of Dual-Use programs that could be used maliciously.
	/// </summary>
	private static readonly List<string> DualUsePrograms =
	[
		@"C:\Windows\System32\bitsadmin.exe",
		@"C:\Windows\System32\certreq.exe",
		@"C:\Windows\System32\certutil.exe",
		@"C:\Windows\System32\cmstp.exe",
		@"C:\Windows\System32\cmd.exe",
		@"C:\Windows\System32\cscript.exe",
		@"C:\Windows\System32\forfiles.exe",
		@"C:\Windows\hh.exe",
		@"C:\Windows\System32\mshta.exe",
		@"C:\Windows\System32\msiexec.exe",
		@"C:\Windows\System32\netsh.exe",
		@"C:\Windows\System32\presentationhost.exe",
		@"C:\Windows\System32\reg.exe",
		@"C:\Windows\System32\regsvr32.exe",
		@"C:\Windows\System32\rundll32.exe",
		@"C:\Windows\System32\schtasks.exe",
		@"C:\Windows\System32\wscript.exe",
		@"C:\Windows\System32\wmic.exe",
		@"C:\Windows\System32\xwizard.exe",
		@"C:\Windows\SysWOW64\bitsadmin.exe",
		@"C:\Windows\SysWOW64\certreq.exe",
		@"C:\Windows\SysWOW64\certutil.exe",
		@"C:\Windows\SysWOW64\cmstp.exe",
		@"C:\Windows\SysWOW64\cmd.exe",
		@"C:\Windows\SysWOW64\cscript.exe",
		@"C:\Windows\SysWOW64\forfiles.exe",
		@"C:\Windows\SysWOW64\hh.exe",
		@"C:\Windows\SysWOW64\mshta.exe",
		@"C:\Windows\SysWOW64\msiexec.exe",
		@"C:\Windows\SysWOW64\netsh.exe",
		@"C:\Windows\SysWOW64\presentationhost.exe",
		@"C:\Windows\SysWOW64\reg.exe",
		@"C:\Windows\SysWOW64\regsvr32.exe",
		@"C:\Windows\SysWOW64\rundll32.exe",
		@"C:\Windows\SysWOW64\schtasks.exe",
		@"C:\Windows\SysWOW64\wscript.exe",
		@"C:\Windows\SysWOW64\wmic.exe",
		@"C:\Windows\SysWOW64\xwizard.exe",
		@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
	];

	/// <summary>
	/// Event handler for the UI button to block dual-use binaries in the firewall.
	/// </summary>
	internal async void BlockDualUseBinariesInFirewall()
	{
		try
		{
			ManagementUIIsEnabled = false;

			await Task.Run(() =>
			{
				foreach (string file in CollectionsMarshal.AsSpan(DualUsePrograms))
				{
					string ruleNameInbound = $"BlockingDualUseProgram-{file}-Inbound";
					string ruleNameOutbound = $"BlockingDualUseProgram-{file}-Outbound";

					MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("WindowsFirewallCreateRuleForMessage"), file));

					Logger.Write(QuantumRelayHSS.Client.RunCommand(GlobalVars.ComManagerProcessPath, $"""firewallprogram "{ruleNameInbound}" inbound block "{ruleNameInbound}" --program "{file}" """));
					Logger.Write(QuantumRelayHSS.Client.RunCommand(GlobalVars.ComManagerProcessPath, $"""firewallprogram "{ruleNameOutbound}" outbound block "{ruleNameOutbound}" --program "{file}" """));
				}

				// Update policies to take effect immediately
				CSEMgr.RegisterCSEGuids();
			});

			await RetrieveFirewallRules_internal();

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("WindowsFirewallRulesCreatedSuccessMessage"), DualUsePrograms.Count));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ManagementUIIsEnabled = true;
		}
	}

	/// <summary>
	/// Event handler for the button that retrieves all of the Firewall rules made by Harden System Security app.
	/// </summary>
	internal async void RetrieveFirewallRules() => await RetrieveFirewallRules_internal();

	/// <summary>
	/// Retrieve the Firewall rules managed by the app.
	/// </summary>
	private async Task RetrieveFirewallRules_internal()
	{
		try
		{
			ManagementUIIsEnabled = false;

			// Clear current data so repeated retrieval doesn't duplicate rows.
			ClearFirewallRulesListInternal();

			List<FirewallRule>? firewallRules = null;

			await Task.Run(() =>
			{
				string rulesOutput = QuantumRelayHSS.Client.RunCommand(GlobalVars.ComManagerProcessPath, "firewallprogramlist");

				firewallRules = JsonSerializer.Deserialize(rulesOutput, FirewallRuleJSONContext.Default.ListFirewallRule);
			});

			if (firewallRules is not null)
			{
				FirewallRules.AddRange(firewallRules);
				AllFirewallRules.AddRange(firewallRules);

				ComputeColumnWidths();

				MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyRetrievedFirewallRulesMessage"), FirewallRules.Count));
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ManagementUIIsEnabled = true;
		}
	}

	/// <summary>
	/// Deletes a Firewall rule using rule Name.
	/// </summary>
	private static void DeleteFirewallRule(string ruleName)
	{
		Logger.Write(QuantumRelayHSS.Client.RunCommand(GlobalVars.ComManagerProcessPath, $"""firewalldelete "{ruleName}" """));
	}

	#region Search

	/// <summary>
	/// Search callback for firewall rules.
	/// </summary>
	private void FirewallRulesSearchTextChanged()
	{
		string? searchTerm = FirewallRulesSearchText?.Trim();
		if (searchTerm is null)
		{
			return;
		}

		ScrollViewer? sv = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.Firewall_Management);

		double? savedHorizontal = null;
		if (sv is not null)
		{
			savedHorizontal = sv.HorizontalOffset;
		}

		List<FirewallRule> filteredResults = [];
		foreach (FirewallRule rule in CollectionsMarshal.AsSpan(AllFirewallRules))
		{
			if (rule.DisplayString.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				rule.Direction.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				rule.Action.Contains(searchTerm, StringComparison.OrdinalIgnoreCase))
			{
				filteredResults.Add(rule);
			}
		}

		FirewallRules.Clear();
		FirewallRules.AddRange(filteredResults);

		ComputeColumnWidths();

		if (sv is not null && savedHorizontal.HasValue)
		{
			_ = sv.ChangeView(savedHorizontal, null, null, disableAnimation: false);
		}
	}

	#endregion

	#region Sort

	/// <summary>
	/// Mapping of sortable / copyable fields for FirewallRule.
	/// </summary>
	private static readonly FrozenDictionary<string, (string Label, Func<FirewallRule, object?> Getter)> _firewallRuleMappings =
		new Dictionary<string, (string Label, Func<FirewallRule, object?> Getter)>(StringComparer.OrdinalIgnoreCase)
		{
			{ "DisplayString", (GlobalVars.GetStr("NameHeader/Text"),      r => r.DisplayString) },
			{ "Direction",    (GlobalVars.GetStr("DirectionHeader/Text"), r => r.Direction) },
			{ "Action",       (GlobalVars.GetStr("ActionHeader/Text"),    r => r.Action) }
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	/// <summary>
	/// Column sorting handler for the Firewall rules ListView header buttons.
	/// </summary>
	internal void HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			if (_firewallRuleMappings.TryGetValue(key, out (string Label, Func<FirewallRule, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					mapping.Getter,
					FirewallRulesSearchText,
					AllFirewallRules,
					FirewallRules,
					SortState,
					key,
					regKey: ListViewHelper.ListViewsRegistry.Firewall_Management);
			}
		}
	}

	#endregion

	#region Copy

	/// <summary>
	/// Converts selected FirewallRule rows to text.
	/// </summary>
	internal void CopySelectedFirewallRules_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Firewall_Management);
		if (lv is null) return;

		if (lv.SelectedItems.Count > 0)
		{
			ListViewHelper.ConvertRowToText(lv.SelectedItems, _firewallRuleMappings);
		}
	}

	/// <summary>
	/// Copy a single property of the current selection.
	/// </summary>
	internal void CopyFirewallRuleProperty_Click(object sender, RoutedEventArgs e)
	{
		MenuFlyoutItem menuItem = (MenuFlyoutItem)sender;
		string key = (string)menuItem.Tag;

		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Firewall_Management);
		if (lv is null) return;

		if (_firewallRuleMappings.TryGetValue(key, out (string Label, Func<FirewallRule, object?> Getter) map))
		{
			ListViewHelper.CopyToClipboard<FirewallRule>(ci => map.Getter(ci)?.ToString(), lv);
		}
	}

	#endregion

	#region Delete

	/// <summary>
	/// Deletes the selected firewall rules (uses rule.Name, not DisplayString), then refreshes.
	/// </summary>
	internal async void DeleteSelectedFirewallRules_Click(object sender, RoutedEventArgs e)
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Firewall_Management);

		if (lv is null || lv.SelectedItems.Count == 0)
		{
			MainInfoBar.WriteWarning("No firewall rules selected for deletion.");
			return;
		}

		try
		{
			ManagementUIIsEnabled = false;
			MainInfoBarIsClosable = false;

			List<FirewallRule> rulesToDelete = [];
			foreach (object item in lv.SelectedItems)
			{
				if (item is FirewallRule rule)
				{
					rulesToDelete.Add(rule);
				}
			}

			if (rulesToDelete.Count == 0)
			{
				MainInfoBar.WriteWarning("No firewall rules selected for deletion.");
				return;
			}

			await Task.Run(() =>
			{
				foreach (FirewallRule rule in CollectionsMarshal.AsSpan(rulesToDelete))
				{
					DeleteFirewallRule(rule.Name);
				}

				// Update policies to take effect immediately
				CSEMgr.RegisterCSEGuids();
			});

			await RetrieveFirewallRules_internal();

			MainInfoBar.WriteSuccess($"Successfully deleted {rulesToDelete.Count} firewall rules.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			MainInfoBarIsClosable = true;
			ManagementUIIsEnabled = true;
		}
	}

	#endregion

	#region Helpers

	/// <summary>
	/// Clears firewall rules collection and resets search text.
	/// </summary>
	private void ClearFirewallRulesListInternal()
	{
		FirewallRules.Clear();
		AllFirewallRules.Clear();
		FirewallRulesSearchText = null;
		ComputeColumnWidths();
	}

	#endregion

	/// <summary>
	/// Event handler for the UI to export Local Firewall rules.
	/// </summary>
	internal async void ExportLocalFirewallRules() => await ExportFirewallRules(false);

	/// <summary>
	/// Event handler for the UI to export GPO-defined Firewall rules.
	/// </summary>
	internal async void ExportGPOFirewallRules() => await ExportFirewallRules(true);

	/// <summary>
	/// Helper to Export Firewall rules from different stores.
	/// </summary>
	/// <param name="isGpo">If true, exports GPO-defined rules. If false, exports local Firewall rules.</param>
	/// <returns></returns>
	private async Task ExportFirewallRules(bool isGpo)
	{
		try
		{
			ManagementUIIsEnabled = false;
			MainInfoBarIsClosable = false;

			string defaultFileName = isGpo ? "GPO_Firewall_Rules.wfw" : "Local_Firewall_Rules.wfw";

			string? saveLocation = FileDialogHelper.ShowSaveFileDialog(
				"Windows Firewall Policy|*.wfw", defaultFileName);

			if (string.IsNullOrEmpty(saveLocation))
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("OperationCancelledMsg"));
				return;
			}

			await Task.Run(() => Firewall.ExportFirewallPolicy(saveLocation, isGpo));

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("FirewallExportSuccess"), isGpo ? "GPO" : "Local", saveLocation));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ManagementUIIsEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Imports local firewall rules.
	/// </summary>
	internal async void ImportLocalFirewallRules() => await ImportFirewallRules(false);

	/// <summary>
	/// Imports GPO firewall rules.
	/// </summary>
	internal async void ImportGPOFirewallRules() => await ImportFirewallRules(true);

	/// <summary>
	/// Imports firewall rules to different stores.
	/// </summary>
	/// <param name="isGpo"></param>
	/// <returns></returns>
	private async Task ImportFirewallRules(bool isGpo)
	{
		try
		{
			ManagementUIIsEnabled = false;
			MainInfoBarIsClosable = false;

			string? fileLocation = FileDialogHelper.ShowFilePickerDialog("Windows Firewall Policy|*.wfw");

			if (string.IsNullOrEmpty(fileLocation))
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("OperationCancelledMsg"));
				return;
			}

			using AppControlManager.CustomUIElements.ContentDialogV2 dialog = new()
			{
				Title = isGpo ? GlobalVars.GetStr("ImportGPOFirewallRulesTitle") : GlobalVars.GetStr("ImportLocalFirewallRulesTitle"),
				Content = string.Format(GlobalVars.GetStr("ImportFirewallRulesWarning"), Path.GetFileName(fileLocation)),
				CloseButtonText = GlobalVars.GetStr("Cancel"),
				PrimaryButtonText = GlobalVars.GetStr("ImportButtonText"),
				DefaultButton = ContentDialogButton.Close,
				Style = (Style)Application.Current.Resources["DefaultContentDialogStyle"],
				FlowDirection = Enum.Parse<FlowDirection>(AppSettings.ApplicationGlobalFlowDirection)
			};

			ContentDialogResult result = await dialog.ShowAsync();

			if (result is not ContentDialogResult.Primary)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("OperationCancelledMsg"));
				return;
			}

			await Task.Run(() => Firewall.ImportFirewallPolicy(fileLocation, isGpo));

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("FirewallImportSuccess"), isGpo ? "GPO" : "Local"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ManagementUIIsEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Restores default Firewall rules for the local store.
	/// </summary>
	internal async void RestoreDefaultFirewallRules()
	{
		try
		{
			ManagementUIIsEnabled = false;
			MainInfoBarIsClosable = false;

			using AppControlManager.CustomUIElements.ContentDialogV2 dialog = new()
			{
				Title = GlobalVars.GetStr("RestoreLocalFirewallRulesTitle"),
				Content = GlobalVars.GetStr("RestoreLocalFirewallRulesWarning"),
				CloseButtonText = GlobalVars.GetStr("Cancel"),
				PrimaryButtonText = GlobalVars.GetStr("RestoreDefaultsButtonText"),
				DefaultButton = ContentDialogButton.Close,
				Style = (Style)Application.Current.Resources["DefaultContentDialogStyle"],
				FlowDirection = Enum.Parse<FlowDirection>(AppSettings.ApplicationGlobalFlowDirection)
			};

			ContentDialogResult result = await dialog.ShowAsync();

			if (result is not ContentDialogResult.Primary)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("OperationCancelledMsg"));
				return;
			}

			await Task.Run(Firewall.RestoreDefaultFirewallPolicy);

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("FirewallRestoreSuccess"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ManagementUIIsEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Deletes all Firewall rules from the Local store.
	/// </summary>
	internal async void DeleteAllLocalFirewallRules()
	{
		try
		{
			ManagementUIIsEnabled = false;
			MainInfoBarIsClosable = false;

			using AppControlManager.CustomUIElements.ContentDialogV2 dialog = new()
			{
				Title = GlobalVars.GetStr("DeleteAllLocalFirewallRulesTitle"),
				Content = GlobalVars.GetStr("DeleteAllLocalFirewallRulesWarning"),
				CloseButtonText = GlobalVars.GetStr("Cancel"),
				PrimaryButtonText = GlobalVars.GetStr("DeleteAllButtonText"),
				DefaultButton = ContentDialogButton.Close,
				Style = (Style)Application.Current.Resources["DefaultContentDialogStyle"],
				FlowDirection = Enum.Parse<FlowDirection>(AppSettings.ApplicationGlobalFlowDirection)
			};

			ContentDialogResult result = await dialog.ShowAsync();

			if (result is not ContentDialogResult.Primary)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("OperationCancelledMsg"));
				return;
			}

			await Task.Run(() => Firewall.DeleteAllFirewallRules(FW_STORE_TYPE.LOCAL));

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("FirewallDeleteSuccess"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ManagementUIIsEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Deletes all Firewall rules from the GPO store.
	/// </summary>
	internal async void DeleteAllGPOFirewallRules()
	{
		try
		{
			ManagementUIIsEnabled = false;
			MainInfoBarIsClosable = false;

			using AppControlManager.CustomUIElements.ContentDialogV2 dialog = new()
			{
				Title = GlobalVars.GetStr("DeleteAllGPOFirewallRulesTitle"),
				Content = GlobalVars.GetStr("DeleteAllGPOFirewallRulesWarning"),
				CloseButtonText = GlobalVars.GetStr("Cancel"),
				PrimaryButtonText = GlobalVars.GetStr("DeleteAllButtonText"),
				DefaultButton = ContentDialogButton.Close,
				Style = (Style)Application.Current.Resources["DefaultContentDialogStyle"],
				FlowDirection = Enum.Parse<FlowDirection>(AppSettings.ApplicationGlobalFlowDirection)
			};

			ContentDialogResult result = await dialog.ShowAsync();

			if (result is not ContentDialogResult.Primary)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("OperationCancelledMsg"));
				return;
			}

			await Task.Run(() => Firewall.DeleteAllFirewallRules(FW_STORE_TYPE.GPO));

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("FirewallDeleteSuccess"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ManagementUIIsEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	#endregion
}
