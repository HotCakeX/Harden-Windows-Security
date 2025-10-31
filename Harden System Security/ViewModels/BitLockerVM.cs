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
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.Others;
using HardenSystemSecurity.BitLocker;
using HardenSystemSecurity.CustomUIElements;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class BitLockerVM : MUnitListViewModelBase
{
	[SetsRequiredMembers]
	internal BitLockerVM()
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
			return MUnit.CreateMUnitsFromPolicies(Categories.BitLockerSettings);
		}, LazyThreadSafetyMode.ExecutionAndPublication);

	/// <summary>
	/// Gets the current catalog of all MUnits for this ViewModel.
	/// </summary>
	public override List<MUnit> AllMUnits => LazyCatalog.Value;

	/// <summary>
	/// This is used to apply the BitLocker category before enabling BitLocker encryption for any drive.
	/// Ensures the correct policies are in place in order to use enhanced security features of BitLocker.
	/// </summary>
	/// <param name="cancellationToken"></param>
	/// <returns></returns>
	private async Task ApplyAllBitLockerSecurityMeasuresAsync(CancellationToken? cancellationToken = null)
	{
		bool errorsOccurred = false;
		ApplyAllCancellableButton.Begin();
		try
		{
			ElementsAreEnabled = false;
			MainInfoBar.WriteInfo("Applying all BitLocker security measures...");

			// Use the full unfiltered backing list so search filters do not hide items from processing
			List<MUnit> allMUnits = [];
			foreach (GroupInfoListForMUnit group in ListViewItemsSourceBackingField)
			{
				allMUnits.AddRange(group);
			}

			await MUnit.ProcessMUnitsWithBulkOperations(this, allMUnits, MUnitOperation.Apply, cancellationToken);
		}
		catch (Exception ex)
		{
			HandleExceptions(ex, ref errorsOccurred, ref ApplyAllCancellableButton.wasCancelled, MainInfoBar);
		}
		finally
		{
			if (ApplyAllCancellableButton.wasCancelled)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("ApplyOperationCancelledByUser"));
			}
			else if (!errorsOccurred)
			{
				MainInfoBar.WriteSuccess("Successfully applied all BitLocker security measures");
			}

			ApplyAllCancellableButton.End();
			ElementsAreEnabled = true;
		}
	}

	#region BITLOCKER Management

	internal readonly ObservableCollection<BitLockerVolume> BitLockerVolumes = [];
	private readonly List<BitLockerVolume> AllBitLockerVolumes = [];

	internal bool BitLockerUiEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				BitLockerProgressVisibility = value ? Visibility.Collapsed : Visibility.Visible;

				// Keep the other specific enablement controls in sync with the main one.
				IsSuspendFeatureEnabled = BitLockerUiEnabled;
			}
		}
	} = true;

	internal Visibility BitLockerProgressVisibility { get; private set => SP(ref field, value); } = Visibility.Collapsed;

	internal string? BitLockerSearchText
	{
		get; set
		{
			if (SPT(ref field, value))
			{
				SearchBox_TextChanged();
			}
		}
	}

	// Column widths
	internal GridLength BLColWidth1 { get; set => SP(ref field, value); }
	internal GridLength BLColWidth2 { get; set => SP(ref field, value); }
	internal GridLength BLColWidth3 { get; set => SP(ref field, value); }
	internal GridLength BLColWidth4 { get; set => SP(ref field, value); }
	internal GridLength BLColWidth5 { get; set => SP(ref field, value); }
	internal GridLength BLColWidth6 { get; set => SP(ref field, value); }
	internal GridLength BLColWidth7 { get; set => SP(ref field, value); }
	internal GridLength BLColWidth8 { get; set => SP(ref field, value); }
	internal GridLength BLColWidth9 { get; set => SP(ref field, value); }
	internal GridLength BLColWidth10 { get; set => SP(ref field, value); }
	internal GridLength BLColWidth11 { get; set => SP(ref field, value); }
	internal GridLength BLColWidth12 { get; set => SP(ref field, value); }

	/// <summary>
	/// Selected BitLocker volume.
	/// </summary>
	internal BitLockerVolume? SelectedBitLockerVolume
	{
		get; set
		{
			if (SP(ref field, value))
			{
				// Update dependent computed properties used for visibility in the details pane.
				OnPropertyChanged(nameof(NoSelectionVisibility));
				OnPropertyChanged(nameof(NoProtectorsVisibility));
				OnPropertyChanged(nameof(HasProtectorsVisibility));

				// Only enable the Suspend feature if OS drive is selected.
				IsSuspendFeatureEnabled = SelectedBitLockerVolume?.VolumeType is VolumeType.OperationSystem;
			}
		}
	}

	/// <summary>
	/// Indicates whether the overlay SplitView pane is open.
	/// </summary>
	internal bool IsBitLockerDetailsPaneOpen { get; set => SP(ref field, value); }

	/// <summary>
	/// Whether the Suspend feature is enabled.
	/// </summary>
	internal bool IsSuspendFeatureEnabled { get; set => SP(ref field, value); }

	/// <summary>
	/// Closes the sidebar pane.
	/// </summary>
	internal void CloseBitLockerDetailsPane()
	{
		IsBitLockerDetailsPaneOpen = false;
	}

	internal Visibility NoSelectionVisibility => SelectedBitLockerVolume is null ? Visibility.Visible : Visibility.Collapsed;

	internal Visibility NoProtectorsVisibility =>
		SelectedBitLockerVolume is not null &&
		(SelectedBitLockerVolume.KeyProtectors is null || SelectedBitLockerVolume.KeyProtectors.Count == 0)
			? Visibility.Visible
			: Visibility.Collapsed;

	internal Visibility HasProtectorsVisibility =>
		SelectedBitLockerVolume is not null &&
		SelectedBitLockerVolume.KeyProtectors is not null &&
		SelectedBitLockerVolume.KeyProtectors.Count > 0
			? Visibility.Visible
			: Visibility.Collapsed;

	/// <summary>
	/// Mapping of sortable / copyable fields.
	/// </summary>
	private static readonly FrozenDictionary<string, (string Label, Func<BitLockerVolume, object?> Getter)> _volumeMappings =
		new Dictionary<string, (string Label, Func<BitLockerVolume, object?> Getter)>(StringComparer.OrdinalIgnoreCase)
		{
			{ "MountPoint",           (GlobalVars.GetStr("MountPointHeader/Text"),           v => v.MountPoint) },
			{ "ProtectionStatus",     (GlobalVars.GetStr("ProtectionStatusHeader/Text"),     v => v.ProtectionStatus) },
			{ "ConversionStatus",     (GlobalVars.GetStr("ConversionStatusHeader/Text"),     v => v.ConversionStatus) },
			{ "EncryptionMethod",     (GlobalVars.GetStr("EncryptionMethodHeader/Text"),     v => v.EncryptionMethod) },
			{ "EncryptionPercentage", (GlobalVars.GetStr("EncryptionPercentageHeader/Text"), v => v.EncryptionPercentage) },
			{ "WipePercentage",       (GlobalVars.GetStr("WipePercentageHeader/Text"),       v => v.WipePercentage) },
			{ "AutoUnlockEnabled",    (GlobalVars.GetStr("AutoUnlockEnabledHeader/Text"),    v => v.AutoUnlockEnabled) },
			{ "AutoUnlockKeyStored",  (GlobalVars.GetStr("AutoUnlockKeyStoredHeader/Text"),  v => v.AutoUnlockKeyStored) },
			{ "VolumeType",           (GlobalVars.GetStr("VolumeTypeHeader/Text"),           v => v.VolumeType) },
			{ "CapacityGB",           (GlobalVars.GetStr("CapacityGBHeader/Text"),           v => v.CapacityGB) },
			{ "FileSystemType",       (GlobalVars.GetStr("FileSystemTypeHeader/Text"),       v => v.FileSystemType) },
			{ "FriendlyName",         (GlobalVars.GetStr("FriendlyNameHeader/Text"),         v => v.FriendlyName) }
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	/// <summary>
	/// Property mappings for KeyProtector used for clipboard operations
	/// </summary>
	private static readonly FrozenDictionary<string, (string Label, Func<KeyProtector, object?> Getter)> KeyProtectorPropertyMappings =
		new Dictionary<string, (string Label, Func<KeyProtector, object?> Getter)>(StringComparer.OrdinalIgnoreCase)
		{
			["Type"] = (GlobalVars.GetStr("Type/Text"), kp => kp.Type),
			["ID"] = (GlobalVars.GetStr("ID/Text"), kp => kp.ID),
			["AutoUnlock"] = (GlobalVars.GetStr("AutoUnlock/Text"), kp => kp.AutoUnlockProtector),
			["KeyFileName"] = (GlobalVars.GetStr("FileName/Text"), kp => kp.KeyFileName),
			["RecoveryPassword"] = (GlobalVars.GetStr("RecoveryPassword/Text"), kp => kp.RecoveryPassword),
			["KeyCertificateType"] = (GlobalVars.GetStr("CertificateType/Text"), kp => kp.KeyCertificateType),
			["Thumbprint"] = (GlobalVars.GetStr("Thumbprint/Text"), kp => kp.Thumbprint)
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	/// <summary>
	/// Retrieve volumes.
	/// </summary>
	internal async void RetrieveBitLockerVolumes()
	{
		try
		{
			BitLockerUiEnabled = false;
			MainInfoBarIsClosable = false;

			MainInfoBar.WriteInfo(GlobalVars.GetStr("RetrievingBitLockerVolumesEllipsis"));

			await GetVolumes();

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("LoadedBitLockerVolumesCount"), BitLockerVolumes.Count));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			BitLockerUiEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	private async Task GetVolumes()
	{
		// Clear any prior selection/state.
		SelectedBitLockerVolume = null;
		IsBitLockerDetailsPaneOpen = false;

		ClearBitLockerVolumes();

		BitLockerVolume[] volumes = await Task.Run(() =>
		{
			const string command = "bitlocker list all";
			string result = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, command)
				?? throw new InvalidOperationException(string.Format(GlobalVars.GetStr("NoOutputReturnedFromPath"), GlobalVars.ComManagerProcessPath));
			return JsonSerializer.Deserialize(result, BitLockerJsonContext.Default.BitLockerVolumeArray)!;
		});

		if (volumes.Length == 0)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("NoBitLockerVolumesDetected"));
			return;
		}

		foreach (BitLockerVolume v in volumes)
		{
			BitLockerVolumes.Add(v);
		}

		AllBitLockerVolumes.Clear();
		AllBitLockerVolumes.AddRange(volumes);

		ComputeColumnWidths();
	}

	/// <summary>
	/// Clear data and reset pane.
	/// </summary>
	internal void ClearBitLockerVolumes()
	{
		AllBitLockerVolumes.Clear();
		BitLockerVolumes.Clear();
		BitLockerSearchText = null;
		SelectedBitLockerVolume = null;
		IsBitLockerDetailsPaneOpen = false;
		ComputeColumnWidths();
	}

	#region Sort

	/// <summary>
	/// Local sort state
	/// </summary>
	private ListViewHelper.SortState SortState { get; set; } = new();

	internal void HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			// Look up the mapping in the reusable property mappings dictionary.
			if (_volumeMappings.TryGetValue(key, out (string Label, Func<BitLockerVolume, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					mapping.Getter,
					BitLockerSearchText,
					AllBitLockerVolumes,
					BitLockerVolumes,
					SortState,
					key,
					regKey: ListViewHelper.ListViewsRegistry.BitLockerVolumes);
			}
		}
	}
	#endregion

	#region Copy

	/// <summary>
	/// Converts selected BitLockerVolume rows to text.
	/// </summary>
	internal void CopySelectedVolumes_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.BitLockerVolumes);
		if (lv is null) return;
		if (lv.SelectedItems.Count > 0)
		{
			// SelectedItems is an IList
			ListViewHelper.ConvertRowToText(lv.SelectedItems, _volumeMappings);
		}
	}

	/// <summary>
	/// Copy a single property of the current selection
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void CopyVolumeProperty_Click(object sender, RoutedEventArgs e)
	{
		MenuFlyoutItem menuItem = (MenuFlyoutItem)sender;
		string key = (string)menuItem.Tag;
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.BitLockerVolumes);
		if (lv is null) return;

		if (_volumeMappings.TryGetValue(key, out var map))
		{
			// TElement = BitLockerVolume, copy just that one property
			ListViewHelper.CopyToClipboard<BitLockerVolume>(ci => map.Getter(ci)?.ToString(), lv);
		}
	}

	/// <summary>
	/// Copy event handler for individual key protectors.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void CopyKeyProtector_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			if (sender is Button button && button.DataContext is KeyProtector protector)
			{
				List<object> items = [protector];
				ListViewHelper.ConvertRowToText(items, KeyProtectorPropertyMappings);
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	#endregion

	#region Search

	/// <summary>
	/// Event handler for the SearchBox text change
	/// </summary>
	internal void SearchBox_TextChanged()
	{
		string? searchTerm = BitLockerSearchText?.Trim();
		if (searchTerm is null)
			return;

		// Get the ListView ScrollViewer info
		ScrollViewer? Sv = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.BitLockerVolumes);

		double? savedHorizontal = null;
		if (Sv != null)
		{
			savedHorizontal = Sv.HorizontalOffset;
		}

		// Perform a case-insensitive search in all relevant fields
		List<BitLockerVolume> filteredResults = AllBitLockerVolumes.Where(v =>
			v.MountPoint.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			v.ProtectionStatus.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			v.ConversionStatus.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			v.EncryptionMethod.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			v.EncryptionPercentage.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			v.WipePercentage.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			v.VolumeType.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			v.CapacityGB.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			v.FileSystemType.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			v.FriendlyName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)).ToList();

		BitLockerVolumes.Clear();
		foreach (BitLockerVolume item in filteredResults)
		{
			BitLockerVolumes.Add(item);
		}

		if (Sv != null && savedHorizontal.HasValue)
		{
			// restore horizontal scroll position
			_ = Sv.ChangeView(savedHorizontal, null, null, disableAnimation: false);
		}
	}
	#endregion

	/// <summary>
	/// Compute dynamic column widths.
	/// </summary>
	private void ComputeColumnWidths()
	{
		double w1 = ListViewHelper.MeasureText(GlobalVars.GetStr("MountPointHeader/Text"));
		double w2 = ListViewHelper.MeasureText(GlobalVars.GetStr("ProtectionStatusHeader/Text"));
		double w3 = ListViewHelper.MeasureText(GlobalVars.GetStr("ConversionStatusHeader/Text"));
		double w4 = ListViewHelper.MeasureText(GlobalVars.GetStr("EncryptionMethodHeader/Text"));
		double w5 = ListViewHelper.MeasureText(GlobalVars.GetStr("EncryptionPercentageHeader/Text"));
		double w6 = ListViewHelper.MeasureText(GlobalVars.GetStr("WipePercentageHeader/Text"));
		double w7 = ListViewHelper.MeasureText(GlobalVars.GetStr("AutoUnlockEnabledHeader/Text"));
		double w8 = ListViewHelper.MeasureText(GlobalVars.GetStr("AutoUnlockKeyStoredHeader/Text"));
		double w9 = ListViewHelper.MeasureText(GlobalVars.GetStr("VolumeTypeHeader/Text"));
		double w10 = ListViewHelper.MeasureText(GlobalVars.GetStr("CapacityGBHeader/Text"));
		double w11 = ListViewHelper.MeasureText(GlobalVars.GetStr("FileSystemTypeHeader/Text"));
		double w12 = ListViewHelper.MeasureText(GlobalVars.GetStr("FriendlyNameHeader/Text"));

		foreach (BitLockerVolume v in AllBitLockerVolumes)
		{
			w1 = ListViewHelper.MeasureText(v.MountPoint, w1);
			w2 = ListViewHelper.MeasureText(v.ProtectionStatus.ToString(), w2);
			w3 = ListViewHelper.MeasureText(v.ConversionStatus.ToString(), w3);
			w4 = ListViewHelper.MeasureText(v.EncryptionMethod.ToString(), w4);
			w5 = ListViewHelper.MeasureText(v.EncryptionPercentage, w5);
			w6 = ListViewHelper.MeasureText(v.WipePercentage, w6);
			w7 = ListViewHelper.MeasureText(v.AutoUnlockEnabled.ToString(), w7);
			w8 = ListViewHelper.MeasureText(v.AutoUnlockKeyStored.ToString(), w8);
			w9 = ListViewHelper.MeasureText(v.VolumeType.ToString(), w9);
			w10 = ListViewHelper.MeasureText(v.CapacityGB, w10);
			w11 = ListViewHelper.MeasureText(v.FileSystemType.ToString(), w11);
			w12 = ListViewHelper.MeasureText(v.FriendlyName, w12);
		}

		BLColWidth1 = new GridLength(w1);
		BLColWidth2 = new GridLength(w2);
		BLColWidth3 = new GridLength(w3);
		BLColWidth4 = new GridLength(w4);
		BLColWidth5 = new GridLength(w5);
		BLColWidth6 = new GridLength(w6);
		BLColWidth7 = new GridLength(w7);
		BLColWidth8 = new GridLength(w8);
		BLColWidth9 = new GridLength(w9);
		BLColWidth10 = new GridLength(w10);
		BLColWidth11 = new GridLength(w11);
		BLColWidth12 = new GridLength(w12);
	}

	/// <summary>
	/// Handles left-click (tap) item invocation to open the overlay details pane.
	/// Right-click / press-hold (for context flyout) will not invoke this handler,
	/// so the pane only opens on normal activation.
	/// </summary>
	internal void BitLockerVolumesList_ItemClick(object sender, ItemClickEventArgs e)
	{
		if (e.ClickedItem is BitLockerVolume volume)
		{
			SelectedBitLockerVolume = volume;
			IsBitLockerDetailsPaneOpen = true;
		}
	}

	/// <summary>
	/// Event handler to remove a Key Protector from a BitLocker volume.
	/// </summary>
	internal async void RemoveKeyProtector_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			if (sender is not Button button || button.DataContext is not KeyProtector keyProtector)
			{
				return;
			}

			// Locate the parent volume containing this key protector.
			BitLockerVolume? volume = AllBitLockerVolumes.FirstOrDefault(v => v.KeyProtectors is not null && v.KeyProtectors.Contains(keyProtector));
			if (volume is null)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("ParentVolumeForKeyProtectorNotFound"));
				return;
			}

			BitLockerUiEnabled = false;
			MainInfoBarIsClosable = false;
			MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("RemovingKeyProtectorFromVolume"), keyProtector.ID, volume.MountPoint));

			// Don't throw if KeyProtector is bound to the volume and keeping it unlocked.
			// Instead the message will be logged.
			string command = $"bitlocker removekp \"{volume.MountPoint}\" \"{keyProtector.ID}\" true";

			await Task.Run(() => ProcessStarter.RunCommandInRealTime(MainInfoBar, GlobalVars.ComManagerProcessPath, command));

			// Refresh the volume list to reflect changes.
			await GetVolumes();

			// If user tried to remove ExternalKey key protector and if the volume only has 1 key protector of type External Key
			if (keyProtector.Type is KeyProtectorType.ExternalKey && (volume.KeyProtectors.Count(x => x.Type is KeyProtectorType.ExternalKey) == 1))
			{
				MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("ExternalKeyRemovalConditionalSuccess"), keyProtector.ID, volume.MountPoint));
			}
			else
			{
				MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyRemovedKeyProtector"), keyProtector.Type, keyProtector.ID, volume.MountPoint));
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			BitLockerUiEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Event handler for the Add Key Protector button.
	/// </summary>
	internal async void AddKeyProtector()
	{
		if (SelectedBitLockerVolume is null)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("NoBitLockerVolumeSelected"));
			return;
		}

		try
		{
			// Instantiate the Content Dialog
			using AddKeyProtectorDialog customDialog = new(SelectedBitLockerVolume, AllBitLockerVolumes);

			// Show the dialog and await its result
			ContentDialogResult result = await customDialog.ShowAsync();

			// Ensure primary button was selected
			if (result is ContentDialogResult.Primary)
			{
				MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("AddingItemToAnotherMsg"), customDialog.SelectedKeyProtectorType, SelectedBitLockerVolume.MountPoint));

				string command = string.Empty;

				switch (customDialog.SelectedKeyProtectorType)
				{
					case KeyProtectorType.Tpm:
						{
							command = $"bitlocker addtpm \"{SelectedBitLockerVolume.MountPoint}\"";

							break;
						}
					case KeyProtectorType.TpmPin:
						{
							if (string.IsNullOrWhiteSpace(customDialog.PIN))
								throw new InvalidOperationException(GlobalVars.GetStr("NoPINEnteredError"));

							command = $"bitlocker addtpm+pin \"{SelectedBitLockerVolume.MountPoint}\" \"{customDialog.PIN}\"";

							break;
						}
					case KeyProtectorType.TpmStartupKey:
						{
							if (customDialog.SelectedRemovableDrive is null)
								throw new InvalidOperationException(GlobalVars.GetStr("NoRemovableDriveSelectedError"));

							command = $"bitlocker addtpm+startup \"{SelectedBitLockerVolume.MountPoint}\" \"{customDialog.SelectedRemovableDrive.MountPoint}\"";

							break;
						}
					case KeyProtectorType.TpmPinStartupKey:
						{
							if (customDialog.SelectedRemovableDrive is null)
								throw new InvalidOperationException(GlobalVars.GetStr("NoRemovableDriveSelectedError"));

							if (string.IsNullOrWhiteSpace(customDialog.PIN))
								throw new InvalidOperationException(GlobalVars.GetStr("NoPINEnteredError"));

							command = $"bitlocker addtpm+pin+startup \"{SelectedBitLockerVolume.MountPoint}\" \"{customDialog.SelectedRemovableDrive.MountPoint}\" \"{customDialog.PIN}\"";

							break;
						}
					case KeyProtectorType.ExternalKey:
						{
							if (customDialog.SelectedRemovableDrive is null)
								throw new InvalidOperationException(GlobalVars.GetStr("NoRemovableDriveSelectedError"));

							command = $"bitlocker addstartupkey \"{SelectedBitLockerVolume.MountPoint}\" \"{customDialog.SelectedRemovableDrive.MountPoint}\"";

							break;
						}
					case KeyProtectorType.AutoUnlock:
						{
							command = $"bitlocker enableautounlock \"{SelectedBitLockerVolume.MountPoint}\"";

							break;
						}
					case KeyProtectorType.Password:
						{
							if (customDialog.Password is null)
								throw new InvalidOperationException(GlobalVars.GetStr("NoPasswordProvidedError"));

							command = $"bitlocker addpass \"{SelectedBitLockerVolume.MountPoint}\" \"{customDialog.Password}\"";

							break;
						}
					case KeyProtectorType.RecoveryPassword:
						{
							if (customDialog.RecoveryPassword is null)
								command = $"bitlocker addrecovery \"{SelectedBitLockerVolume.MountPoint}\" -";
							else
								command = $"bitlocker addrecovery \"{SelectedBitLockerVolume.MountPoint}\" \"{customDialog.RecoveryPassword}\"";

							break;
						}
					case KeyProtectorType.Unknown:
						return;
					case KeyProtectorType.PublicKey:
						return;
					case KeyProtectorType.TpmNetworkKey:
						return;
					case KeyProtectorType.AdAccountOrGroup:
						return;
					default:
						return;
				}

				await Task.Run(() => ProcessStarter.RunCommandInRealTime(MainInfoBar, GlobalVars.ComManagerProcessPath, command));

				// Refresh the volume list to reflect changes.
				await GetVolumes();

				// Sometimes the content dialog lingers on or re-appears so making sure it hides at the end
				customDialog.Hide();

				// Mark whatever message the ComManager sent as success. At this point no error was thrown.
				MainInfoBar.Severity = InfoBarSeverity.Success;

				// Roll the animation to remind user to backup
				TriggerExportJsonButtonHighlight();
			}
			else
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("OperationCancelledMsg"));
				return;
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Encrypts the selected volume.
	/// </summary>
	internal async void EncryptVolume()
	{
		try
		{
			if (SelectedBitLockerVolume is null)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("NoBitLockerVolumeSelected"));
				return;
			}

			BitLockerVolume OSDrive = AllBitLockerVolumes.First(x => x.VolumeType is VolumeType.OperationSystem);

			if (SelectedBitLockerVolume.VolumeType is VolumeType.FixedDisk &&
				OSDrive.ConversionStatus is not ConversionStatus.FullyEncrypted)
			{
				throw new InvalidOperationException(string.Format(GlobalVars.GetStr("OSDriveNotEncryptedForFixedDriveEncryptionError"), OSDrive.ConversionStatus, OSDrive.EncryptionPercentage));
			}

			BitLockerUiEnabled = false;
			MainInfoBarIsClosable = false;

			// Instantiate the Content Dialog
			using BitLockerEncryptDriveDialog customDialog = new(SelectedBitLockerVolume, AllBitLockerVolumes);

			// Show the dialog and await its result
			ContentDialogResult result = await customDialog.ShowAsync();

			// Ensure primary button was selected
			if (result is ContentDialogResult.Primary)
			{
				// Apply BitLocker policies first.
				await ApplyAllBitLockerSecurityMeasuresAsync();

				string command = string.Empty;

				string FreePlusUsedSpaceEncryption = customDialog.FreePlusUsedSpaceEncryption ? "true" : "false";
				string AllowDowngradeOSDriveEncryptionLevel = customDialog.AllowDowngradeOSDriveEncryptionLevel ? "true" : "false";

				switch (SelectedBitLockerVolume.VolumeType)
				{
					case VolumeType.OperationSystem:
						{
							if (customDialog.IsNormalOSDriveEncryptionLevelSelected)
							{
								if (string.IsNullOrWhiteSpace(customDialog.PIN))
								{
									throw new InvalidOperationException(GlobalVars.GetStr("NoPINEnteredError"));
								}

								command = $"bitlocker enableos \"{SelectedBitLockerVolume.MountPoint}\" normal \"{customDialog.PIN}\" - \"{FreePlusUsedSpaceEncryption}\" \"{AllowDowngradeOSDriveEncryptionLevel}\"";
							}
							else if (customDialog.IsEnhancedOSDriveEncryptionLevelSelected)
							{
								if (string.IsNullOrWhiteSpace(customDialog.PIN))
								{
									throw new InvalidOperationException(GlobalVars.GetStr("NoPINEnteredError"));
								}

								if (customDialog.SelectedRemovableDrive is null)
								{
									throw new InvalidOperationException(GlobalVars.GetStr("NoRemovableDriveSelectedError"));
								}

								command = $"bitlocker enableos \"{SelectedBitLockerVolume.MountPoint}\" enhanced \"{customDialog.PIN}\" \"{customDialog.SelectedRemovableDrive.MountPoint}\" \"{FreePlusUsedSpaceEncryption}\" \"{AllowDowngradeOSDriveEncryptionLevel}\"";
							}

							break;
						}
					case VolumeType.FixedDisk:
						{
							command = $"bitlocker enablefixed \"{SelectedBitLockerVolume.MountPoint}\" \"{FreePlusUsedSpaceEncryption}\"";

							break;
						}
					case VolumeType.Removable:
						{
							if (string.IsNullOrWhiteSpace(customDialog.Password))
							{
								throw new InvalidOperationException(GlobalVars.GetStr("NoPasswordProvidedError"));
							}

							command = $"bitlocker enableremovable \"{SelectedBitLockerVolume.MountPoint}\" \"{customDialog.Password}\" \"{FreePlusUsedSpaceEncryption}\"";

							break;
						}

					default:
						break;
				}

				await Task.Run(() => ProcessStarter.RunCommandInRealTime(MainInfoBar, GlobalVars.ComManagerProcessPath, command));

				// Refresh the volume list to reflect changes.
				await GetVolumes();

				// Mark whatever message the ComManager sent as success. At this point no error was thrown.
				MainInfoBar.Severity = InfoBarSeverity.Success;

				// Roll the animation to remind user to backup
				TriggerExportJsonButtonHighlight();
			}
			else
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("OperationCancelledMsg"));
				return;
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			BitLockerUiEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Decrypts the selected volume.
	/// </summary>
	internal async void DecryptVolume()
	{
		try
		{
			if (SelectedBitLockerVolume is null)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("NoBitLockerVolumeSelected"));
				return;
			}

			BitLockerUiEnabled = false;
			MainInfoBarIsClosable = false;

			using AppControlManager.CustomUIElements.ContentDialogV2 dialog = new()
			{
				Title = string.Format(GlobalVars.GetStr("BitLockerDecryptingSelectedVolumeTitle"), SelectedBitLockerVolume.MountPoint),
				Content = GlobalVars.GetStr("BitLockerDecryptingSelectedVolumeBody"),
				CloseButtonText = GlobalVars.GetStr("Cancel"),
				PrimaryButtonText = GlobalVars.GetStr("DecryptMenuFlyoutItem/Text"),
				DefaultButton = ContentDialogButton.Close,
				Style = (Style)Application.Current.Resources["DefaultContentDialogStyle"],
				FlowDirection = Enum.Parse<FlowDirection>(AppSettings.ApplicationGlobalFlowDirection)
			};

			// Show the dialog and wait for user response
			ContentDialogResult result = await dialog.ShowAsync();

			if (result is not ContentDialogResult.Primary)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("OperationCancelledMsg"));
				return;
			}

			string command = $"bitlocker disable \"{SelectedBitLockerVolume.MountPoint}\"";

			await Task.Run(() => ProcessStarter.RunCommandInRealTime(MainInfoBar, GlobalVars.ComManagerProcessPath, command));

			// Refresh the volume list to reflect changes.
			await GetVolumes();

			// Mark whatever message the ComManager sent as success. At this point no error was thrown.
			MainInfoBar.Severity = InfoBarSeverity.Success;
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			BitLockerUiEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Suspends the selected volume's encryption.
	/// </summary>
	internal async void SuspendVolume()
	{
		try
		{
			if (SelectedBitLockerVolume is null)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("NoBitLockerVolumeSelected"));
				return;
			}

			BitLockerUiEnabled = false;
			MainInfoBarIsClosable = false;

			// Instantiate the Content Dialog
			using BitLockerSuspend customDialog = new();

			// Show the dialog and await its result
			ContentDialogResult result = await customDialog.ShowAsync();

			// Ensure primary button was selected
			if (result is ContentDialogResult.Primary)
			{
				string command = $"bitlocker suspend \"{SelectedBitLockerVolume.MountPoint}\" \"{customDialog.RestartCount}\"";

				await Task.Run(() => ProcessStarter.RunCommandInRealTime(MainInfoBar, GlobalVars.ComManagerProcessPath, command));

				// Refresh the volume list to reflect changes.
				await GetVolumes();

				// Mark whatever message the ComManager sent as success. At this point no error was thrown.
				MainInfoBar.Severity = InfoBarSeverity.Success;
			}
			else
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("OperationCancelledMsg"));
				return;
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			BitLockerUiEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Resumes the selected volume's encryption.
	/// </summary>
	internal async void ResumeVolume()
	{
		try
		{
			if (SelectedBitLockerVolume is null)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("NoBitLockerVolumeSelected"));
				return;
			}

			BitLockerUiEnabled = false;
			MainInfoBarIsClosable = false;

			using AppControlManager.CustomUIElements.ContentDialogV2 dialog = new()
			{
				Title = string.Format(GlobalVars.GetStr("BitLockerResumeSelectedVolumeTitle"), SelectedBitLockerVolume.MountPoint),
				Content = GlobalVars.GetStr("BitLockerResumeSelectedVolumeBody"),
				CloseButtonText = GlobalVars.GetStr("Cancel"),
				PrimaryButtonText = GlobalVars.GetStr("ResumeMenuFlyoutItem/Text"),
				DefaultButton = ContentDialogButton.Close,
				Style = (Style)Application.Current.Resources["DefaultContentDialogStyle"],
				FlowDirection = Enum.Parse<FlowDirection>(AppSettings.ApplicationGlobalFlowDirection)
			};

			// Show the dialog and wait for user response
			ContentDialogResult result = await dialog.ShowAsync();

			if (result is not ContentDialogResult.Primary)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("OperationCancelledMsg"));
				return;
			}

			string command = $"bitlocker enablekps \"{SelectedBitLockerVolume.MountPoint}\"";

			await Task.Run(() => ProcessStarter.RunCommandInRealTime(MainInfoBar, GlobalVars.ComManagerProcessPath, command));

			// Refresh the volume list to reflect changes.
			await GetVolumes();

			// Mark whatever message the ComManager sent as success. At this point no error was thrown.
			MainInfoBar.Severity = InfoBarSeverity.Success;
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			BitLockerUiEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Exports all loaded BitLocker volume data (including nested Key Protectors)
	/// to a user-selected JSON file,
	/// </summary>
	internal async void ExportBitLockerData()
	{
		try
		{
			if (AllBitLockerVolumes.Count == 0)
			{
				// No data to export
				MainInfoBar.WriteWarning(GlobalVars.GetStr("NoBitLockerVolumesDetected"));
				return;
			}

			BitLockerUiEnabled = false;
			MainInfoBarIsClosable = false;

			// Show save dialog
			string? saveLocation = FileDialogHelper.ShowSaveFileDialog(
				"BitLocker Volumes_Backup|*.json",
				"BitLocker Volumes_Backup.json");

			if (saveLocation is null)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("OperationCancelledMsg"));
				return;
			}

			// Snapshot the data to avoid collection mutation during async work
			BitLockerVolume[] volumes = AllBitLockerVolumes.ToArray();

			await Task.Run(() =>
			{
				string json = JsonSerializer.Serialize(volumes, BitLockerJsonContext.Default.BitLockerVolumeArray);

				File.WriteAllText(saveLocation, json, System.Text.Encoding.UTF8);
			});

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("BitLockerSuccessExportMsg"), volumes.Length, saveLocation));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			BitLockerUiEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	// Event raised so the Page can animate the Export -> JSON button.
	internal event Action? ExportJsonButtonHighlightRequested;

	private void TriggerExportJsonButtonHighlight()
	{
		Action? handler = ExportJsonButtonHighlightRequested;
		handler?.Invoke();
	}

	#endregion

}
