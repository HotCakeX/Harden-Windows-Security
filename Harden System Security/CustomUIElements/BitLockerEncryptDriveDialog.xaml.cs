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
using System.ComponentModel;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.ViewModels;
using HardenSystemSecurity.BitLocker;
using Microsoft.UI.Xaml.Controls;

namespace HardenSystemSecurity.CustomUIElements;

internal sealed partial class BitLockerEncryptDriveDialog : ContentDialogV2, INPCImplant
{

	private AppSettings.Main AppSettings => App.Settings;

	/// <summary>
	/// Volume selected to add a key protector to.
	/// </summary>
	internal readonly BitLockerVolume Volume;

	/// <summary>
	/// PIN entered by user in textboxes.
	/// </summary>
	internal string? PIN { get; private set => this.SP(ref field, value); }

	/// <summary>
	/// Password entered by user in textboxes.
	/// </summary>
	internal string? Password { get; private set => this.SP(ref field, value); }

	internal BitLockerEncryptDriveDialog(BitLockerVolume volume, List<BitLockerVolume> volumesList)
	{
		InitializeComponent();

		Volume = volume;

		// Get the full list of volumes and filter out non-removable drives.
		RemovableDrives = [.. volumesList.Where(x => x.VolumeType is VolumeType.Removable && !string.IsNullOrWhiteSpace(x.MountPoint))];

		SelectedRemovableDrive = RemovableDrives.FirstOrDefault();

		switch (volume.VolumeType)
		{
			case VolumeType.OperationSystem:
				{
					SelectedKeyProtectorTypeIndex = 0;
					IsOSDriveSectionEnabled = true;

					break;
				}

			case VolumeType.FixedDisk:
				{
					SelectedKeyProtectorTypeIndex = 1;
					IsFixedDriveSectionEnabled = true;

					break;
				}

			case VolumeType.Removable:
				{
					SelectedKeyProtectorTypeIndex = 2;
					IsRemovableDriveSectionEnabled = true;

					break;
				}

			default:
				break;
		}
	}

	/// <summary>
	/// The selected key protector type in the Segmented element.
	/// </summary>
	private int SelectedKeyProtectorTypeIndex { get; set => this.SP(ref field, value); }

	/// <summary>
	/// Bound to the ComboBoxes in the UI that display removable drives.
	/// </summary>
	private readonly ObservableCollection<BitLockerVolume> RemovableDrives;

	/// <summary>
	/// Bound to the ComboBox's selected item.
	/// </summary>
	internal BitLockerVolume? SelectedRemovableDrive { get; set => this.SP(ref field, value); }

	/// <summary>
	/// Whether the UI elements are enabled or disabled.
	/// </summary>
	private bool ElementsAreEnabled { get; set => this.SP(ref field, value); } = true;

	private bool IsOSDriveSectionEnabled { get; set => this.SP(ref field, value); }
	private bool IsFixedDriveSectionEnabled { get; set => this.SP(ref field, value); }
	private bool IsRemovableDriveSectionEnabled { get; set => this.SP(ref field, value); }

	internal bool IsNormalOSDriveEncryptionLevelSelected { get; set => this.SP(ref field, value); } = true;

	internal bool IsEnhancedOSDriveEncryptionLevelSelected { get; set => this.SP(ref field, value); }

	internal bool FreePlusUsedSpaceEncryption { get; set => this.SP(ref field, value); } = true;

	internal bool AllowDowngradeOSDriveEncryptionLevel { get; set => this.SP(ref field, value); }

	/// Event handler for the refresh button of removable drives.
	/// </summary>
	/// <exception cref="InvalidOperationException"></exception>
	private async void RefreshRemovableDrives()
	{
		try
		{
			ElementsAreEnabled = false;

			BitLockerVolume[] volumes = await Task.Run(() =>
			{
				const string command = "bitlocker list all";
				string result = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, command)
					?? throw new InvalidOperationException(string.Format(GlobalVars.GetStr("NoOutputReturnedFromPath"), GlobalVars.ComManagerProcessPath));
				return JsonSerializer.Deserialize(result, BitLockerJsonContext.Default.BitLockerVolumeArray)!;
			});

			RemovableDrives.Clear();

			if (volumes.Length == 0)
			{
				Logger.Write(GlobalVars.GetStr("NoBitLockerVolumesDetected"));
				return;
			}

			foreach (BitLockerVolume vol in volumes)
			{
				if (vol.VolumeType is VolumeType.Removable && !string.IsNullOrWhiteSpace(vol.MountPoint))
				{
					RemovableDrives.Add(vol);
				}
			}

			SelectedRemovableDrive = RemovableDrives.FirstOrDefault();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Event handler for the primary button click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void OnPrimaryButtonClick(ContentDialog sender, ContentDialogButtonClickEventArgs args)
	{

	}

	#region IPropertyChangeHost Implementation
	public event PropertyChangedEventHandler? PropertyChanged;
	public void RaisePropertyChanged(string? propertyName) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	#endregion

}
