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
using System.IO;
using System.Threading.Tasks;
using CommonCore;
using CommonCore.Others;
using Microsoft.UI.Xaml;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;

namespace HardenSystemSecurity.ViewModels;

internal sealed class DriveInfoModel(string driveName, string displayText)
{
	internal string DriveName => driveName;
	internal string DisplayText => displayText;
}

internal sealed partial class BootableDriveMakerVM : ViewModelBase
{
	internal readonly InfoBarSettings MainInfoBar = new();

	internal Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool ElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ProgressBarVisibility = field ? Visibility.Collapsed : Visibility.Visible;
				IsWorkInProgress = !field;
			}
		}
	} = true;

	internal bool IsWorkInProgress { get; set => SP(ref field, value); }
	internal bool IsProgressIndeterminate { get; set => SP(ref field, value); } = true;
	internal double OperationProgress { get; set => SP(ref field, value); }
	internal string? ProgressText { get; set => SP(ref field, value); }

	// Mode flags and Visibility
	internal bool IsManualMode { get; private set; } = true;
	internal Visibility IsManualModeVisibility { get; set => SP(ref field, value); } = Visibility.Visible;
	internal Visibility IsAutoModeVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool FormatRemainingSpace
	{
		get; set
		{
			if (SP(ref field, value))
			{
				FormatRemainingSpaceVisibility = value ? Visibility.Visible : Visibility.Collapsed;
			}
		}
	}

	internal Visibility FormatRemainingSpaceVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal readonly List<string> AvailableFileSystems = ["exFAT", "NTFS", "FAT32"];
	internal string SelectedFileSystem { get; set => SP(ref field, value); } = "exFAT";

	internal readonly ObservableCollection<DriveInfoModel> AvailableDrives = [];
	internal readonly ObservableCollection<PhysicalDiskInfo> AvailablePhysicalDisks = [];

	internal DriveInfoModel? SelectedBootDrive { get; set => SP(ref field, value); }
	internal DriveInfoModel? SelectedDataDrive { get; set => SP(ref field, value); }
	internal PhysicalDiskInfo? SelectedSingleDrive { get; set => SP(ref field, value); }

	internal string? IsoPath
	{
		get; set
		{
			if (SP(ref field, value))
			{
				UpdateIsoDetails();
			}
		}
	}

	internal string IsoDetails { get; set => SP(ref field, value); } = string.Empty;
	internal string? ExtractionPath { get; set => SP(ref field, value); }

	internal void ClearSelectedISOPath() => IsoPath = null;
	internal void ClearSelectedExtractionISOPath() => ExtractionPath = null;

	internal BootableDriveMakerVM() => RefreshDrives();

	internal void SetMode(bool isManual)
	{
		IsManualMode = isManual;
		if (isManual)
		{
			IsManualModeVisibility = Visibility.Visible;
			IsAutoModeVisibility = Visibility.Collapsed;
		}
		else
		{
			IsManualModeVisibility = Visibility.Collapsed;
			IsAutoModeVisibility = Visibility.Visible;
		}
	}

	internal void RefreshDrives_Click(object sender, RoutedEventArgs e)
	{
		RefreshDrives();
		MainInfoBar.WriteSuccess("Drives refreshed.");
	}

	private void RefreshDrives()
	{
		AvailableDrives.Clear();
		AvailablePhysicalDisks.Clear();

		// Fetch standard logical drive partitions (for Manual mode)
		DriveInfo[] drives = DriveInfo.GetDrives();
		foreach (DriveInfo drive in drives)
		{
			if (drive.IsReady && drive.DriveType == DriveType.Removable)
			{
				long sizeGb = drive.TotalSize / (1024 * 1024 * 1024);
				long freeGb = drive.AvailableFreeSpace / (1024 * 1024 * 1024);
				string label = string.IsNullOrWhiteSpace(drive.VolumeLabel) ? "Local Disk" : drive.VolumeLabel;
				string displayText = $"{drive.Name} [{label}] - {drive.DriveFormat} - {sizeGb} GB Total / {freeGb} GB Free";

				AvailableDrives.Add(new DriveInfoModel(drive.Name, displayText));
			}
		}

		// Fetch physical disks (for Automatic mode)
		List<PhysicalDiskInfo> physicalDisks = ISOManager.GetPhysicalDisksInfo();
		foreach (PhysicalDiskInfo disk in physicalDisks)
		{
			AvailablePhysicalDisks.Add(disk);
		}
	}

	internal void BrowseIso_Click(object sender, RoutedEventArgs e)
	{
		string? file = FileDialogHelper.ShowFilePickerDialog("ISO Files|*.iso");
		if (!string.IsNullOrEmpty(file))
		{
			IsoPath = file;
		}
	}

	internal void BrowseExtractionFolder_Click(object sender, RoutedEventArgs e)
	{
		string? folder = FileDialogHelper.ShowDirectoryPickerDialog();
		if (!string.IsNullOrEmpty(folder))
		{
			ExtractionPath = folder;
		}
	}

	private void UpdateIsoDetails()
	{
		if (File.Exists(IsoPath))
		{
			FileInfo fi = new(IsoPath);
			double sizeGb = fi.Length / (1024.0 * 1024.0 * 1024.0);
			IsoDetails = $"Size: {sizeGb:F2} GB";
		}
		else
		{
			IsoDetails = string.Empty;
		}
	}

	internal async void CreateBootableDrive_Click(object sender, RoutedEventArgs e)
	{
		if (IsManualMode)
		{
			if (SelectedBootDrive is null || SelectedDataDrive is null)
			{
				MainInfoBar.WriteWarning("Please select both BOOT and DATA drives.");
				return;
			}
		}
		else
		{
			if (SelectedSingleDrive is null)
			{
				MainInfoBar.WriteWarning("Please select a target physical disk to partition and use.");
				return;
			}
		}

		if (!File.Exists(IsoPath))
		{
			MainInfoBar.WriteWarning("Please select a valid ISO file.");
			return;
		}

		ElementsAreEnabled = false;
		IsProgressIndeterminate = true;
		OperationProgress = 0;
		ProgressText = "Preparing...";

		try
		{
			Progress<double> progressReporter = new(value =>
			{
				if (IsProgressIndeterminate) IsProgressIndeterminate = false;
				OperationProgress = value;
				ProgressText = $"{value:F1}% copied";
			});

			if (IsManualMode)
			{
				await Task.Run(() => ISOManager.CreateBootableDrive(SelectedBootDrive!.DriveName, SelectedDataDrive!.DriveName, IsoPath, progressReporter));
			}
			else
			{
				ProgressText = "Partitioning drive...";
				await Task.Run(() => ISOManager.CreateBootableDriveAutomatic(SelectedSingleDrive!.Number, IsoPath, FormatRemainingSpace, SelectedFileSystem, progressReporter));
			}

			MainInfoBar.WriteSuccess("Bootable USB created successfully.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			ProgressText = string.Empty;
			RefreshDrives(); // Refresh drives after partitioning/formatting
		}
	}

	internal async void ExtractIso_Click(object sender, RoutedEventArgs e)
	{
		if (!File.Exists(IsoPath))
		{
			MainInfoBar.WriteWarning("Please select a valid ISO file.");
			return;
		}

		if (string.Equals(ExtractionPath, "No folder selected.", StringComparison.OrdinalIgnoreCase) || !Directory.Exists(ExtractionPath))
		{
			MainInfoBar.WriteWarning("Please select a valid destination folder.");
			return;
		}

		ElementsAreEnabled = false;
		IsProgressIndeterminate = true;
		OperationProgress = 0;
		ProgressText = "Mounting ISO...";

		try
		{
			Progress<double> progressReporter = new(value =>
			{
				if (IsProgressIndeterminate) IsProgressIndeterminate = false;
				OperationProgress = value;
				ProgressText = $"{value:F1}% extracted";
			});

			await Task.Run(() => ISOManager.ExtractISO(IsoPath, ExtractionPath, progressReporter));
			MainInfoBar.WriteSuccess("ISO extracted successfully.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			ProgressText = string.Empty;
		}
	}
}
