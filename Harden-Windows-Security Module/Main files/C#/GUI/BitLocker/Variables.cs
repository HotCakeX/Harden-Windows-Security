using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using static HardenWindowsSecurity.BitLocker;

namespace HardenWindowsSecurity;

public static class GUIBitLocker
{
	internal static UserControl? View;

	internal static Grid? ParentGrid;

	internal static TabControl? TabControl;

	internal static PasswordBox? PIN1;

	internal static PasswordBox? PIN2;

	internal static Button? RefreshRemovableDrivesInOSDriveSection;

	internal static ComboBox? RemovableDrivesComboBox;

	internal static Button? RefreshNonOSDrives;

	internal static Button? RefreshRemovableDrivesForRemovableDrivesSection;

	internal static List<BitLockerVolume>? NonOSDrivesList;

	internal static List<BitLockerVolume>? RemovableDrivesList;

	internal static ComboBox? BitLockerSecurityLevelComboBox;

	internal static TextBlock? TextBlockStartupKeySelection;

	internal static ComboBox? NonOSDrivesComboBox;

	internal static ComboBox? RemovableDrivesInRemovableDrivesGridComboBox;

	internal static PasswordBox? Password1;

	internal static PasswordBox? Password2;

	internal static DataGrid? RecoveryKeysDataGrid;

	internal static Button? BackupButton;

	internal static Button? RefreshButtonForBackup;


	public sealed class BitLockerVolumeViewModel
	{
		public string? DriveLetter { get; set; }
		public string? KeyID { get; set; }
		public string? RecoveryKey { get; set; }
		public string? SizeGB { get; set; }
		public string? EncryptionPercentage { get; set; }
		public string? ProtectionStatus { get; set; }
		public string? KeyProtector { get; set; }
		public string? EncryptionMethod { get; set; }
	}


	/// <summary>
	/// If a drive has more than 1 recovery password key protector, all of them will be properly
	/// listed and backed up to a file
	/// </summary>
	/// <param name="ExportToFile"></param>
	public static void CreateBitLockerVolumeViewModel(bool ExportToFile)
	{

		// Get all of the BitLocker volumes
		List<BitLockerVolume> AllBitLockerVolumes = GetAllEncryptedVolumeInfo(false, false);

		// List of BitLockerVolumeViewModel objects
		List<BitLockerVolumeViewModel> viewModelList = [];


		foreach (BitLockerVolume Volume in AllBitLockerVolumes)
		{
			if (Volume.KeyProtector is not null)
			{
				foreach (KeyProtector KeyProtector in Volume.KeyProtector)
				{
					if (KeyProtector.KeyProtectorType is KeyProtectorType.RecoveryPassword)
					{
						viewModelList.Add(new BitLockerVolumeViewModel
						{
							DriveLetter = Volume.MountPoint,
							KeyID = KeyProtector.KeyProtectorID,
							RecoveryKey = KeyProtector.RecoveryPassword,
							SizeGB = Volume.CapacityGB,
							EncryptionPercentage = Volume.EncryptionPercentage,
							ProtectionStatus = Volume.ProtectionStatus.ToString(),
							KeyProtector = string.Join(", ", Volume.KeyProtector.Where(kp => kp is not null).Select(p => p.KeyProtectorType.ToString())),
							EncryptionMethod = Volume.EncryptionMethod.ToString()
						});
					}
				}
			}
		}

		// Using the Application dispatcher to update UI elements
		GUIMain.app.Dispatcher.Invoke(() =>
		{
			// Place them in the DataGrid
			RecoveryKeysDataGrid!.ItemsSource = viewModelList;
		});


		if (ExportToFile)
		{
			// Show the save file dialog to let the user pick the save location
			Microsoft.Win32.SaveFileDialog saveFileDialog = new()
			{
				FileName = "BitLockerVolumesBackup", // Default file name
				DefaultExt = ".txt",           // Default file extension
				Filter = "Text documents (.txt)|*.txt" // Filter files by extension
			};

			// Show the dialog and check if the user picked a file
			bool? result = saveFileDialog.ShowDialog();

			if (result == true)
			{
				// Get the selected file path from the dialog
				string filePath = saveFileDialog.FileName;


				// Create and write the headers to the text file
				using (StreamWriter writer = new(filePath))
				{
					// Write headers
					writer.WriteLine("DriveLetter | KeyID | RecoveryKey | Size (GB) | EncryptionPercentage | ProtectionStatus | KeyProtector | EncryptionMethod");

					// Write each BitLockerVolumeViewModel's data into the file
					foreach (BitLockerVolumeViewModel volume in viewModelList!)
					{
						writer.WriteLine($"{volume.DriveLetter} | {volume.KeyID} | {volume.RecoveryKey} | {volume.SizeGB} GB | {volume.EncryptionPercentage} | {volume.ProtectionStatus} | {volume.KeyProtector} | {volume.EncryptionMethod}");
					}

					writer.WriteLine("""



Please refer to this page for additional assistance on BitLocker recovery:
https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/recovery-overview


""");
				}

				// Notify the user
				_ = MessageBox.Show($"BitLocker Recovery Keys have been successfully backed up to {filePath}");

			}
		}

	}
}
