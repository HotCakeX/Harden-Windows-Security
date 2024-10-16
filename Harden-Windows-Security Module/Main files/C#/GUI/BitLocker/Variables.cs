using System.Collections.Generic;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using static HardenWindowsSecurity.BitLocker;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class GUIBitLocker
    {
        internal static UserControl? View;

        internal static Grid? ParentGrid;

        internal static TabControl? TabControl;

        internal static ToggleButton? ExecuteButton;

        internal static PasswordBox? PIN1;

        internal static PasswordBox? PIN2;

        internal static Button? RefreshRemovableDrivesInOSDriveSection;

        internal static ComboBox? RemovableDrivesComboBox;

        internal static Button? RefreshNonOSDrives;

        internal static Button? RefreshRemovableDrivesForRemovableDrivesSection;

        internal static List<BitLocker.BitLockerVolume>? NonOSDrivesList;

        internal static List<BitLocker.BitLockerVolume>? RemovableDrivesList;

        internal static ComboBox? BitLockerSecurityLevelComboBox;

        internal static TextBlock? TextBlockStartupKeySelection;

        internal static ComboBox? NonOSDrivesComboBox;

        internal static ComboBox? RemovableDrivesInRemovableDrivesGridComboBox;

        internal static PasswordBox? Password1;

        internal static PasswordBox? Password2;

        internal static DataGrid? RecoveryKeysDataGrid;

        internal static Button? BackupButton;

        internal static Button? RefreshButtonForBackup;


        public class BitLockerVolumeViewModel
        {
            public string? DriveLetter { get; set; }  // MountPoint in BitLockerVolume type
            public string? KeyID { get; set; }        // KeyProtectorID in KeyProtector type
            public string? RecoveryKey { get; set; }  // RecoveryPassword in KeyProtector type
            public string? SizeGB { get; set; }    // CapacityGB in BitLockerVolume type
        }


        /// <summary>
        /// If a drive has more than 1 recovery password key protector, all of them will be properly
        /// listed and backed up to a file
        /// </summary>
        /// <param name="ExportToFile"></param>
        public static void CreateBitLockerVolumeViewModel(bool ExportToFile)
        {

            // Get all of the BitLocker volumes
            List<HardenWindowsSecurity.BitLocker.BitLockerVolume> AllBitLockerVolumes = HardenWindowsSecurity.BitLocker.GetAllEncryptedVolumeInfo(false, false);

            // List of BitLockerVolumeViewModel objects
            List<BitLockerVolumeViewModel> viewModelList = [];


            if (AllBitLockerVolumes is not null)
            {
                foreach (HardenWindowsSecurity.BitLocker.BitLockerVolume Volume in AllBitLockerVolumes)
                {
                    if (Volume.KeyProtector is not null)
                    {
                        foreach (HardenWindowsSecurity.BitLocker.KeyProtector KeyProtector in Volume.KeyProtector)
                        {
                            if (KeyProtector.KeyProtectorType is not null)
                            {
                                if (KeyProtector.KeyProtectorType is BitLocker.KeyProtectorType.RecoveryPassword)
                                {
                                    viewModelList.Add(new BitLockerVolumeViewModel
                                    {
                                        DriveLetter = Volume.MountPoint,
                                        KeyID = KeyProtector.KeyProtectorID,
                                        RecoveryKey = KeyProtector.RecoveryPassword,
                                        SizeGB = Volume.CapacityGB
                                    });
                                }
                            }
                        }
                    }
                }
            }


            // Using the Application dispatcher to update UI elements
            GUIMain.app!.Dispatcher.Invoke(() =>
            {
                if (viewModelList.Count > 0)
                {
                    // Place them in the DataGrid
                    GUIBitLocker.RecoveryKeysDataGrid!.ItemsSource = viewModelList;
                }
            });


            if (ExportToFile)
            {
                // Show the save file dialog to let the user pick the save location
                var saveFileDialog = new Microsoft.Win32.SaveFileDialog
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
                    using (var writer = new StreamWriter(filePath))
                    {
                        // Write headers
                        writer.WriteLine("DriveLetter | KeyID | RecoveryKey | Size (GB)");

                        // Write each BitLockerVolumeViewModel's data into the file
                        foreach (var volume in viewModelList!)
                        {
                            writer.WriteLine($"{volume.DriveLetter} | {volume.KeyID} | {volume.RecoveryKey} | {volume.SizeGB} GB");
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
}
