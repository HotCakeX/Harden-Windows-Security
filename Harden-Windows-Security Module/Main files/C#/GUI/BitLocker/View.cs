using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Markup;
using System.Windows.Media.Imaging;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class GUIMain
    {

        // Partial class definition for handling navigation and view models
        public partial class NavigationVM : ViewModelBase
        {

            // Method to handle the Logs view, including loading
            private void BitLocker(object obj)
            {
                // Check if the view is already cached
                if (_viewCache.TryGetValue("BitLockerView", out var cachedView))
                {
                    CurrentView = cachedView;
                    return;
                }

                // Defining the path to the XAML XML file
                if (HardenWindowsSecurity.GlobalVars.path is null)
                {
                    throw new InvalidOperationException("GlobalVars.path cannot be null.");
                }

                // if Admin privileges are not available, return and do not proceed any further
                // Will prevent the page from being loaded since the CurrentView won't be set/changed
                if (!HardenWindowsSecurity.UserPrivCheck.IsAdmin())
                {
                    Logger.LogMessage("BitLocker page can only be used when running the Harden Windows Security Application with Administrator privileges", LogTypeIntel.ErrorInteractionRequired);
                    return;
                }

                // Construct the file path for the Logs view XAML
                string xamlPath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "XAML", "BitLocker.xaml");

                // Read the XAML content from the file
                string xamlContent = File.ReadAllText(xamlPath);

                // Parse the XAML content to create a UserControl
                HardenWindowsSecurity.GUIBitLocker.View = (UserControl)XamlReader.Parse(xamlContent);

                // Set the DataContext for the BitLocker view
                GUIBitLocker.View.DataContext = new BitLockerVM();

                // Find the Parent Grid
                HardenWindowsSecurity.GUIBitLocker.ParentGrid = (Grid)HardenWindowsSecurity.GUIBitLocker.View.FindName("ParentGrid");

                GUIBitLocker.TabControl = GUIBitLocker.ParentGrid.FindName("TabControl") as TabControl ?? throw new InvalidOperationException("TabControl could not be found");

                #region Execute Button
                // Find the Execute button Grid, button and its image
                Grid ExecuteButtonGrid = GUIBitLocker.ParentGrid.FindName("ExecuteButtonGrid") as Grid ?? throw new InvalidOperationException("ExecuteButtonGrid could not be found");
                GUIBitLocker.ExecuteButton = ExecuteButtonGrid.FindName("ExecuteButton") as ToggleButton ?? throw new InvalidOperationException("ExecuteButton could not be found");
                // Apply the template to make sure it's available
                _ = GUIBitLocker.ExecuteButton.ApplyTemplate();
                Image ExecuteIconImage = GUIBitLocker.ExecuteButton.Template.FindName("ExecuteIconImage", GUIBitLocker.ExecuteButton) as Image ?? throw new InvalidOperationException("ExecuteIconImage could not be found");

                // Update the image source for the Execute button
                // Load the Execute icon image into memory and set it as the source
                var ExecuteIconBitmapImage = new BitmapImage();
                ExecuteIconBitmapImage.BeginInit();
                ExecuteIconBitmapImage.UriSource = new System.Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "ExecuteButton.png"));
                ExecuteIconBitmapImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
                ExecuteIconBitmapImage.EndInit();
                ExecuteIconImage.Source = ExecuteIconBitmapImage;
                #endregion

                if (GUIBitLocker.TabControl.FindName("OSDriveGrid") is not Grid OSDriveGrid ||
                    GUIBitLocker.TabControl.FindName("NonOSDrivesGrid") is not Grid NonOSDrivesGrid ||
                    GUIBitLocker.TabControl.FindName("RemovableDrivesGrid") is not Grid RemovableDrivesGrid ||
                    GUIBitLocker.TabControl.FindName("BackupGrid") is not Grid BackupGrid)
                {
                    throw new InvalidOperationException("BitLocker view grids could not be found");
                }


                #region OS Drives

                GUIBitLocker.TextBlockStartupKeySelection = OSDriveGrid.FindName("TextBlockStartupKeySelection") as TextBlock;
                GUIBitLocker.BitLockerSecurityLevelComboBox = OSDriveGrid.FindName("BitLockerSecurityLevelComboBox") as ComboBox ?? throw new InvalidOperationException("BitLockerSecurityLevelComboBox could not be found");
                GUIBitLocker.PIN1 = OSDriveGrid.FindName("PIN1") as PasswordBox ?? throw new InvalidOperationException("PIN1 password box could not be found");
                GUIBitLocker.PIN2 = OSDriveGrid.FindName("PIN2") as PasswordBox ?? throw new InvalidOperationException("PIN2 password box could not be found");
                GUIBitLocker.RefreshRemovableDrivesInOSDriveSection = OSDriveGrid.FindName("RefreshRemovableDrivesInOSDriveSection") as Button ?? throw new InvalidOperationException("RefreshRemovableDrivesInOSDriveSection button could not be found");
                Image? RefreshButtonIcon1 = OSDriveGrid.FindName("RefreshButtonIcon1") as Image ?? throw new InvalidOperationException("RefreshButtonIcon1 could not be found");
                GUIBitLocker.RemovableDrivesComboBox = OSDriveGrid.FindName("RemovableDrivesComboBox") as ComboBox ?? throw new InvalidOperationException("RemovableDrivesComboBox could not be found");


                // Event handler for when the refresh button is pressed
                GUIBitLocker.RefreshRemovableDrivesInOSDriveSection.Click += async (sender, e) =>
                {
                    await System.Threading.Tasks.Task.Run(() =>
                    {

                        // Get the Removable drives list
                        List<BitLocker.BitLockerVolume>? UndeterminedRemovableDrivesList = HardenWindowsSecurity.BitLocker.GetAllEncryptedVolumeInfo(false, true);
                        // Only get the writable removable drives
                        GUIBitLocker.RemovableDrivesList = VolumeWritabilityCheck.GetWritableVolumes(UndeterminedRemovableDrivesList);

                        // Update the ComboBox with the removable drives using Application's Dispatcher
                        GUIMain.app!.Dispatcher.Invoke(() =>
                        {
                            GUIBitLocker.RemovableDrivesComboBox.ItemsSource = GUIBitLocker.RemovableDrivesList?.Select(D => D.MountPoint);
                        });
                    });
                };

                // Updates UI elements in the OS Drive section for Enhanced Level
                static void UpdateEnhancedLevelElements()
                {
                    // Using the Application dispatcher
                    GUIMain.app!.Dispatcher.Invoke(() =>
                    {
                        // Retrieve the ComboBoxItem
                        var selectedItem = GUIBitLocker.BitLockerSecurityLevelComboBox!.SelectedItem;
                        if (selectedItem is ComboBoxItem comboBoxItem)
                        {
                            // Get the actual string content from ComboBoxItem
                            string selectedString = comboBoxItem.Content!.ToString()!;

                            // Make sure the Startup key related elements are only enabled for the Enhanced security level
                            if (string.Equals(selectedString, "Normal", StringComparison.OrdinalIgnoreCase))
                            {
                                GUIBitLocker.RefreshRemovableDrivesInOSDriveSection!.IsEnabled = false;
                                GUIBitLocker.RemovableDrivesComboBox!.IsEnabled = false;
                                GUIBitLocker.TextBlockStartupKeySelection!.Opacity = 0.3;
                                GUIBitLocker.RefreshRemovableDrivesInOSDriveSection.Opacity = 0.4;
                                GUIBitLocker.RemovableDrivesComboBox.Opacity = 0.4;
                            }
                            else
                            {
                                GUIBitLocker.RefreshRemovableDrivesInOSDriveSection!.IsEnabled = true;
                                GUIBitLocker.RemovableDrivesComboBox!.IsEnabled = true;
                                GUIBitLocker.TextBlockStartupKeySelection!.Opacity = 1;
                                GUIBitLocker.RefreshRemovableDrivesInOSDriveSection.Opacity = 1;
                                GUIBitLocker.RemovableDrivesComboBox.Opacity = 1;
                            }
                        }
                    });
                }

                // Run this once during GUI load to enable/disable the elements properly
                UpdateEnhancedLevelElements();

                // Event handler for security level selection
                GUIBitLocker.BitLockerSecurityLevelComboBox.SelectionChanged += (sender, e) =>
                {
                    UpdateEnhancedLevelElements();
                };


                #endregion


                #region Non-OS Drives
                GUIBitLocker.RefreshNonOSDrives = NonOSDrivesGrid.FindName("RefreshNonOSDrives") as Button ?? throw new InvalidOperationException("RefreshNonOSDrives button could not be found");
                Image? RefreshButtonIcon2 = NonOSDrivesGrid.FindName("RefreshButtonIcon2") as Image ?? throw new InvalidOperationException("RefreshButtonIcon2 could not be found");
                GUIBitLocker.NonOSDrivesComboBox = NonOSDrivesGrid.FindName("NonOSDrivesComboBox") as ComboBox ?? throw new InvalidOperationException("NonOSDrivesComboBox button could not be found");

                // Event handler for when the refresh button is pressed
                GUIBitLocker.RefreshNonOSDrives.Click += async (sender, e) =>
                {
                    await System.Threading.Tasks.Task.Run(() =>
                    {
                        // Get the Non-OS drives list
                        GUIBitLocker.NonOSDrivesList = HardenWindowsSecurity.BitLocker.GetAllEncryptedVolumeInfo(true, false);

                        // Update the ComboBox with the Non-OS drives using Application's Dispatcher
                        GUIMain.app!.Dispatcher.Invoke(() =>
                        {
                            GUIBitLocker.NonOSDrivesComboBox.ItemsSource = GUIBitLocker.NonOSDrivesList.Select(D => $"{D.MountPoint}");
                        });
                    });
                };

                #endregion



                #region Removable Drives
                GUIBitLocker.RefreshRemovableDrivesForRemovableDrivesSection = RemovableDrivesGrid.FindName("RefreshRemovableDrivesForRemovableDrivesSection") as Button ?? throw new InvalidOperationException("RefreshRemovableDrivesForRemovableDrivesSection button could not be found");
                Image? RefreshButtonIcon3 = RemovableDrivesGrid.FindName("RefreshButtonIcon3") as Image ?? throw new InvalidOperationException("RefreshButtonIcon3 could not be found");
                GUIBitLocker.RemovableDrivesInRemovableDrivesGridComboBox = RemovableDrivesGrid.FindName("RemovableDrivesInRemovableDrivesGridComboBox") as ComboBox ?? throw new InvalidOperationException("RemovableDrivesInRemovableDrivesGridComboBox button could not be found");
                GUIBitLocker.Password1 = RemovableDrivesGrid.FindName("Password1") as PasswordBox ?? throw new InvalidOperationException("Password1 password box could not be found");
                GUIBitLocker.Password2 = RemovableDrivesGrid.FindName("Password2") as PasswordBox ?? throw new InvalidOperationException("Password2 password box could not be found");

                // Event handler for when the refresh button is pressed
                GUIBitLocker.RefreshRemovableDrivesForRemovableDrivesSection.Click += async (sender, e) =>
                {
                    await System.Threading.Tasks.Task.Run(() =>
                    {
                        // Get the Removable drives list
                        List<BitLocker.BitLockerVolume>? UndeterminedRemovableDrivesList = HardenWindowsSecurity.BitLocker.GetAllEncryptedVolumeInfo(false, true);
                        // Only get the writable removable drives
                        GUIBitLocker.RemovableDrivesList = VolumeWritabilityCheck.GetWritableVolumes(UndeterminedRemovableDrivesList);

                        // Update the ComboBox with the Removable drives using Application's Dispatcher
                        GUIMain.app!.Dispatcher.Invoke(() =>
                        {
                            GUIBitLocker.RemovableDrivesInRemovableDrivesGridComboBox.ItemsSource = GUIBitLocker.RemovableDrivesList?.Select(D => D.MountPoint);
                        });
                    });
                };

                #endregion


                #region Backup

                GUIBitLocker.RecoveryKeysDataGrid = BackupGrid.FindName("RecoveryKeysDataGrid") as DataGrid ?? throw new InvalidOperationException("RecoveryKeysDataGrid could not be found");
                GUIBitLocker.BackupButton = BackupGrid.FindName("BackupButton") as Button ?? throw new InvalidOperationException("BackupButton could not be found");
                GUIBitLocker.RefreshButtonForBackup = BackupGrid.FindName("RefreshButtonForBackup") as Button ?? throw new InvalidOperationException("RefreshButtonForBackup could not be found");
                Image? RefreshButtonForBackupIcon = BackupGrid.FindName("RefreshButtonForBackupIcon") as Image ?? throw new InvalidOperationException("RefreshButtonForBackupIcon could not be found");
                Image? BackupButtonIcon = BackupGrid.FindName("BackupButtonIcon") as Image ?? throw new InvalidOperationException("BackupButtonIcon could not be found");

                // Add image to the BackupButtonIcon
                BitmapImage BackupButtonIconBitmapImage = new();
                BackupButtonIconBitmapImage.BeginInit();
                BackupButtonIconBitmapImage.UriSource = new System.Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "ExportIconBlack.png"));
                BackupButtonIconBitmapImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
                BackupButtonIconBitmapImage.EndInit();
                BackupButtonIcon.Source = BackupButtonIconBitmapImage;

                // Event handler to refresh the recovery key info in the DataGrid
                GUIBitLocker.RefreshButtonForBackup.Click += async (sender, e) =>
                {
                    // Perform the main tasks on another thread to avoid freezing the GUI
                    await System.Threading.Tasks.Task.Run(() =>
                    {
                        GUIBitLocker.CreateBitLockerVolumeViewModel(false);
                    });
                };

                // Event handler to export and backup the recovery keys to a file
                GUIBitLocker.BackupButton.Click += async (sender, e) =>
                {
                    // Perform the main tasks on another thread to avoid freezing the GUI
                    await System.Threading.Tasks.Task.Run(() =>
                    {
                        GUIBitLocker.CreateBitLockerVolumeViewModel(true);
                    });
                };


                #endregion

                // Add the same Refresh image to multiple sources
                var RefreshButtonIcon1BitmapImage = new BitmapImage();
                RefreshButtonIcon1BitmapImage.BeginInit();
                RefreshButtonIcon1BitmapImage.UriSource = new System.Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "RefreshButtonIcon.png"));
                RefreshButtonIcon1BitmapImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
                RefreshButtonIcon1BitmapImage.EndInit();
                RefreshButtonIcon1.Source = RefreshButtonIcon1BitmapImage;
                RefreshButtonIcon2.Source = RefreshButtonIcon1BitmapImage;
                RefreshButtonIcon3.Source = RefreshButtonIcon1BitmapImage;
                RefreshButtonForBackupIcon.Source = RefreshButtonIcon1BitmapImage;

                // Register the ExecuteButton and TabControl that will be enabled/disabled based on current activity
                HardenWindowsSecurity.ActivityTracker.RegisterUIElement(GUIBitLocker.ExecuteButton);
                HardenWindowsSecurity.ActivityTracker.RegisterUIElement(GUIBitLocker.TabControl);

                // Event handler for the Execute Button
                GUIBitLocker.ExecuteButton.Click += async (sender, e) =>
                {

                    // Only continue if there is no activity other places
                    if (!HardenWindowsSecurity.ActivityTracker.IsActive)
                    {
                        // mark as activity started
                        HardenWindowsSecurity.ActivityTracker.IsActive = true;

                        // Reset this flag to false indicating no errors Occurred so far
                        HardenWindowsSecurity.BitLocker.HasErrorsOccurred = false;

                        #region Local variables initialization to store the currently active UI element values

                        // Tab control index
                        int? CurrentTabControlIndex = null;

                        // OS Drive | Security Level ComboBox
                        string? SecurityLevel = null;
                        // OS Drive | PINs
                        string? PIN1 = null;
                        string? PIN2 = null;
                        // OS Drive | Removable Drive ComboBox
                        string? RemovableDriveLetter = null;

                        // Non-OS Drives | Drives ComboBox
                        string? NonOSDrivesLetter = null;

                        // Removable Drives | Removable Drive ComboBox
                        string? RemovableDrivesTabDriveSelection = null;
                        // Removable Drives | Passwords
                        string? Password1 = null;
                        string? Password2 = null;

                        #endregion


                        // Using the Application dispatcher to query UI elements' values only
                        GUIMain.app!.Dispatcher.Invoke(() =>
                        {

                            CurrentTabControlIndex = GUIBitLocker.TabControl!.SelectedIndex;

                            // Retrieve the ComboBoxItem of the Security Level in OS Drive tab
                            // Because we are using the index to access it
                            var selectedItem = GUIBitLocker.BitLockerSecurityLevelComboBox!.SelectedItem;
                            if (selectedItem is ComboBoxItem comboBoxItem)
                            {
                                // Get the actual string content from ComboBoxItem
                                SecurityLevel = comboBoxItem.Content?.ToString()!;
                            }

                            // Get the PIN values as plain texts since CIM needs them that way
                            PIN1 = GUIBitLocker.PIN1.Password;
                            PIN2 = GUIBitLocker.PIN2.Password;

                            // Retrieve the ComboBoxItem of the Removable drive in the OS Drive tab
                            RemovableDriveLetter = GUIBitLocker.RemovableDrivesComboBox!.SelectedItem?.ToString();

                            // Retrieve the ComboBoxItem in the Non-OS Drives tab
                            NonOSDrivesLetter = GUIBitLocker.NonOSDrivesComboBox!.SelectedItem?.ToString();

                            // Retrieve the ComboBoxItem in the Removable Drives tab
                            RemovableDrivesTabDriveSelection = GUIBitLocker.RemovableDrivesInRemovableDrivesGridComboBox!.SelectedItem?.ToString();

                            // Get the Password values as plain texts since CIM needs them way that
                            Password1 = GUIBitLocker.Password1.Password;
                            Password2 = GUIBitLocker.Password2.Password;

                        });


                        // Perform the main tasks on another thread to avoid freezing the GUI
                        await System.Threading.Tasks.Task.Run(() =>
                        {

                            #region Group Policy handling
                            if (!HardenWindowsSecurity.BitLocker.PoliciesApplied)
                            {

                                // if LGPO doesn't already exist in the working directory, then download it
                                if (!System.IO.Path.Exists(GlobalVars.LGPOExe))
                                {
                                    Logger.LogMessage("LGPO.exe doesn't exist, downloading it.", LogTypeIntel.Information);
                                    AsyncDownloader.PrepDownloadedFiles(GlobalVars.LGPOExe, null, null, true);
                                }
                                else
                                {
                                    Logger.LogMessage("LGPO.exe already exists, skipping downloading it.", LogTypeIntel.Information);
                                }

                                // Apply the BitLocker group policies
                                HardenWindowsSecurity.BitLockerSettings.Invoke();

                                // Refresh the group policies to apply the changes instantly
                                _ = HardenWindowsSecurity.PowerShellExecutor.ExecuteScript("""
Start-Process -FilePath GPUpdate.exe -ArgumentList '/force' -NoNewWindow
""");
                                // Set the flag to true so this section won't happen again
                                HardenWindowsSecurity.BitLocker.PoliciesApplied = true;
                            }
                            else
                            {
                                Logger.LogMessage("BitLocker group policies already applied.", LogTypeIntel.Information);
                            }
                            #endregion


                            switch (CurrentTabControlIndex)
                            {
                                // OS Drive tab
                                case 0:
                                    {
                                        Logger.LogMessage($"Executing BitLocker Ops for the OS Drive with {SecurityLevel} security level.", LogTypeIntel.Information);

                                        if (string.IsNullOrWhiteSpace(PIN1) || string.IsNullOrWhiteSpace(PIN2))
                                        {
                                            Logger.LogMessage("Both PIN boxes must be entered.", LogTypeIntel.ErrorInteractionRequired);
                                            break;
                                        }

                                        // Make sure the PINs match
                                        if (!string.Equals(PIN1, PIN2, StringComparison.OrdinalIgnoreCase))
                                        {
                                            Logger.LogMessage("PINs don't match.", LogTypeIntel.ErrorInteractionRequired);
                                            break;
                                        }
                                        {
                                            Logger.LogMessage($"PINs matched.", LogTypeIntel.Information);
                                        }

                                        // Get the system directory path
                                        string systemDirectory = Environment.SystemDirectory;
                                        // Extract the drive letter
                                        string systemDrive = System.IO.Path.GetPathRoot(systemDirectory) ?? throw new InvalidOperationException("System/OS drive letter could not be found");

                                        string TrimmedSystemDrive = systemDrive.TrimEnd('\\');

                                        // Determine the security level of the OS encryption
                                        if (string.Equals(SecurityLevel, "Normal", StringComparison.OrdinalIgnoreCase))
                                        {
                                            HardenWindowsSecurity.BitLocker.Enable(TrimmedSystemDrive, HardenWindowsSecurity.BitLocker.OSEncryptionType.Normal, PIN1, null, true);
                                        }
                                        else
                                        {
                                            HardenWindowsSecurity.BitLocker.Enable(TrimmedSystemDrive, HardenWindowsSecurity.BitLocker.OSEncryptionType.Enhanced, PIN1, RemovableDriveLetter, true);
                                        }


                                        if (!HardenWindowsSecurity.BitLocker.HasErrorsOccurred)
                                        {
                                            // Display notification at the end if no errors occurred
                                            NewToastNotification.Show(NewToastNotification.ToastNotificationType.EndOfBitLocker, null, null, null, "Operation System Drive");
                                        }

                                        break;
                                    }
                                // Non-OS Drives tab
                                case 1:
                                    {
                                        if (NonOSDrivesLetter is null)
                                        {
                                            Logger.LogMessage("No Non-OS Drive selected", LogTypeIntel.ErrorInteractionRequired);
                                            break;
                                        }

                                        Logger.LogMessage($"Executing BitLocker Ops for the Non-OS Drives on drive {NonOSDrivesLetter} .", LogTypeIntel.Information);

                                        HardenWindowsSecurity.BitLocker.Enable(NonOSDrivesLetter, true);


                                        if (!HardenWindowsSecurity.BitLocker.HasErrorsOccurred)
                                        {
                                            // Display notification at the end if no errors occurred
                                            NewToastNotification.Show(NewToastNotification.ToastNotificationType.EndOfBitLocker, null, null, null, "Non-OS Drive");
                                        }

                                        break;
                                    }
                                // Removable Drives tab
                                case 2:
                                    {
                                        Logger.LogMessage($"Executing BitLocker Ops for the Removable Drives on drive {RemovableDrivesTabDriveSelection} .", LogTypeIntel.Information);

                                        if (string.IsNullOrWhiteSpace(Password1) || string.IsNullOrWhiteSpace(Password2))
                                        {
                                            Logger.LogMessage("Both Password boxes must be entered.", LogTypeIntel.ErrorInteractionRequired);
                                            break;
                                        }

                                        // Make sure the Passwords match
                                        if (!string.Equals(Password1, Password2, StringComparison.OrdinalIgnoreCase))
                                        {
                                            Logger.LogMessage("Passwords don't match.", LogTypeIntel.ErrorInteractionRequired);
                                            break;
                                        }
                                        {
                                            Logger.LogMessage($"Passwords matched.", LogTypeIntel.Information);
                                        }


                                        if (RemovableDrivesTabDriveSelection is null)
                                        {
                                            Logger.LogMessage("No Removable Drive selected", LogTypeIntel.ErrorInteractionRequired);
                                            break;
                                        }

                                        HardenWindowsSecurity.BitLocker.Enable(RemovableDrivesTabDriveSelection, Password1, true);


                                        if (!HardenWindowsSecurity.BitLocker.HasErrorsOccurred)
                                        {
                                            // Display notification at the end if no errors occurred
                                            NewToastNotification.Show(NewToastNotification.ToastNotificationType.EndOfBitLocker, null, null, null, "Removable Drive");
                                        }

                                        break;
                                    }

                                default:
                                    break;
                            }

                        }); // End of Async Thread

                        // Update the UI Elements at the end of the run
                        await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
                        {
                            GUIBitLocker.ExecuteButton.IsChecked = false; // Uncheck the ExecuteButton button to start the reverse animation
                        });

                        // mark as activity completed
                        HardenWindowsSecurity.ActivityTracker.IsActive = false;
                    }

                };

                // Cache the view before setting it as the CurrentView
                _viewCache["BitLockerView"] = HardenWindowsSecurity.GUIBitLocker.View;

                // Set the CurrentView to the Protect view
                CurrentView = HardenWindowsSecurity.GUIBitLocker.View;
            }
        }
    }
}
