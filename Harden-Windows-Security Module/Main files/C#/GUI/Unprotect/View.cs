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

            // Method to handle the Unprotect view, including loading
            private void Unprotect(object obj)
            {
                // Check if the view is already cached
                if (_viewCache.TryGetValue("UnprotectView", out var cachedView))
                {
                    CurrentView = cachedView;
                    return;
                }

                // Defining the path to the XAML XML file
                if (GlobalVars.path is null)
                {
                    throw new InvalidOperationException("GlobalVars.path cannot be null.");
                }

                // if Admin privileges are not available, return and do not proceed any further
                // Will prevent the page from being loaded since the CurrentView won't be set/changed
                if (!UserPrivCheck.IsAdmin())
                {
                    Logger.LogMessage("Unprotect page can only be used when running the Harden Windows Security Application with Administrator privileges", LogTypeIntel.ErrorInteractionRequired);
                    return;
                }

                // Construct the file path for the Unprotect view XAML
                string xamlPath = Path.Combine(GlobalVars.path, "Resources", "XAML", "Unprotect.xaml");

                // Read the XAML content from the file
                string xamlContent = File.ReadAllText(xamlPath);

                // Parse the XAML content to create a UserControl
                GUIUnprotect.View = (UserControl)XamlReader.Parse(xamlContent);

                // Set the DataContext for the Unprotect view
                GUIUnprotect.View.DataContext = new UnprotectVM();

                #region Finding The Elements

                // Find the Parent Grid
                GUIUnprotect.ParentGrid = (Grid)GUIUnprotect.View.FindName("ParentGrid");

                // Finding the Execute Button Grid
                Grid? ExecuteButtonGrid = GUIUnprotect.ParentGrid.FindName("ExecuteButtonGrid") as Grid ?? throw new InvalidOperationException("ExecuteButtonGrid is null in the ASRRules View");

                // Finding the Execute Button
                ToggleButton? ExecuteButton = ExecuteButtonGrid.FindName("ExecuteButton") as ToggleButton ?? throw new InvalidOperationException("Couldn't find the ExecuteButton in ASRRules view");

                // Apply the template to make sure it's available
                _ = ExecuteButton.ApplyTemplate();

                // Access the image within the Execute Button's template
                Image? RefreshIconImage = ExecuteButton.Template.FindName("RefreshIconImage", ExecuteButton) as Image ?? throw new InvalidOperationException("RefreshIconImage could not be found in the ASRRules view");

                // Update the image source for the Refresh button
                // Load the Refresh icon image into memory and set it as the source
                BitmapImage RefreshIconBitmapImage = new();
                RefreshIconBitmapImage.BeginInit();
                RefreshIconBitmapImage.UriSource = new Uri(Path.Combine(GlobalVars.path!, "Resources", "Media", "ExecuteButton.png"));
                RefreshIconBitmapImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
                RefreshIconBitmapImage.EndInit();

                RefreshIconImage.Source = RefreshIconBitmapImage;

                if (GUIUnprotect.ParentGrid.FindName("AppControlPolicies") is not ComboBox AppControlPoliciesComboBox)
                {
                    throw new InvalidOperationException("AppControlPoliciesComboBox is null");
                }

                if (GUIUnprotect.ParentGrid.FindName("UnprotectCategories") is not ComboBox UnprotectCategoriesComboBox)
                {
                    throw new InvalidOperationException("UnprotectCategoriesComboBox is null");
                }


                Button RefreshDrivesButton = GUIUnprotect.ParentGrid.FindName("RefreshDrivesForSelection") as Button ?? throw new InvalidOperationException("RefreshDrivesForSelection could not be found");
                Image? RefreshDrivesForSelectionButtonIcon = GUIUnprotect.ParentGrid.FindName("RefreshDrivesForSelectionButtonIcon") as Image ?? throw new InvalidOperationException("RefreshDrivesForSelectionButtonIcon could not be found");

                // Add image to the BackupButtonIcon
                BitmapImage BackupButtonIconBitmapImage = new();
                BackupButtonIconBitmapImage.BeginInit();
                BackupButtonIconBitmapImage.UriSource = new Uri(Path.Combine(GlobalVars.path!, "Resources", "Media", "RefreshButtonIcon.png"));
                BackupButtonIconBitmapImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
                BackupButtonIconBitmapImage.EndInit();
                RefreshDrivesForSelectionButtonIcon.Source = BackupButtonIconBitmapImage;

                Button DecryptButton = GUIUnprotect.ParentGrid.FindName("DecryptButton") as Button ?? throw new InvalidOperationException("DecryptButton could not be found");

                ComboBox ListOfDrivesComboBox = GUIUnprotect.ParentGrid.FindName("ListOfDrivesComboBox") as ComboBox ?? throw new InvalidOperationException("ListOfDrivesComboBox could not be found");

                #endregion


                // Register the ExecuteButton as an element that will be enabled/disabled based on current activity
                ActivityTracker.RegisterUIElement(ExecuteButton);

                // Add more button to activity tracker
                ActivityTracker.RegisterUIElement(RefreshDrivesButton);
                ActivityTracker.RegisterUIElement(DecryptButton);

                // Event handler for when the refresh button is pressed
                RefreshDrivesButton.Click += async (sender, e) =>
                {
                    await System.Threading.Tasks.Task.Run(() =>
                    {
                        // Get the drives list
                        List<BitLocker.BitLockerVolume> allDrivesList = HardenWindowsSecurity.BitLocker.GetAllEncryptedVolumeInfo(false, false);

                        // Update the ComboBox with the drives using Application's Dispatcher
                        GUIMain.app!.Dispatcher.Invoke(() =>
                        {
                            ListOfDrivesComboBox.ItemsSource = allDrivesList.Select(D => $"{D.MountPoint}");
                        });
                    });
                };


                // Event handler for the Decrypt Button
                DecryptButton.Click += async (sender, e) =>
                {

                    // Only continue if there is no activity other places
                    if (!ActivityTracker.IsActive)
                    {
                        // mark as activity started
                        ActivityTracker.IsActive = true;

                        // Reset this flag to false indicating no errors Occurred so far
                        HardenWindowsSecurity.BitLocker.HasErrorsOccurred = false;

                        // Variable to store the selected drive letter from the ComboBox
                        string? SelectedDriveFromComboBox = null;

                        // Using the Application dispatcher to query UI elements' values only
                        GUIMain.app!.Dispatcher.Invoke(() =>
                        {
                            SelectedDriveFromComboBox = ListOfDrivesComboBox.SelectedItem?.ToString();
                        });


                        // Perform the main tasks on another thread to avoid freezing the GUI
                        await System.Threading.Tasks.Task.Run(() =>
                        {
                            if (SelectedDriveFromComboBox is null)
                            {
                                Logger.LogMessage("No Drive selected", LogTypeIntel.ErrorInteractionRequired);
                            }
                            else
                            {
                                HardenWindowsSecurity.BitLocker.Disable(SelectedDriveFromComboBox);
                            }
                        }); // End of Async Thread


                        // mark as activity completed
                        HardenWindowsSecurity.ActivityTracker.IsActive = false;
                    }

                };


                // Initially set the App Control Policies ComboBox to disabled
                AppControlPoliciesComboBox.IsEnabled = false;

                // Event handler to disable the App Control ComboBox based on the value of the UnprotectCategories ComboBox
                UnprotectCategoriesComboBox.SelectionChanged += (s, e) =>
                {
                    // Check if the selected index is 1 (Only Remove The AppControl Policies)
                    if (UnprotectCategoriesComboBox.SelectedIndex == 1)
                    {
                        // Enable the AppControlPolicies ComboBox
                        AppControlPoliciesComboBox.IsEnabled = true;
                    }
                    else
                    {
                        // Disable the AppControlPolicies ComboBox
                        AppControlPoliciesComboBox.IsEnabled = false;
                    }
                };


                // Set up the Click event handler for the ExecuteButton button
                ExecuteButton.Click += async (sender, e) =>
                {
                    // Only continue if there is no activity other places
                    if (!HardenWindowsSecurity.ActivityTracker.IsActive)
                    {
                        // This will be filled in the switch statement based on the selected category
                        // And used to send to the Notification method to be used on the toast notification
                        string NotificationMessage = string.Empty;

                        // mark as activity started
                        HardenWindowsSecurity.ActivityTracker.IsActive = true;

                        // Disable the ExecuteButton button while processing
                        System.Windows.Application.Current.Dispatcher.Invoke(() =>
                        {
                            // Store the values of the combo boxes in View variables since they need to be acquired through the Application dispatcher since they belong to the UI thread
                            GUIUnprotect.UnprotectCategoriesComboBoxSelection = (byte)UnprotectCategoriesComboBox.SelectedIndex;
                            GUIUnprotect.AppControlPoliciesComboBoxSelection = (byte)AppControlPoliciesComboBox.SelectedIndex;

                        });

                        // Run the Unprotect commands asynchronously in a different thread
                        await System.Threading.Tasks.Task.Run(() =>
                        {
                            // if LGPO doesn't already exist in the working directory, then download it
                            if (!Path.Exists(GlobalVars.LGPOExe))
                            {
                                Logger.LogMessage("LGPO.exe doesn't exist, downloading it.", LogTypeIntel.Information);
                                AsyncDownloader.PrepDownloadedFiles(GlobalVars.LGPOExe, null, null, true);
                            }
                            else
                            {
                                Logger.LogMessage("LGPO.exe already exists, skipping downloading it.", LogTypeIntel.Information);
                            }


                            switch (GUIUnprotect.UnprotectCategoriesComboBoxSelection)
                            {
                                // Only Remove The Process Mitigations
                                case 0:
                                    {
                                        NotificationMessage = "Process Mitigations";

                                        HardenWindowsSecurity.UnprotectWindowsSecurity.RemoveExploitMitigations();
                                        break;
                                    }
                                // Only Remove The AppControl Policies
                                case 1:
                                    {
                                        // Downloads Defense Measures
                                        if (GUIUnprotect.AppControlPoliciesComboBoxSelection == 0)
                                        {
                                            NotificationMessage = "Downloads Defense Measures AppControl Policy";

                                            HardenWindowsSecurity.UnprotectWindowsSecurity.RemoveAppControlPolicies(true, false);
                                        }
                                        // Dangerous Script Hosts Blocking
                                        else if (GUIUnprotect.AppControlPoliciesComboBoxSelection == 1)
                                        {
                                            NotificationMessage = "Dangerous Script Hosts Blocking AppControl Policy";

                                            HardenWindowsSecurity.UnprotectWindowsSecurity.RemoveAppControlPolicies(false, true);
                                        }
                                        // All AppControl Policies
                                        else
                                        {
                                            NotificationMessage = "AppControl Policies";

                                            HardenWindowsSecurity.UnprotectWindowsSecurity.RemoveAppControlPolicies(true, true);
                                        }

                                        break;
                                    }
                                // Only Remove The Country IP Blocking Firewall Rules
                                case 2:
                                    {
                                        NotificationMessage = "Country IP Blocking Firewall Rules";

                                        HardenWindowsSecurity.UnprotectWindowsSecurity.RemoveCountryIPBlockingFirewallRules();
                                        break;
                                    }
                                // Remove All Protections
                                case 3:
                                    {
                                        NotificationMessage = "Entire Applied Protections";

                                        HardenWindowsSecurity.UnprotectWindowsSecurity.RemoveAppControlPolicies(true, true);
                                        HardenWindowsSecurity.UnprotectWindowsSecurity.Unprotect();
                                        HardenWindowsSecurity.UnprotectWindowsSecurity.RemoveExploitMitigations();

                                        break;
                                    }

                                default:
                                    break;
                            }

                        });

                        // Update the UI Elements at the end of the run
                        await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
                        {
                            ExecuteButton.IsChecked = false; // Uncheck the ExecuteButton button to start the reverse animation
                        });

                        // mark as activity completed
                        HardenWindowsSecurity.ActivityTracker.IsActive = false;

                        // Display notification at the end
                        NewToastNotification.Show(NewToastNotification.ToastNotificationType.EndOfUnprotection, null, null, NotificationMessage, null);
                    }
                };

                // Cache the view before setting it as the CurrentView
                _viewCache["UnprotectView"] = HardenWindowsSecurity.GUIUnprotect.View;

                // Set the CurrentView to the Protect view
                CurrentView = HardenWindowsSecurity.GUIUnprotect.View;
            }
        }
    }
}
