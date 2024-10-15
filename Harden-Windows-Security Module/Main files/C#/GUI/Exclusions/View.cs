using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
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

            // Method to handle the Exclusions view, including loading
            private void Exclusions(object obj)
            {
                // Check if the view is already cached
                if (_viewCache.TryGetValue("ExclusionsView", out var cachedView))
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
                    Logger.LogMessage("Exclusions page can only be used when running the Harden Windows Security Application with Administrator privileges", LogTypeIntel.ErrorInteractionRequired);
                    return;
                }

                // Construct the file path for the Exclusions view XAML
                string xamlPath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "XAML", "Exclusions.xaml");

                // Read the XAML content from the file
                string xamlContent = File.ReadAllText(xamlPath);

                // Parse the XAML content to create a UserControl
                HardenWindowsSecurity.GUIExclusions.View = (UserControl)XamlReader.Parse(xamlContent);

                // Set the DataContext for the Exclusions view
                GUIExclusions.View.DataContext = new ExclusionsVM();

                // Find the Parent Grid
                HardenWindowsSecurity.GUIExclusions.ParentGrid = (Grid)HardenWindowsSecurity.GUIExclusions.View.FindName("ParentGrid");

                #region finding Execute button related elements

                // Finding the Execute Button Grid
                Grid? ExecuteButtonGrid = GUIExclusions.ParentGrid.FindName("ExecuteButtonGrid") as Grid ?? throw new InvalidOperationException("ExecuteButtonGrid is null in the Exclusions View");

                // Finding the Execute Button
                ToggleButton? ExecuteButton = ExecuteButtonGrid.FindName("ExecuteButton") as ToggleButton ?? throw new InvalidOperationException("Couldn't find the ExecuteButton in Exclusions view");

                // Apply the template to make sure it's available
                _ = ExecuteButton.ApplyTemplate();

                // Access the image within the Execute Button's template
                if (ExecuteButton.Template.FindName("RefreshIconImage", ExecuteButton) is not Image RefreshIconImage)
                {
                    throw new InvalidOperationException("RefreshIconImage could not be found in the Exclusions view");
                }

                // Update the image source for the Refresh button
                // Load the Refresh icon image into memory and set it as the source
                var RefreshIconBitmapImage = new BitmapImage();
                RefreshIconBitmapImage.BeginInit();
                RefreshIconBitmapImage.UriSource = new System.Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "ExecuteButton.png"));
                RefreshIconBitmapImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
                RefreshIconBitmapImage.EndInit();

                RefreshIconImage.Source = RefreshIconBitmapImage;

                #endregion


                #region Finding other elements

                ToggleButton? MicrosoftDefenderToggleButton = GUIExclusions.ParentGrid.FindName("MicrosoftDefenderToggleButton") as ToggleButton;
                ToggleButton? ControlledFolderAccessToggleButton = GUIExclusions.ParentGrid.FindName("ControlledFolderAccessToggleButton") as ToggleButton;
                ToggleButton? AttackSurfaceReductionRulesToggleButton = GUIExclusions.ParentGrid.FindName("AttackSurfaceReductionRulesToggleButton") as ToggleButton;

                TextBox? SelectedFilePaths = GUIExclusions.ParentGrid.FindName("SelectedFilePaths") as TextBox ?? throw new InvalidOperationException("Couldn't find SelectedFilePaths in the Exclusions view.");

                Button? BrowseForFilesButton = GUIExclusions.ParentGrid.FindName("BrowseForFilesButton") as Button ?? throw new InvalidOperationException("Couldn't find BrowseForFilesButton in the Exclusions view.");

                // Finding the button's image to assign an icon to it
                Image? BrowseButtonIcon = GUIExclusions.ParentGrid.FindName("BrowseButtonIcon") as Image ?? throw new InvalidOperationException("Couldn't find BrowseButtonIcon in the Exclusions view.");

                // BrowseButtonIconImage
                var BrowseButtonIconImage = new BitmapImage();
                BrowseButtonIconImage.BeginInit();
                BrowseButtonIconImage.UriSource = new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "BrowseButtonIconBlack.png"));
                BrowseButtonIconImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
                BrowseButtonIconImage.EndInit();
                BrowseButtonIcon.Source = BrowseButtonIconImage;

                #endregion


                // Event handler for Browse Button
                BrowseForFilesButton.Click += (sender, e) =>
                {

                    GUIExclusions.selectedFiles = null;

                    // Create OpenFileDialog instance
                    OpenFileDialog openFileDialog = new()
                    {
                        // Set the title of the dialog
                        Title = "Select Executable Files for Exclusion",

                        // Allow multiple file selection
                        Multiselect = true,

                        // Filter to only show .exe files
                        Filter = "Executable Files (*.exe)|*.exe"
                    };

                    // Show the dialog and check if the user selected files
                    if (openFileDialog.ShowDialog() == true)
                    {
                        // Retrieve selected file paths
                        GUIExclusions.selectedFiles = openFileDialog.FileNames;

                        // First clear the TextBox from any previous items
                        SelectedFilePaths.Text = null;

                        // Add the selected paths to the TextBlock for display purposes
                        foreach (string file in GUIExclusions.selectedFiles)
                        {
                            SelectedFilePaths.Text += file + Environment.NewLine;

                            HardenWindowsSecurity.Logger.LogMessage($"Selected file path: {file}", LogTypeIntel.Information);
                        }
                    }

                };


                // Register the ExecuteButton as an element that will be enabled/disabled based on current activity
                HardenWindowsSecurity.ActivityTracker.RegisterUIElement(ExecuteButton);
                HardenWindowsSecurity.ActivityTracker.RegisterUIElement(BrowseForFilesButton);
                HardenWindowsSecurity.ActivityTracker.RegisterUIElement(BrowseForFilesButton);
                HardenWindowsSecurity.ActivityTracker.RegisterUIElement(BrowseForFilesButton);
                HardenWindowsSecurity.ActivityTracker.RegisterUIElement(BrowseForFilesButton);

                // Add the path to the Controlled folder access backup list of the Harden Windows Security
                // Only if it's not already in here
                // This way after the CFA exclusions restore at the end, the changes made here will continue to exist
                static void AddItemToBackup(string itemToAdd)
                {
                    // Check if CFABackup is null; if so, initialize it
                    GlobalVars.CFABackup ??= [];

                    // Convert GlobalVars.CFABackup to a List for easier manipulation
                    var CFABackupLocal = new List<string>(GlobalVars.CFABackup!);

                    // Check if the item is not already in the list
                    if (!CFABackupLocal.Contains(itemToAdd))
                    {
                        CFABackupLocal.Add(itemToAdd);
                    }

                    // Convert the list back to an array
                    GlobalVars.CFABackup = [.. CFABackupLocal];
                }



                // Set up the Click event handler for the ExecuteButton button
                ExecuteButton.Click += async (sender, e) =>
                    {
                        // Only continue if there is no activity other places
                        if (!HardenWindowsSecurity.ActivityTracker.IsActive)
                        {
                            // mark as activity started
                            HardenWindowsSecurity.ActivityTracker.IsActive = true;

                            // Get the status of the toggle buttons using dispatcher and update the bool variables accordingly
                            // This way, we won't need to run the actual job in the dispatcher thread
                            System.Windows.Application.Current.Dispatcher.Invoke(() =>
                            {
                                GUIExclusions.MicrosoftDefenderToggleButtonStatus = MicrosoftDefenderToggleButton?.IsChecked ?? false;
                                GUIExclusions.ControlledFolderAccessToggleButtonStatus = ControlledFolderAccessToggleButton?.IsChecked ?? false;
                                GUIExclusions.AttackSurfaceReductionRulesToggleButtonStatus = AttackSurfaceReductionRulesToggleButton?.IsChecked ?? false;

                            });

                            // Run the exclusion addition job asynchronously in a different thread
                            await System.Threading.Tasks.Task.Run(() =>
                            {

                                // If user selected file paths
                                if (GUIExclusions.selectedFiles is not null)
                                {

                                    #region Getting the current exclusion lists

                                    // These already run in the Initialize() method but we need them up to date after user adds files to the exclusions and then presses the execute button again

                                    // Get the MSFT_MpPreference WMI results and save them to the global variable HardenWindowsSecurity.GlobalVars.MDAVPreferencesCurrent
                                    HardenWindowsSecurity.GlobalVars.MDAVPreferencesCurrent = HardenWindowsSecurity.MpPreferenceHelper.GetMpPreference();


                                    // Attempt to retrieve the property value as string[]
                                    string[] ExclusionPathArray = HardenWindowsSecurity.PropertyHelper.GetPropertyValue(HardenWindowsSecurity.GlobalVars.MDAVPreferencesCurrent, "ExclusionPath");

                                    // Check if the result is not null, then convert to List<string>, or initialize an empty list if null
                                    List<string> ExclusionPathList = ExclusionPathArray is not null
                                        ? new List<string>(ExclusionPathArray)
                                        : [];


                                    // Attempt to retrieve the property value as string[]
                                    string[] ControlledFolderAccessAllowedApplicationsArray = HardenWindowsSecurity.PropertyHelper.GetPropertyValue(HardenWindowsSecurity.GlobalVars.MDAVPreferencesCurrent, "ControlledFolderAccessAllowedApplications");

                                    // Check if the result is not null, then convert to List<string>, or initialize an empty list if null
                                    List<string> ControlledFolderAccessAllowedApplicationsList = ControlledFolderAccessAllowedApplicationsArray is not null
                                        ? new List<string>(ControlledFolderAccessAllowedApplicationsArray)
                                        : [];


                                    // Attempt to retrieve the property value as string[]
                                    string[] attackSurfaceReductionOnlyExclusionsArray = HardenWindowsSecurity.PropertyHelper.GetPropertyValue(HardenWindowsSecurity.GlobalVars.MDAVPreferencesCurrent, "AttackSurfaceReductionOnlyExclusions");

                                    // Check if the result is not null, then convert to List<string>, or initialize an empty list if null
                                    // Makes it easier to check items in it later
                                    List<string> attackSurfaceReductionOnlyExclusionsList = attackSurfaceReductionOnlyExclusionsArray is not null
                                        ? new List<string>(attackSurfaceReductionOnlyExclusionsArray)
                                        : [];
                                    #endregion


                                    // Loop over each user selected file path
                                    foreach (string path in GUIExclusions.selectedFiles)
                                    {

                                        // check for toggle button status
                                        if (GUIExclusions.MicrosoftDefenderToggleButtonStatus)
                                        {

                                            if (!ExclusionPathList.Contains(path))
                                            {
                                                Logger.LogMessage($"Adding {path} to the Microsoft Defender exclusions list", LogTypeIntel.Information);

                                                // ADD the program path to the Microsoft Defender's main Exclusions
                                                HardenWindowsSecurity.ConfigDefenderHelper.ManageMpPreference<string[]>("ExclusionPath", [path], false);
                                            }
                                            else
                                            {
                                                Logger.LogMessage($"{path} already exists in the Microsoft Defender exclusions list, skipping.", LogTypeIntel.Information);
                                            }

                                        }

                                        // check for toggle button status
                                        if (GUIExclusions.ControlledFolderAccessToggleButtonStatus)
                                        {
                                            if (!ControlledFolderAccessAllowedApplicationsList.Contains(path))
                                            {

                                                Logger.LogMessage($"Adding {path} to the Controlled Folder Access Allowed Applications", LogTypeIntel.Information);

                                                // ADD the program path to the Controlled Folder Access Exclusions
                                                HardenWindowsSecurity.ConfigDefenderHelper.ManageMpPreference<string[]>("ControlledFolderAccessAllowedApplications", [path], false);

                                                // ADD the same path for CFA to the CFA backup that the program uses by default so that during the restore, the user change will be included and not left out
                                                AddItemToBackup(path);
                                            }
                                            else
                                            {
                                                Logger.LogMessage($"{path} already exists in the Controlled Folder Access Allowed Applications, skipping.", LogTypeIntel.Information);
                                            }
                                        }

                                        // check for toggle button status
                                        if (GUIExclusions.AttackSurfaceReductionRulesToggleButtonStatus)
                                        {
                                            if (!attackSurfaceReductionOnlyExclusionsList.Contains(path))
                                            {

                                                Logger.LogMessage($"Adding {path} to the Attack Surface Reduction Rules exclusions list", LogTypeIntel.Information);

                                                // ADD the program path to the Attack Surface Exclusions
                                                HardenWindowsSecurity.ConfigDefenderHelper.ManageMpPreference<string[]>("AttackSurfaceReductionOnlyExclusions", [path], false);
                                            }
                                            else
                                            {
                                                Logger.LogMessage($"{path} already exists in the Attack Surface Reduction Rules exclusions list, skipping.", LogTypeIntel.Information);
                                            }
                                        }

                                    }

                                    // Display notification at the end if files were selected
                                    NewToastNotification.Show(NewToastNotification.ToastNotificationType.EndOfExclusions, null, null, null, null);

                                }
                                else
                                {
                                    Logger.LogMessage("No file paths selected for exclusion addition, nothing to process.", LogTypeIntel.Information);
                                }

                            });

                            // Update the UI Elements at the end of the run
                            await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
                            {
                                ExecuteButton.IsChecked = false; // Uncheck the ExecuteButton button to start the reverse animation

                            });

                            // mark as activity completed
                            HardenWindowsSecurity.ActivityTracker.IsActive = false;
                        }
                    };

                // Cache the view before setting it as the CurrentView
                _viewCache["ExclusionsView"] = HardenWindowsSecurity.GUIExclusions.View;

                // Set the CurrentView to the Exclusions view
                CurrentView = HardenWindowsSecurity.GUIExclusions.View;
            }
        }
    }
}
