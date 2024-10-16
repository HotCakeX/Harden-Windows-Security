using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Controls;
using static HardenWindowsSecurity.NewToastNotification;

#nullable enable

namespace HardenWindowsSecurity
{
    /// <summary>
    /// A class to store all of the data that is related to the GUI and its operations
    /// </summary>
    public static partial class GUIProtectWinSecurity
    {

        // The method that defines all of the event handlers for the UI elements
        public static void AddEventHandlers()
        {

            #region
            // null checks to make sure the elements are available to the AddEventHandlers method
            // LoadXaml method doesn't need the checks because these values are initialized in that method

            if (GUIProtectWinSecurity.View is null)
            {
                throw new InvalidOperationException("AddEventHandlers Method: Window object is empty!");
            }

            if (GUIProtectWinSecurity.categories is null)
            {
                throw new InvalidOperationException("AddEventHandlers Method: categories object is empty!");
            }

            if (GUIProtectWinSecurity.selectAllCategories is null)
            {
                throw new InvalidOperationException("AddEventHandlers Method: selectAllCategories object is empty!");
            }

            if (GUIProtectWinSecurity.subCategories is null)
            {
                throw new InvalidOperationException("AddEventHandlers Method: subCategories object is empty!");
            }

            if (GUIProtectWinSecurity.selectAllSubCategories is null)
            {
                throw new InvalidOperationException("AddEventHandlers Method: selectAllSubCategories object is empty!");
            }

            if (GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipTextBox is null)
            {
                throw new InvalidOperationException("AddEventHandlers Method: microsoft365AppsSecurityBaselineZipTextBox object is empty!");
            }

            if (GUIProtectWinSecurity.lgpoZipButton is null)
            {
                throw new InvalidOperationException("AddEventHandlers Method: lgpoZipButton object is empty!");
            }

            if (GUIProtectWinSecurity.lgpoZipTextBox is null)
            {
                throw new InvalidOperationException("AddEventHandlers Method: lgpoZipTextBox object is empty!");
            }

            if (GUIProtectWinSecurity.txtFilePath is null)
            {
                throw new InvalidOperationException("AddEventHandlers Method: txtFilePath object is empty!");
            }

            if (GUIProtectWinSecurity.enableOfflineMode is null)
            {
                throw new InvalidOperationException("AddEventHandlers Method: enableOfflineMode object is empty!");
            }

            if (GUIProtectWinSecurity.microsoftSecurityBaselineZipButton is null)
            {
                throw new InvalidOperationException("AddEventHandlers Method: microsoftSecurityBaselineZipButton object is empty!");
            }

            if (GUIProtectWinSecurity.microsoftSecurityBaselineZipTextBox is null)
            {
                throw new InvalidOperationException("AddEventHandlers Method: microsoftSecurityBaselineZipTextBox object is empty!");
            }

            if (GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipButton is null)
            {
                throw new InvalidOperationException("AddEventHandlers Method: microsoft365AppsSecurityBaselineZipButton object is empty!");
            }

            if (GUIProtectWinSecurity.ExecuteButton is null)
            {
                throw new InvalidOperationException("AddEventHandlers Method: ExecuteButton object is empty!");
            }

            #endregion


            // Add Checked and Unchecked event handlers to category checkboxes
            foreach (var item in GUIProtectWinSecurity.categories.Items)
            {
                ListViewItem categoryItem = (ListViewItem)item;
                CheckBox checkBox = (CheckBox)categoryItem.Content;
                checkBox.DataContext = categoryItem;
                checkBox.Checked += (sender, e) => UpdateSubCategories();
                checkBox.Unchecked += (sender, e) => UpdateSubCategories();
            }

            // Add click event for 'Check All' button
            GUIProtectWinSecurity.selectAllCategories.Checked += (sender, e) =>
            {

                if (HardenWindowsSecurity.GlobalVars.HardeningCategorieX is null)
                {
                    throw new System.ArgumentNullException("GlobalVars.HardeningCategorieX cannot be null.");
                }
                foreach (var item in GUIProtectWinSecurity.categories.Items)
                {
                    ListViewItem categoryItem = (ListViewItem)item;
                    if (HardenWindowsSecurity.GlobalVars.HardeningCategorieX.Contains(((CheckBox)categoryItem.Content).Name))
                    {
                        ((CheckBox)categoryItem.Content).IsChecked = true;
                    }
                }
            };

            // Add click event for 'Uncheck All' button
            GUIProtectWinSecurity.selectAllCategories.Unchecked += (sender, e) =>
            {
                foreach (var item in GUIProtectWinSecurity.categories.Items)
                {
                    ((CheckBox)((ListViewItem)item).Content).IsChecked = false;
                }
            };

            // Add click event for 'Check All' button for enabled sub-categories
            GUIProtectWinSecurity.selectAllSubCategories.Checked += (sender, e) =>
            {

                foreach (var item in GUIProtectWinSecurity.subCategories.Items)
                {
                    ListViewItem subCategoryItem = (ListViewItem)item;
                    if (subCategoryItem.IsEnabled)
                    {
                        ((CheckBox)subCategoryItem.Content).IsChecked = true;
                    }
                }
            };

            // Add click event for 'Uncheck All' button from sub-categories, regardless of whether they are enabled or disabled
            GUIProtectWinSecurity.selectAllSubCategories.Unchecked += (sender, e) =>
            {

                foreach (var item in GUIProtectWinSecurity.subCategories.Items)
                {
                    ((CheckBox)((ListViewItem)item).Content).IsChecked = false;
                }
            };


            // Add Checked event handler to enable offline mode controls/buttons
            // When the Offline Mode button it toggled
            GUIProtectWinSecurity.enableOfflineMode.Checked += (sender, e) =>
            {
                GUIProtectWinSecurity.microsoftSecurityBaselineZipButton.IsEnabled = true;
                GUIProtectWinSecurity.microsoftSecurityBaselineZipTextBox.IsEnabled = true;
                GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipButton.IsEnabled = true;
                GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipTextBox.IsEnabled = true;
                GUIProtectWinSecurity.lgpoZipButton.IsEnabled = true;
                GUIProtectWinSecurity.lgpoZipTextBox.IsEnabled = true;
            };

            // Add Unchecked event handler to disable offline mode controls/buttons
            GUIProtectWinSecurity.enableOfflineMode.Unchecked += (sender, e) =>
            {
                DisableOfflineModeConfigInputs();
            };


            // Define the click event for the Microsoft Security Baseline Zip button
            GUIProtectWinSecurity.microsoftSecurityBaselineZipButton.Click += (sender, e) =>
            {
                var dialog = new OpenFileDialog
                {
                    InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                    Filter = "Zip files (*.zip)|*.zip",
                    Title = "Select the Microsoft Security Baseline Zip file"
                };

                // Show the dialog and process the result
                if (dialog.ShowDialog() == true)
                {
                    try
                    {
                        // Check if the file contains the required script
                        if (!HardenWindowsSecurity.SneakAndPeek.Search("Windows*Security Baseline/Scripts/Baseline-LocalInstall.ps1", dialog.FileName))
                        {
                            HardenWindowsSecurity.Logger.LogMessage("The selected Zip file does not contain the Microsoft Security Baselines Baseline-LocalInstall.ps1 which is required for the Harden Windows Security App to work properly", LogTypeIntel.WarningInteractionRequired);
                        }
                        else
                        {
                            // For displaying the text on the GUI's text box
                            GUIProtectWinSecurity.microsoftSecurityBaselineZipTextBox.Text = dialog.FileName;
                            // The actual value that will be used
                            GUIProtectWinSecurity.MicrosoftSecurityBaselineZipPath = dialog.FileName;
                        }
                    }
                    catch (Exception ex)
                    {
                        // Log the exception if any error occurs
                        HardenWindowsSecurity.Logger.LogMessage(ex.Message, LogTypeIntel.Error);
                    }
                }
            };

            // Define the click event for the Microsoft 365 Apps Security Baseline Zip button
            GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipButton.Click += (sender, e) =>
            {
                var dialog = new OpenFileDialog
                {
                    InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                    Filter = "Zip files (*.zip)|*.zip",
                    Title = "Select the Microsoft 365 Apps Security Baseline Zip file"
                };

                // Show the dialog and process the result
                if (dialog.ShowDialog() == true)
                {
                    try
                    {
                        // Check if the file contains the required script
                        if (!HardenWindowsSecurity.SneakAndPeek.Search("Microsoft 365 Apps for Enterprise*/Scripts/Baseline-LocalInstall.ps1", dialog.FileName))
                        {
                            HardenWindowsSecurity.Logger.LogMessage("The selected Zip file does not contain the Microsoft 365 Apps for Enterprise Security Baselines Baseline-LocalInstall.ps1 which is required for the Harden Windows Security App to work properly", LogTypeIntel.WarningInteractionRequired);
                        }
                        else
                        {
                            // For displaying the text on the GUI's text box
                            GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipTextBox.Text = dialog.FileName;
                            // The actual value that will be used
                            GUIProtectWinSecurity.Microsoft365AppsSecurityBaselineZipPath = dialog.FileName;
                        }
                    }
                    catch (Exception ex)
                    {
                        // Log the exception if any error occurs
                        HardenWindowsSecurity.Logger.LogMessage(ex.Message, LogTypeIntel.Error);
                    }
                }
            };

            // Define the click event for the LGPO Zip button
            GUIProtectWinSecurity.lgpoZipButton.Click += (sender, e) =>
            {
                var dialog = new OpenFileDialog
                {
                    InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                    Filter = "Zip files (*.zip)|*.zip",
                    Title = "Select the LGPO Zip file"
                };

                // Show the dialog and process the result
                if (dialog.ShowDialog() == true)
                {
                    try
                    {
                        // Check if the file contains the required LGPO.exe
                        if (!HardenWindowsSecurity.SneakAndPeek.Search("LGPO_*/LGPO.exe", dialog.FileName))
                        {
                            HardenWindowsSecurity.Logger.LogMessage("The selected Zip file does not contain the LGPO.exe which is required for the Harden Windows Security App to work properly", LogTypeIntel.WarningInteractionRequired);
                        }
                        else
                        {
                            // For displaying the text on the GUI's text box
                            GUIProtectWinSecurity.lgpoZipTextBox.Text = dialog.FileName;
                            // The actual value that will be used
                            GUIProtectWinSecurity.LGPOZipPath = dialog.FileName;
                        }
                    }
                    catch (Exception ex)
                    {
                        // Log the exception if any error occurs
                        HardenWindowsSecurity.Logger.LogMessage(ex.Message, LogTypeIntel.Error);
                    }
                }
            };



            // Defining a set of commands to run when the GUI window is loaded, async
            GUIProtectWinSecurity.View.Loaded += async (sender, e) =>
            {

                // Only continue if there is no activity in other places
                if (!HardenWindowsSecurity.ActivityTracker.IsActive)
                {
                    // mark as activity started
                    HardenWindowsSecurity.ActivityTracker.IsActive = true;

                    // Only proceed if this event hasn't already been triggered
                    if (!HardenWindowsSecurity.GUIProtectWinSecurity.LoadEventHasBeenTriggered)
                    {

                        // Set the flag to true indicating the view loaded event has been triggered
                        HardenWindowsSecurity.GUIProtectWinSecurity.LoadEventHasBeenTriggered = true;

                        // Run this entire section, including the downloading part, asynchronously

                        #region Initial Preset Configuration
                        // Configure the categories and sub-categories for the Recommended preset when the Protect view page is first loaded
                        GUIMain.app!.Dispatcher.Invoke(() =>
                        {

                            string presetName = "preset: recommended";

                            // Check if the preset exists in the dictionary
                            if (GUIProtectWinSecurity.PresetsIntel.TryGetValue(presetName, out var categoriesAndSubcategories))
                            {
                                // Access the categories and subcategories
                                List<string> categories = categoriesAndSubcategories["Categories"];
                                List<string> subcategories = categoriesAndSubcategories["SubCategories"];

                                // Loop over each category in the dictionary
                                foreach (string category in categories)
                                {

                                    // Loop over each category in the GUI
                                    foreach (var item in GUIProtectWinSecurity.categories.Items)
                                    {
                                        // Get the category item list view item
                                        ListViewItem categoryItem = (ListViewItem)item;

                                        // get the name of the list view item as string
                                        string categoryItemName = ((CheckBox)categoryItem.Content).Name.ToString();

                                        // if the category is authorized to be available
                                        if (HardenWindowsSecurity.GlobalVars.HardeningCategorieX!.Contains(categoryItemName))
                                        {
                                            // If the name of the current checkbox list view item in the loop is the same as the category name in the outer loop, then set the category on the GUI to checked
                                            if (string.Equals(categoryItemName, category, StringComparison.OrdinalIgnoreCase))
                                            {
                                                ((CheckBox)categoryItem.Content).IsChecked = true;
                                            }

                                        }
                                    }
                                }

                                foreach (string subcategory in subcategories)
                                {

                                    // Loop over each sub-category in the GUI
                                    foreach (var item in GUIProtectWinSecurity.subCategories.Items)
                                    {
                                        // Get the sub-category item list view item
                                        ListViewItem SubCategoryItem = (ListViewItem)item;

                                        // get the name of the list view item as string
                                        string SubcategoryItemName = ((CheckBox)SubCategoryItem.Content).Name.ToString();

                                        // If the name of the current checkbox list view item in the loop is the same as the sub-category name in the outer loop, then set the sub-category on the GUI to checked
                                        if (string.Equals(SubcategoryItemName, subcategory, StringComparison.OrdinalIgnoreCase))
                                        {
                                            ((CheckBox)SubCategoryItem.Content).IsChecked = true;
                                        }

                                    }
                                }
                            }
                            else
                            {
                                Logger.LogMessage($"Preset '{presetName}' not found.", LogTypeIntel.Error);
                            }

                        });
                        #endregion

                        try
                        {

                            #region Display a Welcome message

                            string nameToDisplay = (!string.IsNullOrWhiteSpace(GlobalVars.userFullName)) ? GlobalVars.userFullName : GlobalVars.userName;

                            HardenWindowsSecurity.Logger.LogMessage(HardenWindowsSecurity.UserPrivCheck.IsAdmin() ? $"Hello {nameToDisplay}, Running as Administrator" : $"Hello {nameToDisplay}, Running as Non-Administrator, some categories are disabled", LogTypeIntel.Information);
                            #endregion

                            // Use Dispatcher.Invoke to update the UI thread
                            HardenWindowsSecurity.GUIProtectWinSecurity.View.Dispatcher.Invoke(() =>
                            {
                                // Set the execute button to disabled until all the prerequisites are met
                                HardenWindowsSecurity.GUIProtectWinSecurity.ExecuteButton.IsEnabled = false;

                                // Start the execute button's operation to show the files are being downloaded
                                HardenWindowsSecurity.GUIProtectWinSecurity.ExecuteButton.IsChecked = true;
                            });

                            // Only download and process the files when the GUI is loaded and if Offline mode is not used
                            // Because at this point, the user might have not selected the files to be used for offline operation
                            if (!HardenWindowsSecurity.GlobalVars.Offline)
                            {
                                HardenWindowsSecurity.Logger.LogMessage("Downloading the required files", LogTypeIntel.Information);

                                // Run the file download process asynchronously
                                await Task.Run(() =>
                                {
                                    HardenWindowsSecurity.AsyncDownloader.PrepDownloadedFiles(
                                        LGPOPath: HardenWindowsSecurity.GUIProtectWinSecurity.LGPOZipPath,
                                        MSFTSecurityBaselinesPath: HardenWindowsSecurity.GUIProtectWinSecurity.MicrosoftSecurityBaselineZipPath,
                                        MSFT365AppsSecurityBaselinesPath: HardenWindowsSecurity.GUIProtectWinSecurity.Microsoft365AppsSecurityBaselineZipPath,
                                        false
                                    );
                                });

                                HardenWindowsSecurity.Logger.LogMessage("Finished downloading the required files", LogTypeIntel.Information);
                            }

                            // Using Dispatcher since the execute button is owned by the GUI thread, and we're in another thread
                            // Enabling the execute button after all files are downloaded and ready or if Offline switch was used and download was skipped
                            HardenWindowsSecurity.GUIProtectWinSecurity.View.Dispatcher.Invoke(() =>
                            {
                                HardenWindowsSecurity.GUIProtectWinSecurity.ExecuteButton.IsEnabled = true;
                                HardenWindowsSecurity.GUIProtectWinSecurity.ExecuteButton.IsChecked = false;
                            });
                        }
                        catch (Exception ex)
                        {
                            HardenWindowsSecurity.Logger.LogMessage($"An error occurred while downloading the required files: {ex.Message}", LogTypeIntel.Error);
                            HardenWindowsSecurity.Logger.LogMessage($"{ex.StackTrace}", LogTypeIntel.Error);
                            HardenWindowsSecurity.Logger.LogMessage($"{ex.InnerException}", LogTypeIntel.Error);
                            // Re-throw the exception to ensure it's caught and handled appropriately
                            //   throw;
                        }
                    }

                    // mark as activity finished
                    HardenWindowsSecurity.ActivityTracker.IsActive = false;
                }
            };


            // When Execute button is pressed
            GUIProtectWinSecurity.ExecuteButton.Click += async (sender, e) =>
           {
               // Only continue if there is no activity in other places
               if (!HardenWindowsSecurity.ActivityTracker.IsActive)
               {
                   // mark as activity started
                   HardenWindowsSecurity.ActivityTracker.IsActive = true;

                   // Everything will run in a different thread
                   await Task.Run(() =>
                   {

                       bool OfflineGreenLightStatus = false;
                       bool OfflineModeToggleStatus = false;

                       // Dispatcher to interact with the GUI elements
                       HardenWindowsSecurity.GUIProtectWinSecurity.View.Dispatcher.Invoke(() =>
                       {
                           // Call the method to get the selected categories and sub-categories
                           HardenWindowsSecurity.GUIProtectWinSecurity.ExecuteButtonPress();
                           // Disable the TextFilePath for the log file path
                           HardenWindowsSecurity.GUIProtectWinSecurity.txtFilePath!.IsEnabled = false;
                       });

                       // If Offline mode is used
                       if (HardenWindowsSecurity.GlobalVars.Offline)
                       {

                           HardenWindowsSecurity.GUIProtectWinSecurity.View.Dispatcher.Invoke(() =>
                           {

                               // Handle the nullable boolean
                               if (HardenWindowsSecurity.GUIProtectWinSecurity.enableOfflineMode.IsChecked.HasValue)
                               {
                                   OfflineModeToggleStatus = HardenWindowsSecurity.GUIProtectWinSecurity.enableOfflineMode.IsChecked.Value;
                               }

                               OfflineGreenLightStatus =
                                   !string.IsNullOrWhiteSpace(HardenWindowsSecurity.GUIProtectWinSecurity.microsoftSecurityBaselineZipTextBox.Text) &&
                                   !string.IsNullOrWhiteSpace(HardenWindowsSecurity.GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipTextBox.Text) &&
                                   !string.IsNullOrWhiteSpace(HardenWindowsSecurity.GUIProtectWinSecurity.lgpoZipTextBox.Text);
                           });


                           // If the required files have not been processed for offline mode already
                           if (!HardenWindowsSecurity.GUIProtectWinSecurity.StartFileDownloadHasRun)
                           {
                               // If the checkbox on the GUI for Offline mode is checked
                               if (OfflineModeToggleStatus)
                               {
                                   // Make sure all 3 fields for offline mode files were selected by the users and they are neither empty nor null
                                   if (OfflineGreenLightStatus)
                                   {

                                       // Process the offline mode files selected by the user
                                       HardenWindowsSecurity.AsyncDownloader.PrepDownloadedFiles(
                                      LGPOPath: HardenWindowsSecurity.GUIProtectWinSecurity.LGPOZipPath,
                                      MSFTSecurityBaselinesPath: HardenWindowsSecurity.GUIProtectWinSecurity.MicrosoftSecurityBaselineZipPath,
                                      MSFT365AppsSecurityBaselinesPath: HardenWindowsSecurity.GUIProtectWinSecurity.Microsoft365AppsSecurityBaselineZipPath,
                                      false
                                       );

                                       HardenWindowsSecurity.Logger.LogMessage("Finished processing the required files", LogTypeIntel.Information);

                                       // Set a flag indicating this code block should not run again when the execute button is pressed
                                       HardenWindowsSecurity.GUIProtectWinSecurity.StartFileDownloadHasRun = true;

                                   }
                                   else
                                   {
                                       HardenWindowsSecurity.Logger.LogMessage("Enable Offline Mode checkbox is checked but you have not selected all of the 3 required files for offline mode operation. Please select them and press the execute button again.", LogTypeIntel.WarningInteractionRequired);
                                   }
                               }
                               else
                               {
                                   HardenWindowsSecurity.Logger.LogMessage("Offline mode is being used but the Enable Offline Mode checkbox is not checked. Please check it and press the execute button again.", LogTypeIntel.WarningInteractionRequired);
                               }
                           }
                       }

                       if (!HardenWindowsSecurity.GlobalVars.Offline || (HardenWindowsSecurity.GlobalVars.Offline && HardenWindowsSecurity.GUIProtectWinSecurity.StartFileDownloadHasRun))
                       {

                           if (!HardenWindowsSecurity.GUIProtectWinSecurity.SelectedCategories.IsEmpty)
                           {

                               // Loop over the ConcurrentQueue that contains the Categories
                               foreach (string Category in HardenWindowsSecurity.GUIProtectWinSecurity.SelectedCategories)
                               {

                                   // A switch for the Categories
                                   switch (Category)
                                   {

                                       case "MicrosoftSecurityBaselines":
                                           {
                                               if (HardenWindowsSecurity.GUIProtectWinSecurity.SelectedSubCategories.Contains("SecBaselines_NoOverrides"))
                                               {
                                                   HardenWindowsSecurity.MicrosoftSecurityBaselines.Invoke();
                                               }
                                               else
                                               {
                                                   HardenWindowsSecurity.MicrosoftSecurityBaselines.Invoke();
                                                   HardenWindowsSecurity.MicrosoftSecurityBaselines.SecBaselines_Overrides();
                                               }
                                               break;
                                           }
                                       case "Microsoft365AppsSecurityBaselines":
                                           {
                                               HardenWindowsSecurity.Microsoft365AppsSecurityBaselines.Invoke();
                                               break;
                                           }
                                       case "MicrosoftDefender":
                                           {
                                               HardenWindowsSecurity.MicrosoftDefender.Invoke();

                                               if (HardenWindowsSecurity.GUIProtectWinSecurity.SelectedSubCategories.Contains("MSFTDefender_SAC"))
                                               {
                                                   HardenWindowsSecurity.MicrosoftDefender.MSFTDefender_SAC();
                                               }

                                               if (HardenWindowsSecurity.GlobalVars.ShouldEnableOptionalDiagnosticData || string.Equals(PropertyHelper.GetPropertyValue(GlobalVars.MDAVConfigCurrent, "SmartAppControlState") ?? string.Empty, "on", StringComparison.OrdinalIgnoreCase))
                                               {
                                                   HardenWindowsSecurity.Logger.LogMessage("Enabling Optional Diagnostic Data because SAC is on or user selected to turn it on", LogTypeIntel.Information);
                                                   HardenWindowsSecurity.MicrosoftDefender.MSFTDefender_EnableDiagData();
                                               }

                                               if (!string.Equals(PropertyHelper.GetPropertyValue(GlobalVars.MDAVConfigCurrent, "SmartAppControlState") ?? string.Empty, "off", StringComparison.OrdinalIgnoreCase))
                                               {
                                                   if (HardenWindowsSecurity.GUIProtectWinSecurity.SelectedSubCategories.Contains("MSFTDefender_NoDiagData"))
                                                   {
                                                       // do nothing
                                                   }
                                               }

                                               if (!HardenWindowsSecurity.GUIProtectWinSecurity.SelectedSubCategories.Contains("MSFTDefender_NoScheduledTask"))
                                               {
                                                   HardenWindowsSecurity.MicrosoftDefender.MSFTDefender_ScheduledTask();
                                               }

                                               if (HardenWindowsSecurity.GUIProtectWinSecurity.SelectedSubCategories.Contains("MSFTDefender_BetaChannels"))
                                               {
                                                   HardenWindowsSecurity.MicrosoftDefender.MSFTDefender_BetaChannels();
                                               }
                                               break;
                                           }
                                       case "AttackSurfaceReductionRules":
                                           {
                                               HardenWindowsSecurity.AttackSurfaceReductionRules.Invoke();
                                               break;
                                           }
                                       case "BitLockerSettings":
                                           {
                                               HardenWindowsSecurity.BitLockerSettings.Invoke();
                                               break;
                                           }
                                       case "DeviceGuard":
                                           {
                                               HardenWindowsSecurity.DeviceGuard.Invoke();
                                               break;
                                           }
                                       case "TLSSecurity":
                                           {
                                               HardenWindowsSecurity.TLSSecurity.Invoke();
                                               break;
                                           }
                                       case "LockScreen":
                                           {
                                               HardenWindowsSecurity.LockScreen.Invoke();

                                               if (HardenWindowsSecurity.GUIProtectWinSecurity.SelectedSubCategories.Contains("LockScreen_CtrlAltDel"))
                                               {
                                                   HardenWindowsSecurity.LockScreen.LockScreen_CtrlAltDel();
                                               }
                                               if (HardenWindowsSecurity.GUIProtectWinSecurity.SelectedSubCategories.Contains("LockScreen_NoLastSignedIn"))
                                               {
                                                   HardenWindowsSecurity.LockScreen.LockScreen_LastSignedIn();
                                               }
                                               break;
                                           }
                                       case "UserAccountControl":
                                           {
                                               HardenWindowsSecurity.UserAccountControl.Invoke();

                                               if (HardenWindowsSecurity.GUIProtectWinSecurity.SelectedSubCategories.Contains("UAC_NoFastSwitching"))
                                               {
                                                   HardenWindowsSecurity.UserAccountControl.UAC_NoFastSwitching();
                                               }
                                               if (HardenWindowsSecurity.GUIProtectWinSecurity.SelectedSubCategories.Contains("UAC_OnlyElevateSigned"))
                                               {
                                                   HardenWindowsSecurity.UserAccountControl.UAC_OnlyElevateSigned();
                                               }

                                               break;
                                           }
                                       case "WindowsFirewall":
                                           {
                                               HardenWindowsSecurity.WindowsFirewall.Invoke();
                                               break;
                                           }
                                       case "OptionalWindowsFeatures":
                                           {
                                               HardenWindowsSecurity.OptionalWindowsFeatures.Invoke();
                                               break;
                                           }
                                       case "WindowsNetworking":
                                           {
                                               HardenWindowsSecurity.WindowsNetworking.Invoke();

                                               if (HardenWindowsSecurity.GUIProtectWinSecurity.SelectedSubCategories.Contains("WindowsNetworking_BlockNTLM"))
                                               {
                                                   HardenWindowsSecurity.WindowsNetworking.WindowsNetworking_BlockNTLM();
                                               }

                                               break;
                                           }
                                       case "MiscellaneousConfigurations":
                                           {
                                               HardenWindowsSecurity.MiscellaneousConfigurations.Invoke();

                                               if (HardenWindowsSecurity.GUIProtectWinSecurity.SelectedSubCategories.Contains("Miscellaneous_WindowsProtectedPrint"))
                                               {
                                                   HardenWindowsSecurity.MiscellaneousConfigurations.MiscellaneousConfigurations_WindowsProtectedPrint();
                                               }

                                               break;
                                           }
                                       case "WindowsUpdateConfigurations":
                                           {
                                               HardenWindowsSecurity.WindowsUpdateConfigurations.Invoke();
                                               break;
                                           }
                                       case "EdgeBrowserConfigurations":
                                           {
                                               HardenWindowsSecurity.EdgeBrowserConfigurations.Invoke();
                                               break;
                                           }
                                       case "CertificateCheckingCommands":
                                           {
                                               HardenWindowsSecurity.CertificateCheckingCommands.Invoke();
                                               break;
                                           }
                                       case "CountryIPBlocking":
                                           {
                                               HardenWindowsSecurity.CountryIPBlocking.Invoke();

                                               if (HardenWindowsSecurity.GUIProtectWinSecurity.SelectedSubCategories.Contains("CountryIPBlocking_OFAC"))
                                               {
                                                   HardenWindowsSecurity.CountryIPBlocking.CountryIPBlocking_OFAC();
                                               }
                                               break;
                                           }
                                       case "DownloadsDefenseMeasures":
                                           {
                                               HardenWindowsSecurity.DownloadsDefenseMeasures.Invoke();
                                               if (HardenWindowsSecurity.GUIProtectWinSecurity.SelectedSubCategories.Contains("DangerousScriptHostsBlocking"))
                                               {
                                                   HardenWindowsSecurity.DownloadsDefenseMeasures.DangerousScriptHostsBlocking();
                                               }
                                               break;
                                           }
                                       case "NonAdminCommands":
                                           {
                                               HardenWindowsSecurity.NonAdminCommands.Invoke();
                                               break;
                                           }

                                       default:
                                           break;
                                   }
                               }

                               if (HardenWindowsSecurity.GlobalVars.UseNewNotificationsExp)
                               {
                                   HardenWindowsSecurity.NewToastNotification.Show(ToastNotificationType.EndOfProtection, null, null, null, null);
                               }
                           }
                           else
                           {
                               HardenWindowsSecurity.Logger.LogMessage("No category was selected", LogTypeIntel.Warning);
                           }
                       }

                       HardenWindowsSecurity.GUIProtectWinSecurity.View.Dispatcher.Invoke(() =>
                       {
                           // Manually trigger the ToggleButton to be unchecked to trigger the ending animation
                           HardenWindowsSecurity.GUIProtectWinSecurity.ExecuteButton!.IsChecked = false;

                           // Only enable the log file path TextBox if the log toggle button is toggled
                           if (GUIProtectWinSecurity.log!.IsChecked == true)
                           {
                               HardenWindowsSecurity.GUIProtectWinSecurity.txtFilePath!.IsEnabled = true;
                           }
                       });

                   });

                   // mark as activity completed
                   HardenWindowsSecurity.ActivityTracker.IsActive = false;
               }
           };
        }
    }
}
