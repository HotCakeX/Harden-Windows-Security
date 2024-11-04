﻿using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Controls;

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

                if (GlobalVars.HardeningCategorieX is null)
                {
                    throw new ArgumentNullException("GlobalVars.HardeningCategorieX cannot be null.");
                }
                foreach (var item in GUIProtectWinSecurity.categories.Items)
                {
                    ListViewItem categoryItem = (ListViewItem)item;
                    if (GlobalVars.HardeningCategorieX.Contains(((CheckBox)categoryItem.Content).Name))
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
                OpenFileDialog dialog = new()
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
                        if (!SneakAndPeek.Search("Windows*Security Baseline/Scripts/Baseline-LocalInstall.ps1", dialog.FileName))
                        {
                            Logger.LogMessage("The selected Zip file does not contain the Microsoft Security Baselines Baseline-LocalInstall.ps1 which is required for the Harden Windows Security App to work properly", LogTypeIntel.WarningInteractionRequired);
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
                        Logger.LogMessage(ex.Message, LogTypeIntel.Error);
                    }
                }
            };

            // Define the click event for the Microsoft 365 Apps Security Baseline Zip button
            GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipButton.Click += (sender, e) =>
            {
                OpenFileDialog dialog = new()
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
                        if (!SneakAndPeek.Search("Microsoft 365 Apps for Enterprise*/Scripts/Baseline-LocalInstall.ps1", dialog.FileName))
                        {
                            Logger.LogMessage("The selected Zip file does not contain the Microsoft 365 Apps for Enterprise Security Baselines Baseline-LocalInstall.ps1 which is required for the Harden Windows Security App to work properly", LogTypeIntel.WarningInteractionRequired);
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
                        Logger.LogMessage(ex.Message, LogTypeIntel.Error);
                    }
                }
            };

            // Define the click event for the LGPO Zip button
            GUIProtectWinSecurity.lgpoZipButton.Click += (sender, e) =>
            {
                OpenFileDialog dialog = new()
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
                        if (!SneakAndPeek.Search("LGPO_*/LGPO.exe", dialog.FileName))
                        {
                            Logger.LogMessage("The selected Zip file does not contain the LGPO.exe which is required for the Harden Windows Security App to work properly", LogTypeIntel.WarningInteractionRequired);
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
                        Logger.LogMessage(ex.Message, LogTypeIntel.Error);
                    }
                }
            };



            // Defining a set of commands to run when the GUI window is loaded, async
            GUIProtectWinSecurity.View.Loaded += async (sender, e) =>
            {

                // Only continue if there is no activity in other places
                if (!ActivityTracker.IsActive)
                {
                    // mark as activity started
                    ActivityTracker.IsActive = true;

                    // Only proceed if this event hasn't already been triggered
                    if (!GUIProtectWinSecurity.LoadEventHasBeenTriggered)
                    {

                        // Set the flag to true indicating the view loaded event has been triggered
                        GUIProtectWinSecurity.LoadEventHasBeenTriggered = true;

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
                                        if (GlobalVars.HardeningCategorieX!.Contains(categoryItemName))
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

                            Logger.LogMessage(UserPrivCheck.IsAdmin() ? $"Hello {nameToDisplay}, you have Administrator privileges" : $"Hello {nameToDisplay}, you don't have Administrator privileges, some categories are disabled", LogTypeIntel.Information);
                            #endregion

                            // Use Dispatcher.Invoke to update the UI thread
                            GUIProtectWinSecurity.View.Dispatcher.Invoke(() =>
                            {
                                // Set the execute button to disabled until all the prerequisites are met
                                GUIProtectWinSecurity.ExecuteButton.IsEnabled = false;

                                // Start the execute button's operation to show the files are being downloaded
                                GUIProtectWinSecurity.ExecuteButton.IsChecked = true;
                            });

                            // Only download and process the files when the GUI is loaded and if Offline mode is not used
                            // Because at this point, the user might have not selected the files to be used for offline operation
                            if (!GlobalVars.Offline)
                            {
                                Logger.LogMessage("Downloading the required files", LogTypeIntel.Information);

                                // Run the file download process asynchronously
                                await Task.Run(() =>
                                {
                                    AsyncDownloader.PrepDownloadedFiles(
                                        LGPOPath: GUIProtectWinSecurity.LGPOZipPath,
                                        MSFTSecurityBaselinesPath: GUIProtectWinSecurity.MicrosoftSecurityBaselineZipPath,
                                        MSFT365AppsSecurityBaselinesPath: GUIProtectWinSecurity.Microsoft365AppsSecurityBaselineZipPath,
                                        false
                                    );
                                });

                                Logger.LogMessage("Finished downloading the required files", LogTypeIntel.Information);
                            }

                            // Using Dispatcher since the execute button is owned by the GUI thread, and we're in another thread
                            // Enabling the execute button after all files are downloaded and ready or if Offline switch was used and download was skipped
                            GUIProtectWinSecurity.View.Dispatcher.Invoke(() =>
                            {
                                GUIProtectWinSecurity.ExecuteButton.IsEnabled = true;
                                GUIProtectWinSecurity.ExecuteButton.IsChecked = false;
                            });
                        }
                        catch (Exception ex)
                        {
                            Logger.LogMessage($"An error occurred while downloading the required files: {ex.Message}", LogTypeIntel.Error);
                            Logger.LogMessage($"{ex.StackTrace}", LogTypeIntel.Error);
                            Logger.LogMessage($"{ex.InnerException}", LogTypeIntel.Error);
                            // Re-throw the exception to ensure it's caught and handled appropriately
                            //   throw;
                        }
                    }

                    // mark as activity finished
                    ActivityTracker.IsActive = false;
                }
            };


            // When Execute button is pressed
            GUIProtectWinSecurity.ExecuteButton.Click += async (sender, e) =>
           {
               // Only continue if there is no activity in other places
               if (!ActivityTracker.IsActive)
               {
                   // mark as activity started
                   ActivityTracker.IsActive = true;

                   // Everything will run in a different thread
                   await Task.Run(() =>
                   {

                       bool OfflineGreenLightStatus = false;
                       bool OfflineModeToggleStatus = false;

                       // Dispatcher to interact with the GUI elements
                       GUIProtectWinSecurity.View.Dispatcher.Invoke(() =>
                       {
                           // Call the method to get the selected categories and sub-categories
                           GUIProtectWinSecurity.ExecuteButtonPress();
                           // Disable the TextFilePath for the log file path
                           GUIProtectWinSecurity.txtFilePath!.IsEnabled = false;
                       });

                       // If Offline mode is used
                       if (GlobalVars.Offline)
                       {

                           GUIProtectWinSecurity.View.Dispatcher.Invoke(() =>
                           {

                               // Handle the nullable boolean
                               if (GUIProtectWinSecurity.enableOfflineMode.IsChecked.HasValue)
                               {
                                   OfflineModeToggleStatus = GUIProtectWinSecurity.enableOfflineMode.IsChecked.Value;
                               }

                               OfflineGreenLightStatus =
                                   !string.IsNullOrWhiteSpace(GUIProtectWinSecurity.microsoftSecurityBaselineZipTextBox.Text) &&
                                   !string.IsNullOrWhiteSpace(GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipTextBox.Text) &&
                                   !string.IsNullOrWhiteSpace(GUIProtectWinSecurity.lgpoZipTextBox.Text);
                           });


                           // If the required files have not been processed for offline mode already
                           if (!GUIProtectWinSecurity.StartFileDownloadHasRun)
                           {
                               // If the checkbox on the GUI for Offline mode is checked
                               if (OfflineModeToggleStatus)
                               {
                                   // Make sure all 3 fields for offline mode files were selected by the users and they are neither empty nor null
                                   if (OfflineGreenLightStatus)
                                   {

                                       // Process the offline mode files selected by the user
                                       AsyncDownloader.PrepDownloadedFiles(
                                      LGPOPath: GUIProtectWinSecurity.LGPOZipPath,
                                      MSFTSecurityBaselinesPath: GUIProtectWinSecurity.MicrosoftSecurityBaselineZipPath,
                                      MSFT365AppsSecurityBaselinesPath: GUIProtectWinSecurity.Microsoft365AppsSecurityBaselineZipPath,
                                      false
                                       );

                                       Logger.LogMessage("Finished processing the required files", LogTypeIntel.Information);

                                       // Set a flag indicating this code block should not run again when the execute button is pressed
                                       GUIProtectWinSecurity.StartFileDownloadHasRun = true;

                                   }
                                   else
                                   {
                                       Logger.LogMessage("Enable Offline Mode checkbox is checked but you have not selected all of the 3 required files for offline mode operation. Please select them and press the execute button again.", LogTypeIntel.WarningInteractionRequired);
                                   }
                               }
                               else
                               {
                                   Logger.LogMessage("Offline mode is being used but the Enable Offline Mode checkbox is not checked. Please check it and press the execute button again.", LogTypeIntel.WarningInteractionRequired);
                               }
                           }
                       }

                       if (!GlobalVars.Offline || (GlobalVars.Offline && GUIProtectWinSecurity.StartFileDownloadHasRun))
                       {

                           if (!GUIProtectWinSecurity.SelectedCategories.IsEmpty)
                           {

                               // Loop over the ConcurrentQueue that contains the Categories
                               foreach (string Category in GUIProtectWinSecurity.SelectedCategories)
                               {

                                   // A switch for the Categories
                                   switch (Category)
                                   {

                                       case "MicrosoftSecurityBaselines":
                                           {
                                               if (GUIProtectWinSecurity.SelectedSubCategories.Contains("SecBaselines_NoOverrides"))
                                               {
                                                   MicrosoftSecurityBaselines.Invoke();
                                               }
                                               else
                                               {
                                                   MicrosoftSecurityBaselines.Invoke();
                                                   MicrosoftSecurityBaselines.SecBaselines_Overrides();
                                               }
                                               break;
                                           }
                                       case "Microsoft365AppsSecurityBaselines":
                                           {
                                               Microsoft365AppsSecurityBaselines.Invoke();
                                               break;
                                           }
                                       case "MicrosoftDefender":
                                           {
                                               MicrosoftDefender.Invoke();

                                               if (GUIProtectWinSecurity.SelectedSubCategories.Contains("MSFTDefender_SAC"))
                                               {
                                                   MicrosoftDefender.MSFTDefender_SAC();
                                               }

                                               if (GlobalVars.ShouldEnableOptionalDiagnosticData || string.Equals(PropertyHelper.GetPropertyValue(GlobalVars.MDAVConfigCurrent, "SmartAppControlState") ?? string.Empty, "on", StringComparison.OrdinalIgnoreCase))
                                               {
                                                   Logger.LogMessage("Enabling Optional Diagnostic Data because SAC is on or user selected to turn it on", LogTypeIntel.Information);
                                                   MicrosoftDefender.MSFTDefender_EnableDiagData();
                                               }

                                               if (!string.Equals(PropertyHelper.GetPropertyValue(GlobalVars.MDAVConfigCurrent, "SmartAppControlState") ?? string.Empty, "off", StringComparison.OrdinalIgnoreCase))
                                               {
                                                   if (GUIProtectWinSecurity.SelectedSubCategories.Contains("MSFTDefender_NoDiagData"))
                                                   {
                                                       // do nothing
                                                   }
                                               }

                                               if (!GUIProtectWinSecurity.SelectedSubCategories.Contains("MSFTDefender_NoScheduledTask"))
                                               {
                                                   MicrosoftDefender.MSFTDefender_ScheduledTask();
                                               }

                                               if (GUIProtectWinSecurity.SelectedSubCategories.Contains("MSFTDefender_BetaChannels"))
                                               {
                                                   MicrosoftDefender.MSFTDefender_BetaChannels();
                                               }
                                               break;
                                           }
                                       case "AttackSurfaceReductionRules":
                                           {
                                               AttackSurfaceReductionRules.Invoke();
                                               break;
                                           }
                                       case "BitLockerSettings":
                                           {
                                               BitLockerSettings.Invoke();
                                               break;
                                           }
                                       case "DeviceGuard":
                                           {
                                               DeviceGuard.Invoke();
                                               if (GUIProtectWinSecurity.SelectedSubCategories.Contains("DeviceGuard_MandatoryVBS"))
                                               {
                                                   DeviceGuard.DeviceGuard_MandatoryVBS();
                                               }
                                               break;
                                           }
                                       case "TLSSecurity":
                                           {
                                               TLSSecurity.Invoke();
                                               break;
                                           }
                                       case "LockScreen":
                                           {
                                               LockScreen.Invoke();

                                               if (GUIProtectWinSecurity.SelectedSubCategories.Contains("LockScreen_CtrlAltDel"))
                                               {
                                                   LockScreen.LockScreen_CtrlAltDel();
                                               }
                                               if (GUIProtectWinSecurity.SelectedSubCategories.Contains("LockScreen_NoLastSignedIn"))
                                               {
                                                   LockScreen.LockScreen_LastSignedIn();
                                               }
                                               break;
                                           }
                                       case "UserAccountControl":
                                           {
                                               UserAccountControl.Invoke();

                                               if (GUIProtectWinSecurity.SelectedSubCategories.Contains("UAC_NoFastSwitching"))
                                               {
                                                   UserAccountControl.UAC_NoFastSwitching();
                                               }
                                               if (GUIProtectWinSecurity.SelectedSubCategories.Contains("UAC_OnlyElevateSigned"))
                                               {
                                                   UserAccountControl.UAC_OnlyElevateSigned();
                                               }

                                               break;
                                           }
                                       case "WindowsFirewall":
                                           {
                                               WindowsFirewall.Invoke();
                                               break;
                                           }
                                       case "OptionalWindowsFeatures":
                                           {
                                               OptionalWindowsFeatures.Invoke();
                                               break;
                                           }
                                       case "WindowsNetworking":
                                           {
                                               WindowsNetworking.Invoke();

                                               if (GUIProtectWinSecurity.SelectedSubCategories.Contains("WindowsNetworking_BlockNTLM"))
                                               {
                                                   WindowsNetworking.WindowsNetworking_BlockNTLM();
                                               }

                                               break;
                                           }
                                       case "MiscellaneousConfigurations":
                                           {
                                               MiscellaneousConfigurations.Invoke();

                                               if (GUIProtectWinSecurity.SelectedSubCategories.Contains("Miscellaneous_WindowsProtectedPrint"))
                                               {
                                                   MiscellaneousConfigurations.MiscellaneousConfigurations_WindowsProtectedPrint();
                                               }

                                               if (GUIProtectWinSecurity.SelectedSubCategories.Contains("MiscellaneousConfigurations_LongPathSupport"))
                                               {
                                                   MiscellaneousConfigurations.MiscellaneousConfigurations_LongPathSupport();
                                               }

                                               if (GUIProtectWinSecurity.SelectedSubCategories.Contains("MiscellaneousConfigurations_StrongKeyProtection"))
                                               {
                                                   MiscellaneousConfigurations.MiscellaneousConfigurations_StrongKeyProtection();
                                               }

                                               break;
                                           }
                                       case "WindowsUpdateConfigurations":
                                           {
                                               WindowsUpdateConfigurations.Invoke();
                                               break;
                                           }
                                       case "EdgeBrowserConfigurations":
                                           {
                                               EdgeBrowserConfigurations.Invoke();
                                               break;
                                           }
                                       case "CertificateCheckingCommands":
                                           {
                                               CertificateCheckingCommands.Invoke();
                                               break;
                                           }
                                       case "CountryIPBlocking":
                                           {
                                               CountryIPBlocking.Invoke();

                                               if (GUIProtectWinSecurity.SelectedSubCategories.Contains("CountryIPBlocking_OFAC"))
                                               {
                                                   CountryIPBlocking.CountryIPBlocking_OFAC();
                                               }
                                               break;
                                           }
                                       case "DownloadsDefenseMeasures":
                                           {
                                               DownloadsDefenseMeasures.Invoke();
                                               if (GUIProtectWinSecurity.SelectedSubCategories.Contains("DangerousScriptHostsBlocking"))
                                               {
                                                   DownloadsDefenseMeasures.DangerousScriptHostsBlocking();
                                               }
                                               break;
                                           }
                                       case "NonAdminCommands":
                                           {
                                               NonAdminCommands.Invoke();
                                               break;
                                           }

                                       default:
                                           break;
                                   }
                               }

                               if (GlobalVars.UseNewNotificationsExp)
                               {
                                   ToastNotification.Show(ToastNotification.Type.EndOfProtection, null, null, null, null);
                               }
                           }
                           else
                           {
                               Logger.LogMessage("No category was selected", LogTypeIntel.Warning);
                           }
                       }

                       GUIProtectWinSecurity.View.Dispatcher.Invoke(() =>
                       {
                           // Manually trigger the ToggleButton to be unchecked to trigger the ending animation
                           GUIProtectWinSecurity.ExecuteButton!.IsChecked = false;

                           // Only enable the log file path TextBox if the log toggle button is toggled
                           if (GUIProtectWinSecurity.log!.IsChecked == true)
                           {
                               GUIProtectWinSecurity.txtFilePath!.IsEnabled = true;
                           }
                       });

                   });

                   // mark as activity completed
                   ActivityTracker.IsActive = false;
               }
           };
        }
    }
}
