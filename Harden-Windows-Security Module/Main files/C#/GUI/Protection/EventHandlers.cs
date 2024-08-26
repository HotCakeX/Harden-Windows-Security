using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Markup;
using System.Xml;
using System.Windows.Media.Imaging;
using System.Linq;
using System.Windows.Forms;
using System.Collections.Concurrent;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Effects;
using System.Windows.Threading;
using System.Runtime.CompilerServices;
using System.Diagnostics;
using System.ComponentModel;
using System.Threading;
using System.Windows.Automation;
using System.Windows.Controls.Ribbon;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Forms.Integration;
using System.Windows.Ink;
using System.Windows.Media.Animation;
using System.Windows.Media.Media3D;
using System.Windows.Media.TextFormatting;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Shell;
using System.Threading.Tasks;
using System.Text;
using System.Reflection.PortableExecutable;
using System.Security.Principal;
using static HardenWindowsSecurity.NewToastNotification;

#nullable enable

namespace HardenWindowsSecurity
{
    /// <summary>
    /// A class to store all of the data that is related to the GUI and its operations
    /// </summary>
    public partial class GUIProtectWinSecurity
    {

        // The method that defines all of the event handlers for the UI elements
        public static void AddEventHandlers()
        {

            #region
            // null checks to make sure the elements are available to the AddEventHandlers method
            // LoadXaml method doesn't need the checks because these values are initialized in that method

            if (GUIProtectWinSecurity.View == null)
            {
                throw new Exception("AddEventHandlers Method: Window object is empty!");
            }

            if (GUIProtectWinSecurity.outputTextBlock == null)
            {
                throw new Exception("AddEventHandlers Method: outputTextBlock object is empty!");
            }

            if (GUIProtectWinSecurity.categories == null)
            {
                throw new Exception("AddEventHandlers Method: categories object is empty!");
            }

            if (GUIProtectWinSecurity.selectAllCategories == null)
            {
                throw new Exception("AddEventHandlers Method: selectAllCategories object is empty!");
            }

            if (GUIProtectWinSecurity.subCategories == null)
            {
                throw new Exception("AddEventHandlers Method: subCategories object is empty!");
            }

            if (GUIProtectWinSecurity.selectAllSubCategories == null)
            {
                throw new Exception("AddEventHandlers Method: selectAllSubCategories object is empty!");
            }

            if (GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipTextBox == null)
            {
                throw new Exception("AddEventHandlers Method: microsoft365AppsSecurityBaselineZipTextBox object is empty!");
            }

            if (GUIProtectWinSecurity.lgpoZipButton == null)
            {
                throw new Exception("AddEventHandlers Method: lgpoZipButton object is empty!");
            }

            if (GUIProtectWinSecurity.lgpoZipTextBox == null)
            {
                throw new Exception("AddEventHandlers Method: lgpoZipTextBox object is empty!");
            }

            if (GUIProtectWinSecurity.txtFilePath == null)
            {
                throw new Exception("AddEventHandlers Method: txtFilePath object is empty!");
            }

            if (GUIProtectWinSecurity.enableOfflineMode == null)
            {
                throw new Exception("AddEventHandlers Method: enableOfflineMode object is empty!");
            }

            if (GUIProtectWinSecurity.microsoftSecurityBaselineZipButton == null)
            {
                throw new Exception("AddEventHandlers Method: microsoftSecurityBaselineZipButton object is empty!");
            }

            if (GUIProtectWinSecurity.microsoftSecurityBaselineZipTextBox == null)
            {
                throw new Exception("AddEventHandlers Method: microsoftSecurityBaselineZipTextBox object is empty!");
            }

            if (GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipButton == null)
            {
                throw new Exception("AddEventHandlers Method: microsoft365AppsSecurityBaselineZipButton object is empty!");
            }

            if (GUIProtectWinSecurity.ExecuteButton == null)
            {
                throw new Exception("AddEventHandlers Method: ExecuteButton object is empty!");
            }

            if (GUIProtectWinSecurity.mainProgressBar == null)
            {
                throw new Exception("AddEventHandlers Method: mainProgressBar object is empty!");
            }
            #endregion


            // Add Checked and Unchecked event handlers to category checkboxes
            foreach (var item in GUIProtectWinSecurity.categories.Items)
            {
                System.Windows.Controls.ListViewItem categoryItem = (System.Windows.Controls.ListViewItem)item;
                System.Windows.Controls.CheckBox checkBox = (System.Windows.Controls.CheckBox)categoryItem.Content;
                checkBox.DataContext = categoryItem;
                checkBox.Checked += (sender, e) => UpdateSubCategories();
                checkBox.Unchecked += (sender, e) => UpdateSubCategories();
            }

            // Register an event handler for the window size changed event
            GUIProtectWinSecurity.View.SizeChanged += (sender, e) =>
            {
                // Calculate the max width based on the window width
                // Subtract 50 to account for the padding and margin
                long newMaxWidth = (long)GUIProtectWinSecurity.View.ActualWidth - 50;

                // Update the main TextBox's MaxWidth property dynamically, instead of setting it to a fixed value in the XAML
                GUIProtectWinSecurity.outputTextBlock.MaxWidth = newMaxWidth;
            };


            // Add click event for 'Check All' button
            GUIProtectWinSecurity.selectAllCategories.Checked += (sender, e) =>
            {

                if (HardenWindowsSecurity.GlobalVars.HardeningCategorieX == null)
                {
                    throw new System.ArgumentNullException("GlobalVars.HardeningCategorieX cannot be null.");
                }
                foreach (var item in GUIProtectWinSecurity.categories.Items)
                {
                    System.Windows.Controls.ListViewItem categoryItem = (System.Windows.Controls.ListViewItem)item;
                    if (HardenWindowsSecurity.GlobalVars.HardeningCategorieX.Contains(((System.Windows.Controls.CheckBox)categoryItem.Content).Name))
                    {
                        ((System.Windows.Controls.CheckBox)categoryItem.Content).IsChecked = true;
                    }
                }
            };

            // Add click event for 'Uncheck All' button
            GUIProtectWinSecurity.selectAllCategories.Unchecked += (sender, e) =>
            {
                foreach (var item in GUIProtectWinSecurity.categories.Items)
                {
                    ((System.Windows.Controls.CheckBox)((System.Windows.Controls.ListViewItem)item).Content).IsChecked = false;
                }
            };

            // Add click event for 'Check All' button for enabled sub-categories
            GUIProtectWinSecurity.selectAllSubCategories.Checked += (sender, e) =>
            {

                foreach (var item in GUIProtectWinSecurity.subCategories.Items)
                {
                    System.Windows.Controls.ListViewItem subCategoryItem = (System.Windows.Controls.ListViewItem)item;
                    if (subCategoryItem.IsEnabled)
                    {
                        ((System.Windows.Controls.CheckBox)subCategoryItem.Content).IsChecked = true;
                    }
                }
            };

            // Add click event for 'Uncheck All' button from sub-categories, regardless of whether they are enabled or disabled
            GUIProtectWinSecurity.selectAllSubCategories.Unchecked += (sender, e) =>
            {

                foreach (var item in GUIProtectWinSecurity.subCategories.Items)
                {
                    ((System.Windows.Controls.CheckBox)((System.Windows.Controls.ListViewItem)item).Content).IsChecked = false;
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
                using (var dialog = new System.Windows.Forms.OpenFileDialog())
                {
                    dialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    dialog.Filter = "Zip files (*.zip)|*.zip";
                    dialog.Title = "Select the Microsoft Security Baseline Zip file";

                    if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                    {
                        try
                        {
                            if (!HardenWindowsSecurity.SneakAndPeek.Search("Windows*Security Baseline/Scripts/Baseline-LocalInstall.ps1", dialog.FileName))
                            {
                                HardenWindowsSecurity.Logger.LogMessage("The selected Zip file does not contain the Microsoft Security Baselines Baseline-LocalInstall.ps1 which is required for the Protect-WindowsSecurity function to work properly");
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
                            HardenWindowsSecurity.Logger.LogMessage(ex.Message);
                        }
                    }
                }
            };

            // Define the click event for the Microsoft 365 Apps Security Baseline Zip button
            GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipButton.Click += (sender, e) =>
            {
                using (var dialog = new System.Windows.Forms.OpenFileDialog())
                {
                    dialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    dialog.Filter = "Zip files (*.zip)|*.zip";
                    dialog.Title = "Select the Microsoft 365 Apps Security Baseline Zip file";

                    if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                    {
                        try
                        {
                            if (!HardenWindowsSecurity.SneakAndPeek.Search("Microsoft 365 Apps for Enterprise*/Scripts/Baseline-LocalInstall.ps1", dialog.FileName))
                            {
                                HardenWindowsSecurity.Logger.LogMessage("The selected Zip file does not contain the Microsoft 365 Apps for Enterprise Security Baselines Baseline-LocalInstall.ps1 which is required for the Protect-WindowsSecurity function to work properly");
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
                            HardenWindowsSecurity.Logger.LogMessage(ex.Message);
                        }
                    }
                }
            };

            // Define the click event for the LGPO Zip button
            GUIProtectWinSecurity.lgpoZipButton.Click += (sender, e) =>
            {
                using (var dialog = new System.Windows.Forms.OpenFileDialog())
                {
                    dialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    dialog.Filter = "Zip files (*.zip)|*.zip";
                    dialog.Title = "Select the LGPO Zip file";

                    if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                    {
                        try
                        {
                            if (!HardenWindowsSecurity.SneakAndPeek.Search("LGPO_*/LGPO.exe", dialog.FileName))
                            {
                                HardenWindowsSecurity.Logger.LogMessage("The selected Zip file does not contain the LGPO.exe which is required for the Protect-WindowsSecurity function to work properly");
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
                            HardenWindowsSecurity.Logger.LogMessage(ex.Message);
                        }
                    }
                }
            };





            // Defining a set of commands to run when the GUI window is loaded, async
            GUIProtectWinSecurity.View.Loaded += async (sender, e) =>
            {
                // Only proceed if this event hasn't already been triggered
                if (!HardenWindowsSecurity.GUIProtectWinSecurity.LoadEventHasBeenTriggered)
                {

                    // Set the flag to true indicating the view loaded event has been triggered
                    HardenWindowsSecurity.GUIProtectWinSecurity.LoadEventHasBeenTriggered = true;

                    // Run this entire section, including the downloading part, asynchronously
                    try
                    {

                        #region Display a Welcome message
                        string nameToDisplay = string.Empty;

                        string UserValue = string.Empty;

                        System.Security.Principal.WindowsIdentity CurrentUserResult = System.Security.Principal.WindowsIdentity.GetCurrent();
                        System.Security.Principal.SecurityIdentifier? User = CurrentUserResult.User;

                        if (User != null)
                        {
                            UserValue = User.Value.ToString();
                        }

                        HardenWindowsSecurity.LocalUser? CurrentLocalUser = HardenWindowsSecurity.LocalUserRetriever.Get().FirstOrDefault(Lu => Lu.SID == UserValue);

                        nameToDisplay = (!string.IsNullOrWhiteSpace(CurrentLocalUser!.FullName)) ? CurrentLocalUser.FullName : !string.IsNullOrWhiteSpace(CurrentLocalUser.Name) ? CurrentLocalUser.Name : "Unknown User";

                        HardenWindowsSecurity.Logger.LogMessage(HardenWindowsSecurity.UserPrivCheck.IsAdmin() ? $"Hello {nameToDisplay}, Running as Administrator" : $"Hello {nameToDisplay}, Running as Non-Administrator, some categories are disabled");
                        #endregion

                        // Use Dispatcher.Invoke to update the UI thread
                        HardenWindowsSecurity.GUIProtectWinSecurity.View.Dispatcher.Invoke(() =>
                        {
                            // Set the execute button to disabled until all the prerequisites are met
                            HardenWindowsSecurity.GUIProtectWinSecurity.ExecuteButton.IsEnabled = false;

                            // Display the progress bar during file download
                            HardenWindowsSecurity.GUIProtectWinSecurity.mainProgressBar.Visibility = Visibility.Visible;
                            HardenWindowsSecurity.GUIProtectWinSecurity.ExecuteButton.IsChecked = true;
                        });

                        // Only download and process the files when the GUI is loaded and if Offline mode is not used
                        // Because at this point, the user might have not selected the files to be used for offline operation
                        if (!HardenWindowsSecurity.GlobalVars.Offline)
                        {
                            HardenWindowsSecurity.Logger.LogMessage("Downloading the required files");

                            // Run the file download process asynchronously
                            await Task.Run(() =>
                            {
                                HardenWindowsSecurity.FileDownloader.PrepDownloadedFiles(
                                    LGPOPath: HardenWindowsSecurity.GUIProtectWinSecurity.LGPOZipPath,
                                    MSFTSecurityBaselinesPath: HardenWindowsSecurity.GUIProtectWinSecurity.MicrosoftSecurityBaselineZipPath,
                                    MSFT365AppsSecurityBaselinesPath: HardenWindowsSecurity.GUIProtectWinSecurity.Microsoft365AppsSecurityBaselineZipPath
                                );
                            });

                            HardenWindowsSecurity.Logger.LogMessage("Finished downloading the required files");
                        }

                        // Using Dispatcher since the execute button is owned by the GUI (parent) RunSpace, and we're in another RunSpace (ThreadJob)
                        // Enabling the execute button after all files are downloaded and ready or if Offline switch was used and download was skipped
                        HardenWindowsSecurity.GUIProtectWinSecurity.View.Dispatcher.Invoke(() =>
                        {
                            HardenWindowsSecurity.GUIProtectWinSecurity.ExecuteButton.IsEnabled = true;
                            HardenWindowsSecurity.GUIProtectWinSecurity.mainProgressBar.Visibility = Visibility.Hidden;
                            HardenWindowsSecurity.GUIProtectWinSecurity.ExecuteButton.IsChecked = false;
                        });
                    }
                    catch (Exception ex)
                    {
                        HardenWindowsSecurity.Logger.LogMessage($"An error occurred while downloading the required files: {ex.Message}");
                        HardenWindowsSecurity.Logger.LogMessage($"{ex.StackTrace}");
                        HardenWindowsSecurity.Logger.LogMessage($"{ex.InnerException}");
                        // Re-throw the exception to ensure it's caught and handled appropriately
                        //   throw;
                    }
                }
            };


            // When Execute button is pressed
            GUIProtectWinSecurity.ExecuteButton.Click += async (sender, e) =>
           {
               // Only continue if there is no activity other places
               if (HardenWindowsSecurity.ActivityTracker.IsActive == false)
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
                           HardenWindowsSecurity.GUIProtectWinSecurity.ExecuteButtonPress();
                           HardenWindowsSecurity.GUIProtectWinSecurity.DisableUIElements();

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
                                       HardenWindowsSecurity.FileDownloader.PrepDownloadedFiles(
                                      LGPOPath: HardenWindowsSecurity.GUIProtectWinSecurity.LGPOZipPath,
                                      MSFTSecurityBaselinesPath: HardenWindowsSecurity.GUIProtectWinSecurity.MicrosoftSecurityBaselineZipPath,
                                      MSFT365AppsSecurityBaselinesPath: HardenWindowsSecurity.GUIProtectWinSecurity.Microsoft365AppsSecurityBaselineZipPath
                                       );

                                       HardenWindowsSecurity.Logger.LogMessage("Finished processing the required files");

                                       //Set a flag indicating this code block should not happen again when the execute button is pressed
                                       HardenWindowsSecurity.GUIProtectWinSecurity.StartFileDownloadHasRun = true;


                                   }
                                   else
                                   {
                                       HardenWindowsSecurity.Logger.LogMessage("Enable Offline Mode checkbox is checked but you have not selected all of the 3 required files for offline mode operation. Please select them and press the execute button again.");
                                   }
                               }
                               else
                               {
                                   HardenWindowsSecurity.Logger.LogMessage("Offline mode is being used but the Enable Offline Mode checkbox is not checked. Please check it and press the execute button again.");
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

                                               if (HardenWindowsSecurity.GlobalVars.ShouldEnableOptionalDiagnosticData || string.Equals(HardenWindowsSecurity.GlobalVars.MDAVConfigCurrent!.SmartAppControlState, "on", StringComparison.OrdinalIgnoreCase))
                                               {
                                                   HardenWindowsSecurity.Logger.LogMessage("Enabling Optional Diagnostic Data because SAC is on or user selected to turn it on");
                                                   HardenWindowsSecurity.MicrosoftDefender.MSFTDefender_EnableDiagData();
                                               }

                                               if (!string.Equals(HardenWindowsSecurity.GlobalVars.MDAVConfigCurrent!.SmartAppControlState, "off", StringComparison.OrdinalIgnoreCase))
                                               {
                                                   if (HardenWindowsSecurity.GUIProtectWinSecurity.SelectedSubCategories.Contains("MSFTDefender_NoDiagData"))
                                                   {
                                                       // do nothing !?
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
                                               break;
                                           }
                                       case "MiscellaneousConfigurations":
                                           {
                                               HardenWindowsSecurity.MiscellaneousConfigurations.Invoke();
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
                                               if (HardenWindowsSecurity.GUIProtectWinSecurity.SelectedSubCategories.Contains("ClipboardSync"))
                                               {
                                                   HardenWindowsSecurity.NonAdminCommands.ClipboardSync();
                                               }
                                               break;
                                           }
                                   }
                               }

                               if (HardenWindowsSecurity.GlobalVars.UseNewNotificationsExp == true)
                               {
                                   HardenWindowsSecurity.NewToastNotification.Show(ToastNotificationType.EndOfProtection, null, null);
                               }
                           }
                           else
                           {
                               HardenWindowsSecurity.Logger.LogMessage("No category was selected");
                           }
                       }

                       HardenWindowsSecurity.GUIProtectWinSecurity.View.Dispatcher.Invoke(() =>
                       {
                           HardenWindowsSecurity.GUIProtectWinSecurity.EnableUIElements();
                       });

                   });

                   // mark as activity completed
                   HardenWindowsSecurity.ActivityTracker.IsActive = false;
               }
           };
        }
    }
}
