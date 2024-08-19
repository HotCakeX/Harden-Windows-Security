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

#nullable enable

namespace HardenWindowsSecurity
{
    /// <summary>
    /// A class to store all of the data that is related to the GUI and its operations
    /// </summary>
    public partial class GUIProtectWinSecurity
    {

        // The method that defines all of the event handlers for the UI elements
        private static void AddEventHandlers()
        {

            #region
            // null checks to make sure the elements are available to the AddEventHandlers method
            // LoadXaml method doesn't need the checks because these values are initialized in that method

            if (GUIProtectWinSecurity.window == null)
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
            GUIProtectWinSecurity.window.SizeChanged += (sender, e) =>
            {
                // Calculate the max width based on the window width
                // Subtract 50 to account for the padding and margin
                long newMaxWidth = (long)GUIProtectWinSecurity.window.ActualWidth - 50;

                // Update the main TextBox's MaxWidth property dynamically, instead of setting it to a fixed value in the XAML
                GUIProtectWinSecurity.outputTextBlock.MaxWidth = newMaxWidth;
            };

            // event handler to make the GUI window draggable wherever it's empty
            GUIProtectWinSecurity.window.MouseDown += (sender, e) =>
            {
                // Only allow dragging the window when the left mouse button (also includes touch) is clicked
                if (e.ChangedButton == MouseButton.Left)
                {
                    GUIProtectWinSecurity.window.DragMove();
                }
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

            // Defining what happens when the GUI window is closed
            GUIProtectWinSecurity.window.Closed += (sender, e) =>
            {
                // Only proceed further if user enabled logging and the log file path is not empty
                if (
                    GUIProtectWinSecurity.log!.IsChecked == true &&
                !string.IsNullOrEmpty(GUIProtectWinSecurity.txtFilePath.Text)
                )
                {

                    // Create the footer to the log file
                    string endOfLogFile = $"""
**********************
Harden Windows Security operation log end
End time: {DateTime.Now}
**********************
""";

                    // Add the footer to the log file
                    GUIProtectWinSecurity.Logger.Add(endOfLogFile);

                    // Convert ArrayList to List<string>
                    List<string> logEntries = new List<string>();
                    foreach (string item in GUIProtectWinSecurity.Logger)
                    {
                        logEntries.Add(item);
                    }


                    // trim any white spaces, single or double quotes in case the user entered the path with quotes around it
                    GUIProtectWinSecurity.txtFilePath.Text = GUIProtectWinSecurity.txtFilePath.Text.Trim(' ', '\'', '\"'); ;

                    // Ensure the path is absolute
                    GUIProtectWinSecurity.txtFilePath.Text = System.IO.Path.GetFullPath(GUIProtectWinSecurity.txtFilePath.Text);

                    // Append log entries to the file
                    try
                    {
                        File.AppendAllLines(GUIProtectWinSecurity.txtFilePath.Text, logEntries);
                    }
                    catch
                    {
                        HardenWindowsSecurity.Logger.LogMessage($"Couldn't save the logs in the selected path: {GUIProtectWinSecurity.txtFilePath.Text}");
                    }
                };

            };

            /*
                        // Startup Event
                        GUIProtectWinSecurity.app!.Startup += (object s, StartupEventArgs e) =>
                        {
                            // Display a welcome message
                            System.Windows.MessageBox.Show(messageBoxText: "Welcome to the application!", caption: "Startup", button: MessageBoxButton.OK, icon: MessageBoxImage.Information);
                        };

                        // Exit Event
                        GUIProtectWinSecurity.app!.Exit += (object s, ExitEventArgs e) =>
                        {
                            System.Windows.MessageBox.Show(messageBoxText: "Exiting!", caption: "Exit", button: MessageBoxButton.OK, icon: MessageBoxImage.Information);
                        };

                        // DispatcherUnhandledException Event is triggered when an unhandled exception occurs in the application
                        GUIProtectWinSecurity.app!.DispatcherUnhandledException += (object s, DispatcherUnhandledExceptionEventArgs e) =>
                        {

                            // Display an error message to the user
                            System.Windows.MessageBox.Show(messageBoxText: "An unexpected error occurred.", caption: "Error", button: MessageBoxButton.OK, icon: MessageBoxImage.Error);

                            // Mark the exception as handled
                            e.Handled = true;
                        };
            */

            /*
                        GUIProtectWinSecurity.app!.Resources["GlobalStyle"] = new Style(typeof(System.Windows.Controls.Button))
                        {
                            Setters =
                            {
                                new Setter(System.Windows.Controls.Button.BackgroundProperty, System.Windows.Media.Brushes.LightBlue),
                                new Setter(System.Windows.Controls.Button.ForegroundProperty, System.Windows.Media.Brushes.DarkBlue)
                            }
                        };
            */



            // Defining a set of commands to run when the GUI window is loaded, async
            GUIProtectWinSecurity.window.ContentRendered += async (sender, e) =>
            {
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
                    HardenWindowsSecurity.GUIProtectWinSecurity.window.Dispatcher.Invoke(() =>
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
                                MSFT365AppsSecurityBaselinesPath: HardenWindowsSecurity.GUIProtectWinSecurity.Microsoft365AppsSecurityBaselineZipPath,
                                GUI: true
                            );
                        });

                        HardenWindowsSecurity.Logger.LogMessage("Finished downloading/processing the required files");
                    }

                    // Using Dispatcher since the execute button is owned by the GUI (parent) RunSpace, and we're in another RunSpace (ThreadJob)
                    // Enabling the execute button after all files are downloaded and ready or if Offline switch was used and download was skipped
                    HardenWindowsSecurity.GUIProtectWinSecurity.window.Dispatcher.Invoke(() =>
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
            };
        }
    }
}
