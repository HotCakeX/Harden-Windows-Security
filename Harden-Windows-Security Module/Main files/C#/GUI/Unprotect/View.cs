using System;
using System.IO;
using System.Windows.Markup;

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
                if (HardenWindowsSecurity.GlobalVars.path is null)
                {
                    throw new InvalidOperationException("GlobalVars.path cannot be null.");
                }

                // if Admin privileges are not available, return and do not proceed any further
                // Will prevent the page from being loaded since the CurrentView won't be set/changed
                if (!HardenWindowsSecurity.UserPrivCheck.IsAdmin())
                {
                    Logger.LogMessage("Unprotect page can only be used when running the Harden Windows Security Application with Administrator privileges", LogTypeIntel.ErrorInteractionRequired);
                    return;
                }

                // Construct the file path for the Unprotect view XAML
                string xamlPath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "XAML", "Unprotect.xaml");

                // Read the XAML content from the file
                string xamlContent = File.ReadAllText(xamlPath);

                // Parse the XAML content to create a UserControl
                HardenWindowsSecurity.GUIUnprotect.View = (System.Windows.Controls.UserControl)XamlReader.Parse(xamlContent);

                // Set the DataContext for the Unprotect view
                GUIUnprotect.View.DataContext = new UnprotectVM();

                #region Finding The Elements

                // Find the Parent Grid
                HardenWindowsSecurity.GUIUnprotect.ParentGrid = (System.Windows.Controls.Grid)HardenWindowsSecurity.GUIUnprotect.View.FindName("ParentGrid");

                // Finding the Execute Button Grid
                System.Windows.Controls.Grid? ExecuteButtonGrid = GUIUnprotect.ParentGrid.FindName("ExecuteButtonGrid") as System.Windows.Controls.Grid ?? throw new InvalidOperationException("ExecuteButtonGrid is null in the ASRRules View");

                // Finding the Execute Button
                System.Windows.Controls.Primitives.ToggleButton? ExecuteButton = ExecuteButtonGrid.FindName("ExecuteButton") as System.Windows.Controls.Primitives.ToggleButton ?? throw new InvalidOperationException("Couldn't find the ExecuteButton in ASRRules view");

                // Apply the template to make sure it's available
                _ = ExecuteButton.ApplyTemplate();

                // Access the image within the Execute Button's template
                System.Windows.Controls.Image? RefreshIconImage = ExecuteButton.Template.FindName("RefreshIconImage", ExecuteButton) as System.Windows.Controls.Image ?? throw new InvalidOperationException("RefreshIconImage could not be found in the ASRRules view");

                // Update the image source for the Refresh button
                // Load the Refresh icon image into memory and set it as the source
                var RefreshIconBitmapImage = new System.Windows.Media.Imaging.BitmapImage();
                RefreshIconBitmapImage.BeginInit();
                RefreshIconBitmapImage.UriSource = new System.Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "ExecuteButton.png"));
                RefreshIconBitmapImage.CacheOption = System.Windows.Media.Imaging.BitmapCacheOption.OnLoad; // Load the image data into memory
                RefreshIconBitmapImage.EndInit();

                RefreshIconImage.Source = RefreshIconBitmapImage;

                #endregion


                // Register the ExecuteButton as an element that will be enabled/disabled based on current activity
                HardenWindowsSecurity.ActivityTracker.RegisterUIElement(ExecuteButton);

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

                            if (GUIUnprotect.ParentGrid.FindName("WDACPolicies") is not System.Windows.Controls.ComboBox WDACPoliciesComboBox)
                            {
                                throw new InvalidOperationException("WDACPoliciesComboBox is null");
                            }

                            if (GUIUnprotect.ParentGrid.FindName("UnprotectCategories") is not System.Windows.Controls.ComboBox UnprotectCategoriesComboBox)
                            {
                                throw new InvalidOperationException("UnprotectCategoriesComboBox is null");
                            }

                            // Store the values of the combo boxes in View variables since they need to be acquired through the Application dispatcher since they belong to the UI thread
                            GUIUnprotect.UnprotectCategoriesComboBoxSelection = (byte)UnprotectCategoriesComboBox.SelectedIndex;
                            GUIUnprotect.WDACPoliciesComboBoxSelection = (byte)WDACPoliciesComboBox.SelectedIndex;

                        });

                        // Run the Unprotect commands asynchronously in a different thread
                        await System.Threading.Tasks.Task.Run(() =>
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


                            switch (GUIUnprotect.UnprotectCategoriesComboBoxSelection)
                            {
                                // Only Remove The Process Mitigations
                                case 0:
                                    {
                                        NotificationMessage = "Process Mitigations";

                                        HardenWindowsSecurity.UnprotectWindowsSecurity.RemoveExploitMitigations();
                                        break;
                                    }
                                // Only Remove The WDAC Policies
                                case 1:
                                    {
                                        // Downloads Defense Measures
                                        if (GUIUnprotect.WDACPoliciesComboBoxSelection == 0)
                                        {
                                            NotificationMessage = "Downloads Defense Measures WDAC Policy";

                                            HardenWindowsSecurity.UnprotectWindowsSecurity.RemoveWDACPolicies(true, false);
                                        }
                                        // Dangerous Script Hosts Blocking
                                        else if (GUIUnprotect.WDACPoliciesComboBoxSelection == 1)
                                        {
                                            NotificationMessage = "Dangerous Script Hosts Blocking WDAC Policy";

                                            HardenWindowsSecurity.UnprotectWindowsSecurity.RemoveWDACPolicies(false, true);
                                        }
                                        // All WDAC Policies
                                        else
                                        {
                                            NotificationMessage = "WDAC Policies";

                                            HardenWindowsSecurity.UnprotectWindowsSecurity.RemoveWDACPolicies(true, true);
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

                                        HardenWindowsSecurity.UnprotectWindowsSecurity.RemoveWDACPolicies(true, true);
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
