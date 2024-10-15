using System;
using System.Collections.Generic;
using System.Globalization;
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

            // Method to handle the ASRRules view, including loading
            private void ASRRules(object obj)
            {
                // Check if the view is already cached
                if (_viewCache.TryGetValue("ASRRulesView", out var cachedView))
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
                    Logger.LogMessage("ASR Rules page can only be used when running the Harden Windows Security Application with Administrator privileges", LogTypeIntel.ErrorInteractionRequired);
                    return;
                }

                // Construct the file path for the ASRRules view XAML
                string xamlPath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "XAML", "ASRRules.xaml");

                // Read the XAML content from the file
                string xamlContent = File.ReadAllText(xamlPath);

                // Parse the XAML content to create a UserControl
                HardenWindowsSecurity.GUIASRRules.View = (UserControl)XamlReader.Parse(xamlContent);

                // Set the DataContext for the ASRRules view
                GUIASRRules.View.DataContext = new ASRRulesVM();

                // Find the Parent Grid
                HardenWindowsSecurity.GUIASRRules.ParentGrid = (Grid)HardenWindowsSecurity.GUIASRRules.View.FindName("ParentGrid");

                #region finding elements

                // Finding the Execute Button Grid
                Grid? ExecuteButtonGrid = GUIASRRules.ParentGrid.FindName("ExecuteButtonGrid") as Grid ?? throw new InvalidOperationException("ExecuteButtonGrid is null in the ASRRules View");

                // Finding the Execute Button
                if (ExecuteButtonGrid.FindName("ExecuteButton") is not ToggleButton ExecuteButton)
                {
                    throw new InvalidOperationException("Couldn't find the ExecuteButton in ASRRules view");
                }

                // Apply the template to make sure it's available
                _ = ExecuteButton.ApplyTemplate();

                // Access the image within the Execute Button's template
                if (ExecuteButton.Template.FindName("RefreshIconImage", ExecuteButton) is not Image RefreshIconImage)
                {
                    throw new InvalidOperationException("RefreshIconImage could not be found in the ASRRules view");
                }

                // Update the image source for the Refresh button
                // Load the Refresh icon image into memory and set it as the source
                var RefreshIconBitmapImage = new BitmapImage();
                RefreshIconBitmapImage.BeginInit();
                RefreshIconBitmapImage.UriSource = new System.Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "ExecuteButton.png"));
                RefreshIconBitmapImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
                RefreshIconBitmapImage.EndInit();

                RefreshIconImage.Source = RefreshIconBitmapImage;

                Button RetrieveASRStatusButton = GUIASRRules.ParentGrid.FindName("RetrieveASRStatus") as Button ?? throw new InvalidOperationException("RetrieveASRStatus could not be found in the ASRRules view");

                #endregion


                // Register button to be disabled/enabled based on global activity
                HardenWindowsSecurity.ActivityTracker.RegisterUIElement(RetrieveASRStatusButton);

                // Create a dictionary to store the ComboBox Names as keys and their corresponding SelectedIndex as Values so that we will loop over this dictionary instead of access UI elements and won't need to use UI Dispatcher
                Dictionary<string, byte> comboBoxDictionary = [];

                // Method to process ListView items
                void ProcessListViewItems(System.Windows.Controls.ListView listView)
                {
                    foreach (ListViewItem item in listView.Items.Cast<ListViewItem>())
                    {
                        // Find the StackPanel inside the ListViewItem
                        if (item.Content is StackPanel stackPanel)
                        {
                            // Find the Label inside the StackPanel
                            // System.Windows.Controls.Label label = stackPanel.Children.OfType<System.Windows.Controls.Label>().FirstOrDefault();

                            // Find the ComboBox inside the StackPanel
                            ComboBox? comboBox = stackPanel.Children.OfType<ComboBox>().FirstOrDefault();

                            // To make sure the ComboBox's selected index is not -1 indicating it's empty
                            if (comboBox is not null && comboBox.SelectedIndex is not -1)
                            {
                                // Add the ComboBox Name as string key and ComboBox SelectedIndex as byte value
                                comboBoxDictionary[comboBox.Name.ToString()] = (byte)comboBox.SelectedIndex;
                            }
                        }
                    }
                }

                /// A method that will get the ComboBox and the ASRRuleName, then return the path to the .pol file for the correct ASR rule and action to be applied using LGPO.exe
                string GetASRRuleConfig(string ASRRuleName, byte ComboBoxIndex)
                {

                    if (HardenWindowsSecurity.GlobalVars.path is null)
                    {
                        throw new InvalidOperationException("HardenWindowsSecurity.GlobalVars.path is null.");
                    }

                    if (AttackSurfaceReductionIntel.ASRRulesCorrelation is null)
                    {
                        throw new InvalidOperationException("ASRRulesCorrelation is null");
                    }

                    // Initialize the FilePath variable, it will be returned at the end of the method
                    string FilePath = string.Empty;

                    // Check the index of the ComboBox selected Item
                    switch (ComboBoxIndex)
                    {
                        case 0:
                            {
                                // Disable
                                FilePath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Individual ASR Rule Configs", AttackSurfaceReductionIntel.ASRRulesCorrelation.GetValueOrDefault(ASRRuleName)!, "Disabled.pol");
                                break;
                            }
                        case 1:
                            {
                                // Block
                                FilePath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Individual ASR Rule Configs", AttackSurfaceReductionIntel.ASRRulesCorrelation.GetValueOrDefault(ASRRuleName)!, "Block.pol");
                                break;
                            }
                        case 2:
                            {
                                // Audit
                                FilePath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Individual ASR Rule Configs", AttackSurfaceReductionIntel.ASRRulesCorrelation.GetValueOrDefault(ASRRuleName)!, "Audit.pol");
                                break;
                            }
                        case 3:
                            {
                                // Warn
                                FilePath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Individual ASR Rule Configs", AttackSurfaceReductionIntel.ASRRulesCorrelation.GetValueOrDefault(ASRRuleName)!, "Warn.pol");
                                break;
                            }
                        default:
                            break;
                    }

                    return FilePath;
                }


                // Register the ExecuteButton as an element that will be enabled/disabled based on current activity
                HardenWindowsSecurity.ActivityTracker.RegisterUIElement(ExecuteButton);


                // Set up the Click event handler for the ExecuteButton button
                ExecuteButton.Click += async (sender, e) =>
                {
                    // Only continue if there is no activity other places
                    if (!HardenWindowsSecurity.ActivityTracker.IsActive)
                    {
                        // mark as activity started
                        HardenWindowsSecurity.ActivityTracker.IsActive = true;

                        // Set text blocks to empty while new data is being generated
                        System.Windows.Application.Current.Dispatcher.Invoke(() =>
                        {
                            // Get the ListViews
                            if (GUIASRRules.ParentGrid.FindName("ASRRuleSet1") is not System.Windows.Controls.ListView ASRRuleSet1 || GUIASRRules.ParentGrid.FindName("ASRRuleSet2") is not System.Windows.Controls.ListView ASRRuleSet2)
                            {
                                throw new InvalidOperationException("One of the ListViews in the ASRRules view XAML is empty.");
                            }

                            // Empty the dictionary from previous ComboBox values in order to collect new data
                            comboBoxDictionary.Clear();

                            // Process both ListViews by getting the values of all ComboBoxes and storing them in the dictionary
                            ProcessListViewItems(ASRRuleSet1);
                            ProcessListViewItems(ASRRuleSet2);
                        });

                        // Run the loop asynchronously in a different thread
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

                            // Loop over every ComboBox in the ASRRules view GUI
                            foreach (KeyValuePair<string, byte> ComboBox in comboBoxDictionary)
                            {

                                string ASRRuleActionBasedPath = ComboBox.Key switch
                                {
                                    "BlockAbuseOfExploitedVulnerableSignedDrivers" => GetASRRuleConfig("BlockAbuseOfExploitedVulnerableSignedDrivers", ComboBox.Value),
                                    "BlockAdobeReaderFromCreatingChildProcesses" => GetASRRuleConfig("BlockAdobeReaderFromCreatingChildProcesses", ComboBox.Value),
                                    "BlockAllOfficeApplicationsFromCreatingChildProcesses" => GetASRRuleConfig("BlockAllOfficeApplicationsFromCreatingChildProcesses", ComboBox.Value),
                                    "BlockCredentialStealingFromTheWindowsLocalSecurityAuthoritySubsystem" => GetASRRuleConfig("BlockCredentialStealingFromTheWindowsLocalSecurityAuthoritySubsystem", ComboBox.Value),
                                    "BlockExecutableContentFromEmailClientAndWebmail" => GetASRRuleConfig("BlockExecutableContentFromEmailClientAndWebmail", ComboBox.Value),
                                    "BlockExecutableFilesFromRunningUnlessTheyMeetAPrevalenceAgeOrTrustedListCriterion" => GetASRRuleConfig("BlockExecutableFilesFromRunningUnlessTheyMeetAPrevalenceAgeOrTrustedListCriterion", ComboBox.Value),
                                    "BlockExecutionOfPotentiallyObfuscatedScripts" => GetASRRuleConfig("BlockExecutionOfPotentiallyObfuscatedScripts", ComboBox.Value),
                                    "BlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent" => GetASRRuleConfig("BlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent", ComboBox.Value),
                                    "BlockOfficeApplicationsFromCreatingExecutableContent" => GetASRRuleConfig("BlockOfficeApplicationsFromCreatingExecutableContent", ComboBox.Value),
                                    "BlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses" => GetASRRuleConfig("BlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses", ComboBox.Value),
                                    "BlockOfficeCommunicationApplicationFromCreatingChildProcesses" => GetASRRuleConfig("BlockOfficeCommunicationApplicationFromCreatingChildProcesses", ComboBox.Value),
                                    "BlockPersistenceThroughWMIEventSubscription" => GetASRRuleConfig("BlockPersistenceThroughWMIEventSubscription", ComboBox.Value),
                                    "BlockProcessCreationsOriginatingFromPSExecAndWMICommands" => GetASRRuleConfig("BlockProcessCreationsOriginatingFromPSExecAndWMICommands", ComboBox.Value),
                                    "BlockRebootingMachineInSafeMode" => GetASRRuleConfig("BlockRebootingMachineInSafeMode", ComboBox.Value),
                                    "BlockUntrustedAndUnsignedProcessesThatRunFromUSB" => GetASRRuleConfig("BlockUntrustedAndUnsignedProcessesThatRunFromUSB", ComboBox.Value),
                                    "BlockUseOfCopiedOrImpersonatedSystemTools" => GetASRRuleConfig("BlockUseOfCopiedOrImpersonatedSystemTools", ComboBox.Value),
                                    "BlockWebshellCreationForServers" => GetASRRuleConfig("BlockWebshellCreationForServers", ComboBox.Value),
                                    "BlockWin32APICallsFromOfficeMacros" => GetASRRuleConfig("BlockWin32APICallsFromOfficeMacros", ComboBox.Value),
                                    "UseAdvancedProtectionAgainstRansomware" => GetASRRuleConfig("UseAdvancedProtectionAgainstRansomware", ComboBox.Value),
                                    _ => throw new UnauthorizedAccessException("The switch cannot have undefined values!")
                                };

                                // Using it for logging
                                string stringComboBoxAction = ComboBox.Value switch
                                {
                                    0 => "Disabled",
                                    1 => "Block",
                                    2 => "Audit",
                                    3 => "Warn",
                                    _ => "unknown"
                                };

                                Logger.LogMessage($"Setting ASR rule named {ComboBox.Key} to the value of {stringComboBoxAction}", LogTypeIntel.Information);

                                HardenWindowsSecurity.LGPORunner.RunLGPOCommand(ASRRuleActionBasedPath, LGPORunner.FileType.POL);
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
                        NewToastNotification.Show(NewToastNotification.ToastNotificationType.EndOfASRRules, null, null, null, null);
                    }
                };


                // Event handler for Retrieve ASR Status Button
                RetrieveASRStatusButton.Click += async (sender, e) =>
                {
                    // Only continue if there is no activity other places
                    if (!HardenWindowsSecurity.ActivityTracker.IsActive)
                    {
                        // mark as activity started
                        HardenWindowsSecurity.ActivityTracker.IsActive = true;

                        // Dictionary of ComboBoxes, key is ComboBox name and value is ComboBox element itself
                        Dictionary<string, ComboBox> ComboBoxList = [];

                        System.Windows.Application.Current.Dispatcher.Invoke(() =>
                        {
                            // Get the ListViews
                            if (GUIASRRules.ParentGrid.FindName("ASRRuleSet1") is not System.Windows.Controls.ListView ASRRuleSet1 ||
                                GUIASRRules.ParentGrid.FindName("ASRRuleSet2") is not System.Windows.Controls.ListView ASRRuleSet2)
                            {
                                throw new InvalidOperationException("One of the ListViews in the ASRRules view XAML is empty.");
                            }

                            // Combine the items of both ListViews
                            IEnumerable<ListViewItem> combinedItems = ASRRuleSet1.Items.Cast<ListViewItem>()
                                               .Concat(ASRRuleSet2.Items.Cast<ListViewItem>());

                            foreach (ListViewItem item in combinedItems)
                            {
                                // Find the StackPanel inside the ListViewItem
                                if (item.Content is StackPanel stackPanel)
                                {
                                    // Find the ComboBox inside the StackPanel
                                    ComboBox? comboBox = stackPanel.Children.OfType<ComboBox>().FirstOrDefault();

                                    if (comboBox is not null)
                                    {
                                        ComboBoxList.Add(comboBox.Name, comboBox);
                                    }
                                }
                            }

                        });

                        // Run the loop asynchronously in a different thread
                        await System.Threading.Tasks.Task.Run(() =>
                        {

                            // Get the MSFT_MpPreference WMI results and save them to the global variable HardenWindowsSecurity.GlobalVars.MDAVPreferencesCurrent
                            // Necessary in order to get up to date results
                            HardenWindowsSecurity.GlobalVars.MDAVPreferencesCurrent = HardenWindowsSecurity.MpPreferenceHelper.GetMpPreference();


                            // variables to store the ASR rules IDs and their corresponding actions
                            object idsObj;
                            object actionsObj;

                            idsObj = PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "AttackSurfaceReductionRules_Ids");
                            actionsObj = PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "AttackSurfaceReductionRules_Actions");

                            // Individual ASR rules verification
                            string[]? ids = HelperMethods.ConvertToStringArray(idsObj);
                            string[]? actions = HelperMethods.ConvertToStringArray(actionsObj);

                            // If $Ids variable is not empty, convert them to lower case because some IDs can be in upper case and result in inaccurate comparison
                            if (ids is not null)
                            {
                                ids = ids.Select(id => id.ToLowerInvariant()).ToArray();
                            }

                            // Loop over each item in the HashTable
                            foreach (var kvp in AttackSurfaceReductionIntel.ASRTable)
                            {
                                // Assign each key/value to local variables
                                string name = kvp.Key.ToLowerInvariant();
                                string friendlyName = kvp.Value;

                                // Default action is set to 0, the ComboBox will show "Disabled"
                                string action = "0";

                                // Check if the $Ids array is not empty and current ID is present in the $Ids array
                                if (ids is not null && ids.Contains(name, StringComparer.OrdinalIgnoreCase))
                                {
                                    // If yes, check if the $Actions array is not empty
                                    if (actions is not null)
                                    {
                                        // If yes, use the index of the ID in the array to access the action value
                                        action = actions[Array.FindIndex(ids, id => id.Equals(name, StringComparison.OrdinalIgnoreCase))];
                                    }
                                }

                                // Get the name of the ComboBox from XAML which is the ASR Rule friendlyName but with no spaces
                                _ = AttackSurfaceReductionIntel.ReversedASRRulesCorrelation.TryGetValue(name, out string? ComboBoxName);

                                // Use the ComboBox name to find the ComboBox XAML element itself
                                _ = ComboBoxList.TryGetValue(ComboBoxName!, out ComboBox? currentMatchingComboBox);

                                // Use the GUI dispatcher to set the ComboBox selected index to the currently applied ASR rule's action
                                System.Windows.Application.Current.Dispatcher.Invoke(() =>
                                {
                                    // Make the connection between ASR rule applied action and the ComboBox Item Indexes
                                    int selectedIndex = Convert.ToInt32(action, CultureInfo.InvariantCulture) switch
                                    {
                                        0 => 0,  // Not Configured
                                        1 => 1,   // Block
                                        2 => 2,   // Audit
                                        6 => 3,   // Warn
                                        _ => 0   // Default case
                                    };

                                    currentMatchingComboBox!.SelectedIndex = selectedIndex;
                                });
                            }

                        });


                        // mark as activity completed
                        HardenWindowsSecurity.ActivityTracker.IsActive = false;

                    }
                };



                // Cache the view before setting it as the CurrentView
                _viewCache["ASRRulesView"] = HardenWindowsSecurity.GUIASRRules.View;

                // Set the CurrentView to the ASRRules view
                CurrentView = HardenWindowsSecurity.GUIASRRules.View;
            }
        }
    }
}
