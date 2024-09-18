using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows.Controls;
using System.Windows.Markup;

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
                if (HardenWindowsSecurity.GlobalVars.path == null)
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
                HardenWindowsSecurity.GUIASRRules.View = (System.Windows.Controls.UserControl)XamlReader.Parse(xamlContent);

                // Set the DataContext for the ASRRules view
                GUIASRRules.View.DataContext = new ASRRulesVM();

                // Find the Parent Grid
                HardenWindowsSecurity.GUIASRRules.ParentGrid = (System.Windows.Controls.Grid)HardenWindowsSecurity.GUIASRRules.View.FindName("ParentGrid");

                #region finding elements

                // Finding the Execute Button Grid
                System.Windows.Controls.Grid? ExecuteButtonGrid = GUIASRRules.ParentGrid.FindName("ExecuteButtonGrid") as System.Windows.Controls.Grid ?? throw new InvalidOperationException("ExecuteButtonGrid is null in the ASRRules View");

                // Finding the Execute Button
                if (ExecuteButtonGrid.FindName("ExecuteButton") is not System.Windows.Controls.Primitives.ToggleButton ExecuteButton)
                {
                    throw new InvalidOperationException("Couldn't find the ExecuteButton in ASRRules view");
                }

                // Apply the template to make sure it's available
                _ = ExecuteButton.ApplyTemplate();

                // Access the image within the Execute Button's template
                if (ExecuteButton.Template.FindName("RefreshIconImage", ExecuteButton) is not System.Windows.Controls.Image RefreshIconImage)
                {
                    throw new InvalidOperationException("RefreshIconImage could not be found in the ASRRules view");
                }

                // Update the image source for the Refresh button
                // Load the Refresh icon image into memory and set it as the source
                var RefreshIconBitmapImage = new System.Windows.Media.Imaging.BitmapImage();
                RefreshIconBitmapImage.BeginInit();
                RefreshIconBitmapImage.UriSource = new System.Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "ExecuteButton.png"));
                RefreshIconBitmapImage.CacheOption = System.Windows.Media.Imaging.BitmapCacheOption.OnLoad; // Load the image data into memory
                RefreshIconBitmapImage.EndInit();

                RefreshIconImage.Source = RefreshIconBitmapImage;


                #endregion


                // Create a dictionary to store the ComboBox names and their corresponding SelectedIndex so that we will loop over this dictionary instead of access UI elements and won't need to use UI Dispatcher
                Dictionary<string, byte> comboBoxDictionary = [];

                // Method to process ListView items
                void ProcessListViewItems(System.Windows.Controls.ListView listView)
                {
                    foreach (System.Windows.Controls.ListViewItem item in listView.Items.Cast<System.Windows.Controls.ListViewItem>())
                    {
                        // Find the StackPanel inside the ListViewItem
                        if (item.Content is StackPanel stackPanel)
                        {
                            // Find the Label inside the StackPanel
                            // System.Windows.Controls.Label label = stackPanel.Children.OfType<System.Windows.Controls.Label>().FirstOrDefault();

                            // Find the ComboBox inside the StackPanel
                            System.Windows.Controls.ComboBox? comboBox = stackPanel.Children.OfType<System.Windows.Controls.ComboBox>().FirstOrDefault();

                            if (comboBox != null)
                            {
                                // Add the ComboBox Name as string key and ComboBox SelectedIndex as byte value
                                comboBoxDictionary[comboBox.Name.ToString()] = (byte)comboBox.SelectedIndex;
                            }
                        }
                    }
                }


                // Correlation between the ComboBox Names in the XAML and the GUID of the ASR Rule they belong to
                System.Collections.Generic.Dictionary<string, string> ASRRulesCorrelation = new()
                {
                    {"BlockAbuseOfExploitedVulnerableSignedDrivers" , "56a863a9-875e-4185-98a7-b882c64b5ce5"},
                    {"BlockAdobeReaderFromCreatingChildProcesses" , "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"},
                    {"BlockAllOfficeApplicationsFromCreatingChildProcesses" , "d4f940ab-401b-4efc-aadc-ad5f3c50688a"},
                    {"BlockCredentialStealingFromTheWindowsLocalSecurityAuthoritySubsystem" , "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"},
                    {"BlockExecutableContentFromEmailClientAndWebmail" , "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"},
                    {"BlockExecutableFilesFromRunningUnlessTheyMeetAPrevalenceAgeOrTrustedListCriterion" , "01443614-cd74-433a-b99e-2ecdc07bfc25"},
                    {"BlockExecutionOfPotentiallyObfuscatedScripts" , "5beb7efe-fd9a-4556-801d-275e5ffc04cc"},
                    {"BlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent" , "d3e037e1-3eb8-44c8-a917-57927947596d"},
                    {"BlockOfficeApplicationsFromCreatingExecutableContent" , "3b576869-a4ec-4529-8536-b80a7769e899"},
                    {"BlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses" , "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"},
                    {"BlockOfficeCommunicationApplicationFromCreatingChildProcesses" , "26190899-1602-49e8-8b27-eb1d0a1ce869"},
                    {"BlockPersistenceThroughWMIEventSubscription" , "e6db77e5-3df2-4cf1-b95a-636979351e5b"},
                    {"BlockProcessCreationsOriginatingFromPSExecAndWMICommands" , "d1e49aac-8f56-4280-b9ba-993a6d77406c"},
                    {"BlockRebootingMachineInSafeMode" , "33ddedf1-c6e0-47cb-833e-de6133960387"},
                    {"BlockUntrustedAndUnsignedProcessesThatRunFromUSB" , "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"},
                    {"BlockUseOfCopiedOrImpersonatedSystemTools" , "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb"},
                    {"BlockWebshellCreationForServers" , "a8f5898e-1dc8-49a9-9878-85004b8a61e6"},
                    {"BlockWin32APICallsFromOfficeMacros" , "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"},
                    {"UseAdvancedProtectionAgainstRansomware","c1db55ab-c21a-4637-bb3f-a12568109d35" }

                };


                /// A method that will get the ComboBox and the ASRRuleName, then return the path to the .pol file for the correct ASR rule and action to be applied using LGPO.exe
                string GetASRRuleConfig(string ASRRuleName, byte ComboBoxIndex)
                {

                    if (HardenWindowsSecurity.GlobalVars.path == null)
                    {
                        throw new InvalidOperationException("HardenWindowsSecurity.GlobalVars.path is null.");
                    }

                    if (ASRRulesCorrelation == null)
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
                                FilePath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Individual ASR Rule Configs", ASRRulesCorrelation.GetValueOrDefault(ASRRuleName)!, "Disabled.pol");
                                break;
                            }
                        case 1:
                            {
                                // Block
                                FilePath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Individual ASR Rule Configs", ASRRulesCorrelation.GetValueOrDefault(ASRRuleName)!, "Block.pol");
                                break;
                            }
                        case 2:
                            {
                                // Audit
                                FilePath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Individual ASR Rule Configs", ASRRulesCorrelation.GetValueOrDefault(ASRRuleName)!, "Audit.pol");
                                break;
                            }
                        case 3:
                            {
                                // Warn
                                FilePath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Individual ASR Rule Configs", ASRRulesCorrelation.GetValueOrDefault(ASRRuleName)!, "Warn.pol");
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

                                switch (ComboBox.Key)
                                {

                                    case "BlockAbuseOfExploitedVulnerableSignedDrivers":
                                        {
                                            string ASRRuleActionBasedPath = GetASRRuleConfig("BlockAbuseOfExploitedVulnerableSignedDrivers", ComboBox.Value);
                                            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(ASRRuleActionBasedPath, LGPORunner.FileType.POL);
                                            break;
                                        }
                                    case "BlockAdobeReaderFromCreatingChildProcesses":
                                        {
                                            string ASRRuleActionBasedPath = GetASRRuleConfig("BlockAdobeReaderFromCreatingChildProcesses", ComboBox.Value);
                                            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(ASRRuleActionBasedPath, LGPORunner.FileType.POL);
                                            break;
                                        }
                                    case "BlockAllOfficeApplicationsFromCreatingChildProcesses":
                                        {
                                            string ASRRuleActionBasedPath = GetASRRuleConfig("BlockAllOfficeApplicationsFromCreatingChildProcesses", ComboBox.Value);
                                            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(ASRRuleActionBasedPath, LGPORunner.FileType.POL);
                                            break;
                                        }
                                    case "BlockCredentialStealingFromTheWindowsLocalSecurityAuthoritySubsystem":
                                        {
                                            string ASRRuleActionBasedPath = GetASRRuleConfig("BlockCredentialStealingFromTheWindowsLocalSecurityAuthoritySubsystem", ComboBox.Value);
                                            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(ASRRuleActionBasedPath, LGPORunner.FileType.POL);
                                            break;
                                        }
                                    case "BlockExecutableContentFromEmailClientAndWebmail":
                                        {
                                            string ASRRuleActionBasedPath = GetASRRuleConfig("BlockExecutableContentFromEmailClientAndWebmail", ComboBox.Value);
                                            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(ASRRuleActionBasedPath, LGPORunner.FileType.POL);
                                            break;
                                        }
                                    case "BlockExecutableFilesFromRunningUnlessTheyMeetAPrevalenceAgeOrTrustedListCriterion":
                                        {
                                            string ASRRuleActionBasedPath = GetASRRuleConfig("BlockExecutableFilesFromRunningUnlessTheyMeetAPrevalenceAgeOrTrustedListCriterion", ComboBox.Value);
                                            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(ASRRuleActionBasedPath, LGPORunner.FileType.POL);
                                            break;
                                        }
                                    case "BlockExecutionOfPotentiallyObfuscatedScripts":
                                        {
                                            string ASRRuleActionBasedPath = GetASRRuleConfig("BlockExecutionOfPotentiallyObfuscatedScripts", ComboBox.Value);
                                            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(ASRRuleActionBasedPath, LGPORunner.FileType.POL);
                                            break;
                                        }
                                    case "BlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent":
                                        {
                                            string ASRRuleActionBasedPath = GetASRRuleConfig("BlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent", ComboBox.Value);
                                            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(ASRRuleActionBasedPath, LGPORunner.FileType.POL);
                                            break;
                                        }
                                    case "BlockOfficeApplicationsFromCreatingExecutableContent":
                                        {
                                            string ASRRuleActionBasedPath = GetASRRuleConfig("BlockOfficeApplicationsFromCreatingExecutableContent", ComboBox.Value);
                                            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(ASRRuleActionBasedPath, LGPORunner.FileType.POL);
                                            break;
                                        }
                                    case "BlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses":
                                        {
                                            string ASRRuleActionBasedPath = GetASRRuleConfig("BlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses", ComboBox.Value);
                                            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(ASRRuleActionBasedPath, LGPORunner.FileType.POL);
                                            break;
                                        }
                                    case "BlockOfficeCommunicationApplicationFromCreatingChildProcesses":
                                        {
                                            string ASRRuleActionBasedPath = GetASRRuleConfig("BlockOfficeCommunicationApplicationFromCreatingChildProcesses", ComboBox.Value);
                                            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(ASRRuleActionBasedPath, LGPORunner.FileType.POL);
                                            break;
                                        }
                                    case "BlockPersistenceThroughWMIEventSubscription":
                                        {
                                            string ASRRuleActionBasedPath = GetASRRuleConfig("BlockPersistenceThroughWMIEventSubscription", ComboBox.Value);
                                            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(ASRRuleActionBasedPath, LGPORunner.FileType.POL);
                                            break;
                                        }
                                    case "BlockProcessCreationsOriginatingFromPSExecAndWMICommands":
                                        {
                                            string ASRRuleActionBasedPath = GetASRRuleConfig("BlockProcessCreationsOriginatingFromPSExecAndWMICommands", ComboBox.Value);
                                            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(ASRRuleActionBasedPath, LGPORunner.FileType.POL);
                                            break;
                                        }
                                    case "BlockRebootingMachineInSafeMode":
                                        {
                                            string ASRRuleActionBasedPath = GetASRRuleConfig("BlockRebootingMachineInSafeMode", ComboBox.Value);
                                            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(ASRRuleActionBasedPath, LGPORunner.FileType.POL);
                                            break;
                                        }
                                    case "BlockUntrustedAndUnsignedProcessesThatRunFromUSB":
                                        {
                                            string ASRRuleActionBasedPath = GetASRRuleConfig("BlockUntrustedAndUnsignedProcessesThatRunFromUSB", ComboBox.Value);
                                            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(ASRRuleActionBasedPath, LGPORunner.FileType.POL);
                                            break;
                                        }
                                    case "BlockUseOfCopiedOrImpersonatedSystemTools":
                                        {
                                            string ASRRuleActionBasedPath = GetASRRuleConfig("BlockUseOfCopiedOrImpersonatedSystemTools", ComboBox.Value);
                                            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(ASRRuleActionBasedPath, LGPORunner.FileType.POL);
                                            break;
                                        }
                                    case "BlockWebshellCreationForServers":
                                        {
                                            string ASRRuleActionBasedPath = GetASRRuleConfig("BlockWebshellCreationForServers", ComboBox.Value);
                                            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(ASRRuleActionBasedPath, LGPORunner.FileType.POL);
                                            break;
                                        }
                                    case "BlockWin32APICallsFromOfficeMacros":
                                        {
                                            string ASRRuleActionBasedPath = GetASRRuleConfig("BlockWin32APICallsFromOfficeMacros", ComboBox.Value);
                                            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(ASRRuleActionBasedPath, LGPORunner.FileType.POL);
                                            break;
                                        }
                                    case "UseAdvancedProtectionAgainstRansomware":
                                        {
                                            string ASRRuleActionBasedPath = GetASRRuleConfig("UseAdvancedProtectionAgainstRansomware", ComboBox.Value);
                                            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(ASRRuleActionBasedPath, LGPORunner.FileType.POL);
                                            break;
                                        }
                                    default:
                                        break;
                                }
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

                // Cache the view before setting it as the CurrentView
                _viewCache["ASRRulesView"] = HardenWindowsSecurity.GUIASRRules.View;

                // Set the CurrentView to the ASRRules view
                CurrentView = HardenWindowsSecurity.GUIASRRules.View;
            }
        }
    }
}
