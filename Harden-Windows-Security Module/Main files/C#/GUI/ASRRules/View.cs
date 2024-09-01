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
using System.Xml.Linq;

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
                    throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
                }

                // Construct the file path for the ASRRules view XAML
                string xamlPath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "XAML", "ASRRules.xaml");

                // Read the XAML content from the file
                string xamlContent = File.ReadAllText(xamlPath);

                // Parse the XAML content to create a UserControl
                HardenWindowsSecurity.GUIASRRules.View = (System.Windows.Controls.UserControl)XamlReader.Parse(xamlContent);

                // Find the Parent Grid
                HardenWindowsSecurity.GUIASRRules.ParentGrid = (System.Windows.Controls.Grid)HardenWindowsSecurity.GUIASRRules.View.FindName("ParentGrid");

                #region finding elements

                // Get the ListViews
                System.Windows.Controls.ListView? ASRRuleSet1 = GUIASRRules.ParentGrid.FindName("ASRRuleSet1") as System.Windows.Controls.ListView;
                System.Windows.Controls.ListView? ASRRuleSet2 = GUIASRRules.ParentGrid.FindName("ASRRuleSet2") as System.Windows.Controls.ListView;


                // Finding the Execute Button Grid
                System.Windows.Controls.Grid? ExecuteButtonGrid = GUIASRRules.ParentGrid.FindName("ExecuteButtonGrid") as System.Windows.Controls.Grid;

                if (ExecuteButtonGrid == null)
                {
                    throw new Exception("ExecuteButtonGrid is null in the ASRRules View");
                }

                // Finding the Execute Button
                System.Windows.Controls.Primitives.ToggleButton? ExecuteButton = ExecuteButtonGrid.FindName("ExecuteButton") as System.Windows.Controls.Primitives.ToggleButton;

                if (ExecuteButton == null)
                {
                    throw new Exception("Couldn't find the ExecuteButton in ASRRules view");
                }

                // Register the ExecuteButton as an element that will be enabled/disabled based on current activity
                HardenWindowsSecurity.ActivityTracker.RegisterUIElement(ExecuteButton);

                // Apply the template to make sure it's available
                ExecuteButton.ApplyTemplate();

                // Access the image within the Execute Button's template
                System.Windows.Controls.Image? RefreshIconImage = ExecuteButton.Template.FindName("RefreshIconImage", ExecuteButton) as System.Windows.Controls.Image;

                if (RefreshIconImage == null)
                {
                    throw new Exception("RefreshIconImage could not be found in the ASRRules view");
                }

                // Update the image source for the Refresh button
                RefreshIconImage.Source =
                    new System.Windows.Media.Imaging.BitmapImage(
                        new System.Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "ExecuteButton.png"))
                    );

                #endregion


                // Create a dictionary to store the ComboBox names and their corresponding SelectedIndex so that we will loop over this dictionary instead of access UI elements and won't need to use UI Dispatcher
                Dictionary<string, byte> comboBoxDictionary = new Dictionary<string, byte>();

                // Method to process ListView items
                void ProcessListViewItems(System.Windows.Controls.ListView listView)
                {
                    foreach (System.Windows.Controls.ListViewItem item in listView.Items.Cast<System.Windows.Controls.ListViewItem>())
                    {
                        // Find the StackPanel inside the ListViewItem
                        StackPanel? stackPanel = item.Content as StackPanel;
                        if (stackPanel != null)
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
                System.Collections.Generic.Dictionary<string, string> ASRRulesCorrelation = new Dictionary<string, string>()
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
                        throw new Exception("HardenWindowsSecurity.GlobalVars.path is null.");
                    }

                    if (ASRRulesCorrelation == null)
                    {
                        throw new Exception("ASRRulesCorrelation is null");
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
                    }

                    return FilePath;
                }

                if (ExecuteButton == null)
                {
                    throw new Exception("ExecuteButton is null.");
                }

                // Set up the Click event handler for the ExecuteButton button
                ExecuteButton.Click += async (sender, e) =>
                {
                    // Only continue if there is no activity other places
                    if (HardenWindowsSecurity.ActivityTracker.IsActive == false)
                    {
                        // mark as activity started
                        HardenWindowsSecurity.ActivityTracker.IsActive = true;

                        // Disable the ExecuteButton button while processing
                        // Set text blocks to empty while new data is being generated
                        System.Windows.Application.Current.Dispatcher.Invoke(() =>
                        {
                            ExecuteButton.IsEnabled = false;

                            if (ASRRuleSet1 == null || ASRRuleSet2 == null)
                            {
                                throw new Exception("One of the ListViews in the ASRRules view XAML is empty.");
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
                                Logger.LogMessage("LGPO.exe doesn't exist, downloading it.");
                                AsyncDownloader.PrepDownloadedFiles(GlobalVars.LGPOExe, null, null, true);
                            }
                            else
                            {
                                Logger.LogMessage("LGPO.exe already exists, skipping downloading it.");
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
                                }
                            }

                        });

                        // Update the UI Elements at the end of the run
                        await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
                        {
                            ExecuteButton.IsEnabled = true; // Enable the ExecuteButton button
                            ExecuteButton.IsChecked = false; // Uncheck the ExecuteButton button to start the reverse animation

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
