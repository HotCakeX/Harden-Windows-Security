using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;
using Windows.ApplicationModel;
using Windows.Foundation;
using Windows.Management.Deployment;

namespace HardenWindowsSecurity;

public partial class GUIMain
{

	// Partial class definition for handling navigation and view models
	public partial class NavigationVM : ViewModelBase
	{

		// Method to handle the OptionalFeatures view, including loading
		private void OptionalFeaturesView(object obj)
		{

			// Check if the view is already cached
			if (_viewCache.TryGetValue("OptionalFeaturesView", out var cachedView))
			{
				CurrentView = cachedView;
				return;
			}

			// Construct the file path for the OptionalFeatures view XAML
			string xamlPath = Path.Combine(GlobalVars.path, "Resources", "XAML", "OptionalFeatures.xaml");

			// Read the XAML content from the file
			string xamlContent = File.ReadAllText(xamlPath);

			// Parse the XAML content to create a UserControl
			GUIOptionalFeatures.View = (UserControl)XamlReader.Parse(xamlContent);

			// Find the Parent Grid
			GUIOptionalFeatures.ParentGrid = (Grid)GUIOptionalFeatures.View.FindName("ParentGrid");

			// Finding other elements
			ListView OptionalFeatures = (ListView)(GUIOptionalFeatures.ParentGrid).FindName("OptionalFeatures");
			CheckBox SelectAllOptionalFeatures = (CheckBox)(GUIOptionalFeatures.ParentGrid).FindName("SelectAllOptionalFeatures");
			Button ApplyOptionalFeaturesButton = (Button)(GUIOptionalFeatures.ParentGrid).FindName("ApplyOptionalFeaturesButton");
			Button RetrieveOptionalFeaturesStatus = (Button)(GUIOptionalFeatures.ParentGrid).FindName("RetrieveOptionalFeaturesStatus");

			ListView Apps = (ListView)(GUIOptionalFeatures.ParentGrid).FindName("Apps");
			CheckBox SelectAllApps = (CheckBox)(GUIOptionalFeatures.ParentGrid).FindName("SelectAllApps");
			Button RetrieveRemovableApps = (Button)(GUIOptionalFeatures.ParentGrid).FindName("RetrieveRemovableApps");
			Button RemoveApps = (Button)(GUIOptionalFeatures.ParentGrid).FindName("RemoveApps");

			// A dictionary to store all checkboxes
			Dictionary<string, CheckBox> featureCheckboxes = [];

			// Iterate through the ListView items to find CheckBoxes
			foreach (ListViewItem item in OptionalFeatures.Items)
			{
				// Check if the content of the item is a CheckBox
				if (item.Content is CheckBox checkbox)
				{
					// Add the checkbox to the dictionary with its name as the key
					featureCheckboxes[checkbox.Name] = checkbox;
				}
			}


			// Add click event for 'Check All' button
			SelectAllOptionalFeatures.Checked += (sender, e) =>
			{
				foreach (CheckBox item in featureCheckboxes.Values)
				{
					item.IsChecked = true;

				}
			};

			// Add click event for 'Uncheck All' button
			SelectAllOptionalFeatures.Unchecked += (sender, e) =>
			{
				foreach (CheckBox item in featureCheckboxes.Values)
				{
					item.IsChecked = false;
				}
			};


			// Register the elements that will be enabled/disabled based on current activity
			ActivityTracker.RegisterUIElement(ApplyOptionalFeaturesButton);
			ActivityTracker.RegisterUIElement(RetrieveOptionalFeaturesStatus);
			ActivityTracker.RegisterUIElement(RemoveApps);
			ActivityTracker.RegisterUIElement(RetrieveRemovableApps);


			// Event handler for the apply button
			ApplyOptionalFeaturesButton.Click += async (sender, e) =>
			{

				// Only continue if there is no activity other places
				if (ActivityTracker.IsActive)
				{
					return;
				}

				// mark as activity started
				ActivityTracker.IsActive = true;

				try
				{

					// Get the results of all optional features once and store them in the static variable to be reused later
					WindowsFeatureChecker.FeatureStatus FeaturesCheckResults = await Task.Run(() => WindowsFeatureChecker.CheckWindowsFeatures());

					// Get all checked checkboxes' contents from the dictionary
					List<string> checkedCheckboxes = [.. featureCheckboxes
						.Where(pair => pair.Value.IsChecked is true)
						.Select(pair => pair.Value.Name)];

					await Task.Run(() =>
					{

						foreach (string optionalFeatureName in checkedCheckboxes)
						{

							switch (optionalFeatureName)
							{
								case "RemovePowerShellV2":
									{
										OptionalWindowsFeatures.ConfigureWindowsOptionalFeature(false, "MicrosoftWindowsPowerShellV2", "PowerShell v2", "PowerShellv2", FeaturesCheckResults);
										OptionalWindowsFeatures.ConfigureWindowsOptionalFeature(false, "MicrosoftWindowsPowerShellV2Root", "PowerShell v2 root", "PowerShellv2Engine", FeaturesCheckResults);
										break;
									}
								case "RemoveWorkFolders":
									{
										OptionalWindowsFeatures.ConfigureWindowsOptionalFeature(false, "WorkFolders-Client", "Work Folders", "WorkFoldersClient", FeaturesCheckResults);
										break;
									}
								case "RemoveInternetPrintingClient":
									{
										OptionalWindowsFeatures.ConfigureWindowsOptionalFeature(false, "Printing-Foundation-InternetPrinting-Client", "Internet Printing Client", "InternetPrintingClient", FeaturesCheckResults);
										break;
									}
								case "RemoveLegacyWindowsMediaPlayer":
									{
										OptionalWindowsFeatures.RemoveCapability("Media.WindowsMediaPlayer", "The old Windows Media Player");
										break;
									}
								case "RemoveMicrosoftDefenderApplicationGuard":
									{
										OptionalWindowsFeatures.ConfigureWindowsOptionalFeature(false, "Windows-Defender-ApplicationGuard", "Deprecated Microsoft Defender Application Guard (MDAG)", "MDAG", FeaturesCheckResults);
										break;
									}
								case "RemoveLegacyNotepad":
									{
										OptionalWindowsFeatures.RemoveCapability("Microsoft.Windows.Notepad.System", "Old classic Notepad");
										break;
									}
								case "RemoveVBSCRIPT":
									{
										OptionalWindowsFeatures.RemoveCapability("VBSCRIPT", "Deprecated VBScript");
										break;
									}
								case "RemoveInternetExplorerModeForEdge":
									{
										OptionalWindowsFeatures.RemoveCapability("Browser.InternetExplorer", "Internet Explorer Mode for Edge");
										break;
									}
								case "RemoveWMIC":
									{
										OptionalWindowsFeatures.RemoveCapability("WMIC", "Deprecated WMIC");
										break;
									}
								case "RemoveWordPad":
									{
										OptionalWindowsFeatures.RemoveCapability("Microsoft.Windows.WordPad", "Deprecated WordPad");
										break;
									}
								case "RemovePowerShellISE":
									{
										OptionalWindowsFeatures.RemoveCapability("Microsoft.Windows.PowerShell.ISE", "PowerShell ISE");
										break;
									}
								case "RemoveStepsRecorder":
									{
										OptionalWindowsFeatures.RemoveCapability("App.StepsRecorder", "Deprecated Steps Recorder");
										break;
									}
								case "RemoveMathRecognizer":
									{
										OptionalWindowsFeatures.RemoveCapability("MathRecognizer", "Math Recognizer");
										break;
									}
								case "RemovePrintManagement":
									{
										OptionalWindowsFeatures.RemoveCapability("Print.Management.Console", "Print Management");
										break;
									}
								case "RemoveOpenSSHClient":
									{
										OptionalWindowsFeatures.RemoveCapability("OpenSSH.Client", "OpenSSH Client");
										break;
									}
								case "RemoveFacialRecognition":
									{
										OptionalWindowsFeatures.RemoveCapability("Hello.Face", "Windows Hello Facial Recognition");
										break;
									}
								case "RemoveExtendedThemeContent":
									{
										OptionalWindowsFeatures.RemoveCapability("Microsoft.Wallpapers.Extended", "Extended Windows Theme content");
										break;
									}
								case "EnableWindowsSandbox":
									{
										OptionalWindowsFeatures.ConfigureWindowsOptionalFeature(true, "Containers-DisposableClientVM", "Windows Sandbox", "WindowsSandbox", FeaturesCheckResults);
										break;
									}
								case "EnableHyperV":
									{
										OptionalWindowsFeatures.ConfigureWindowsOptionalFeature(true, "Microsoft-Hyper-V", "Hyper-V", "HyperV", FeaturesCheckResults);
										break;
									}
								default:
									{
										break;
									}
							}

						}
					});

				}
				finally
				{
					// mark as activity completed
					ActivityTracker.IsActive = false;
				}
			};



			// Event handler for the button that retrieves features and capabilities status
			RetrieveOptionalFeaturesStatus.Click += async (sender, e) =>
			{

				// Only continue if there is no activity other places
				if (ActivityTracker.IsActive)
				{
					return;
				}

				// mark as activity started
				ActivityTracker.IsActive = true;
				try
				{

					// Defining the variables outside the Task so they are accessible after the task completes
					string PowerShellv2 = "Unknown";
					string PowerShellv2Engine = "Unknown";
					string WorkFoldersClient = "Unknown";
					string InternetPrintingClient = "Unknown";
					string WindowsMediaPlayer = "Unknown";
					string MDAG = "Unknown";
					string WindowsSandbox = "Unknown";
					string HyperV = "Unknown";

					string WMIC = "Unknown";
					string IEMode = "Unknown";
					string LegacyNotepad = "Unknown";
					string LegacyWordPad = "Unknown";
					string PowerShellISE = "Unknown";
					string StepsRecorder = "Unknown";
					string VBSCRIPT = "Unknown";

					string MathRecognizer = "Unknown";
					string PrintManagementConsole = "Unknown";
					string OpenSSHClient = "Unknown";
					string HelloFace = "Unknown";
					string MicrosoftWallpapersExtended = "Unknown";


					await Task.Run(() =>
					{

						// Get the states of optional features using Cim Instance only once so that we can use it multiple times
						Dictionary<string, string>? optionalFeatureStates = WindowsFeatureChecker.GetOptionalFeatureStates();

						PowerShellv2 = optionalFeatureStates.GetValueOrDefault("MicrosoftWindowsPowerShellV2", "Unknown");
						PowerShellv2Engine = optionalFeatureStates.GetValueOrDefault("MicrosoftWindowsPowerShellV2Root", "Unknown");
						WorkFoldersClient = optionalFeatureStates.GetValueOrDefault("WorkFolders-Client", "Unknown");
						InternetPrintingClient = optionalFeatureStates.GetValueOrDefault("Printing-Foundation-InternetPrinting-Client", "Unknown");
						WindowsMediaPlayer = WindowsFeatureChecker.GetCapabilityState("Media.WindowsMediaPlayer");
						MDAG = optionalFeatureStates.GetValueOrDefault("Windows-Defender-ApplicationGuard", "Unknown");
						WindowsSandbox = optionalFeatureStates.GetValueOrDefault("Containers-DisposableClientVM", "Unknown");
						HyperV = optionalFeatureStates.GetValueOrDefault("Microsoft-Hyper-V", "Unknown");

						WMIC = WindowsFeatureChecker.GetCapabilityState("Wmic");
						IEMode = WindowsFeatureChecker.GetCapabilityState("Browser.InternetExplorer");
						LegacyNotepad = WindowsFeatureChecker.GetCapabilityState("Microsoft.Windows.Notepad.System");
						LegacyWordPad = WindowsFeatureChecker.GetCapabilityState("Microsoft.Windows.WordPad");
						PowerShellISE = WindowsFeatureChecker.GetCapabilityState("Microsoft.Windows.PowerShell.ISE");
						StepsRecorder = WindowsFeatureChecker.GetCapabilityState("App.StepsRecorder");
						VBSCRIPT = WindowsFeatureChecker.GetCapabilityState("VBSCRIPT");

						MathRecognizer = WindowsFeatureChecker.GetCapabilityState("MathRecognizer");
						PrintManagementConsole = WindowsFeatureChecker.GetCapabilityState("Print.Management.Console");
						OpenSSHClient = WindowsFeatureChecker.GetCapabilityState("OpenSSH.Client");
						HelloFace = WindowsFeatureChecker.GetCapabilityState("Hello.Face");
						MicrosoftWallpapersExtended = WindowsFeatureChecker.GetCapabilityState("Microsoft.Wallpapers.Extended");

					});


					// Disable and uncheck the Checkboxes if their corresponding feature is already disabled/enabled
					if (string.Equals(PowerShellv2, "Disabled", StringComparison.OrdinalIgnoreCase) ||
						string.Equals(PowerShellv2, "Unknown", StringComparison.OrdinalIgnoreCase))
					{
						featureCheckboxes["RemovePowerShellV2"].IsChecked = false;
						featureCheckboxes["RemovePowerShellV2"].IsEnabled = false;
					}
					else
					{
						featureCheckboxes["RemovePowerShellV2"].IsEnabled = true;
					}

					if (string.Equals(PowerShellv2Engine, "Disabled", StringComparison.OrdinalIgnoreCase) ||
						string.Equals(PowerShellv2Engine, "Unknown", StringComparison.OrdinalIgnoreCase))
					{
						featureCheckboxes["RemovePowerShellV2"].IsChecked = false;
						featureCheckboxes["RemovePowerShellV2"].IsEnabled = false;
					}
					else
					{
						featureCheckboxes["RemovePowerShellV2"].IsEnabled = true;
					}

					if (string.Equals(WorkFoldersClient, "Disabled", StringComparison.OrdinalIgnoreCase) ||
						string.Equals(WorkFoldersClient, "Unknown", StringComparison.OrdinalIgnoreCase))
					{
						featureCheckboxes["RemoveWorkFolders"].IsChecked = false;
						featureCheckboxes["RemoveWorkFolders"].IsEnabled = false;
					}
					else
					{
						featureCheckboxes["RemoveWorkFolders"].IsEnabled = true;
					}

					if (string.Equals(InternetPrintingClient, "Disabled", StringComparison.OrdinalIgnoreCase) ||
						string.Equals(InternetPrintingClient, "Unknown", StringComparison.OrdinalIgnoreCase))
					{
						featureCheckboxes["RemoveInternetPrintingClient"].IsChecked = false;
						featureCheckboxes["RemoveInternetPrintingClient"].IsEnabled = false;
					}
					else
					{
						featureCheckboxes["RemoveInternetPrintingClient"].IsEnabled = true;
					}

					if (string.Equals(WindowsMediaPlayer, "Not Present", StringComparison.OrdinalIgnoreCase) ||
						string.Equals(WindowsMediaPlayer, "Unknown", StringComparison.OrdinalIgnoreCase))
					{
						featureCheckboxes["RemoveLegacyWindowsMediaPlayer"].IsChecked = false;
						featureCheckboxes["RemoveLegacyWindowsMediaPlayer"].IsEnabled = false;
					}
					else
					{
						featureCheckboxes["RemoveLegacyWindowsMediaPlayer"].IsEnabled = true;
					}

					if (string.Equals(MDAG, "Disabled", StringComparison.OrdinalIgnoreCase) ||
						string.Equals(MDAG, "Unknown", StringComparison.OrdinalIgnoreCase))
					{
						featureCheckboxes["RemoveMicrosoftDefenderApplicationGuard"].IsChecked = false;
						featureCheckboxes["RemoveMicrosoftDefenderApplicationGuard"].IsEnabled = false;
					}
					else
					{
						featureCheckboxes["RemoveMicrosoftDefenderApplicationGuard"].IsEnabled = true;
					}

					if (string.Equals(WindowsSandbox, "Enabled", StringComparison.OrdinalIgnoreCase) ||
						string.Equals(WindowsSandbox, "Unknown", StringComparison.OrdinalIgnoreCase))
					{
						featureCheckboxes["EnableWindowsSandbox"].IsChecked = false;
						featureCheckboxes["EnableWindowsSandbox"].IsEnabled = false;
					}
					else
					{
						featureCheckboxes["EnableWindowsSandbox"].IsEnabled = true;
					}

					if (string.Equals(HyperV, "Enabled", StringComparison.OrdinalIgnoreCase) ||
						string.Equals(HyperV, "Unknown", StringComparison.OrdinalIgnoreCase))
					{
						featureCheckboxes["EnableHyperV"].IsChecked = false;
						featureCheckboxes["EnableHyperV"].IsEnabled = false;
					}
					else
					{
						featureCheckboxes["EnableHyperV"].IsEnabled = true;
					}

					if (string.Equals(WMIC, "Not Present", StringComparison.OrdinalIgnoreCase) ||
						string.Equals(WMIC, "Unknown", StringComparison.OrdinalIgnoreCase))
					{
						featureCheckboxes["RemoveWMIC"].IsChecked = false;
						featureCheckboxes["RemoveWMIC"].IsEnabled = false;
					}
					else
					{
						featureCheckboxes["RemoveWMIC"].IsEnabled = true;
					}

					if (string.Equals(IEMode, "Not Present", StringComparison.OrdinalIgnoreCase) ||
						string.Equals(IEMode, "Unknown", StringComparison.OrdinalIgnoreCase))
					{
						featureCheckboxes["RemoveInternetExplorerModeForEdge"].IsChecked = false;
						featureCheckboxes["RemoveInternetExplorerModeForEdge"].IsEnabled = false;
					}
					else
					{
						featureCheckboxes["RemoveInternetExplorerModeForEdge"].IsEnabled = true;
					}

					if (string.Equals(LegacyNotepad, "Not Present", StringComparison.OrdinalIgnoreCase) ||
						string.Equals(LegacyNotepad, "Unknown", StringComparison.OrdinalIgnoreCase))
					{
						featureCheckboxes["RemoveLegacyNotepad"].IsChecked = false;
						featureCheckboxes["RemoveLegacyNotepad"].IsEnabled = false;
					}
					else
					{
						featureCheckboxes["RemoveLegacyNotepad"].IsEnabled = true;
					}

					if (string.Equals(LegacyWordPad, "Not Present", StringComparison.OrdinalIgnoreCase) ||
						string.Equals(LegacyWordPad, "Unknown", StringComparison.OrdinalIgnoreCase))
					{
						featureCheckboxes["RemoveWordPad"].IsChecked = false;
						featureCheckboxes["RemoveWordPad"].IsEnabled = false;
					}
					else
					{
						featureCheckboxes["RemoveWordPad"].IsEnabled = true;
					}

					if (string.Equals(PowerShellISE, "Not Present", StringComparison.OrdinalIgnoreCase) ||
						string.Equals(PowerShellISE, "Unknown", StringComparison.OrdinalIgnoreCase))
					{
						featureCheckboxes["RemovePowerShellISE"].IsChecked = false;
						featureCheckboxes["RemovePowerShellISE"].IsEnabled = false;
					}
					else
					{
						featureCheckboxes["RemovePowerShellISE"].IsEnabled = true;
					}

					if (string.Equals(StepsRecorder, "Not Present", StringComparison.OrdinalIgnoreCase) ||
						string.Equals(StepsRecorder, "Unknown", StringComparison.OrdinalIgnoreCase))
					{
						featureCheckboxes["RemoveStepsRecorder"].IsChecked = false;
						featureCheckboxes["RemoveStepsRecorder"].IsEnabled = false;
					}
					else
					{
						featureCheckboxes["RemoveStepsRecorder"].IsEnabled = true;
					}

					if (string.Equals(VBSCRIPT, "Not Present", StringComparison.OrdinalIgnoreCase) ||
						string.Equals(VBSCRIPT, "Unknown", StringComparison.OrdinalIgnoreCase))
					{
						featureCheckboxes["RemoveVBSCRIPT"].IsChecked = false;
						featureCheckboxes["RemoveVBSCRIPT"].IsEnabled = false;
					}
					else
					{
						featureCheckboxes["RemoveVBSCRIPT"].IsEnabled = true;
					}

					if (string.Equals(MathRecognizer, "Not Present", StringComparison.OrdinalIgnoreCase) ||
						string.Equals(MathRecognizer, "Unknown", StringComparison.OrdinalIgnoreCase))
					{
						featureCheckboxes["RemoveMathRecognizer"].IsChecked = false;
						featureCheckboxes["RemoveMathRecognizer"].IsEnabled = false;
					}
					else
					{
						featureCheckboxes["RemoveMathRecognizer"].IsEnabled = true;
					}

					if (string.Equals(PrintManagementConsole, "Not Present", StringComparison.OrdinalIgnoreCase) ||
						string.Equals(PrintManagementConsole, "Unknown", StringComparison.OrdinalIgnoreCase))
					{
						featureCheckboxes["RemovePrintManagement"].IsChecked = false;
						featureCheckboxes["RemovePrintManagement"].IsEnabled = false;
					}
					else
					{
						featureCheckboxes["RemovePrintManagement"].IsEnabled = true;
					}

					if (string.Equals(OpenSSHClient, "Not Present", StringComparison.OrdinalIgnoreCase) ||
						string.Equals(OpenSSHClient, "Unknown", StringComparison.OrdinalIgnoreCase))
					{
						featureCheckboxes["RemoveOpenSSHClient"].IsChecked = false;
						featureCheckboxes["RemoveOpenSSHClient"].IsEnabled = false;
					}
					else
					{
						featureCheckboxes["RemoveOpenSSHClient"].IsEnabled = true;
					}

					if (string.Equals(HelloFace, "Not Present", StringComparison.OrdinalIgnoreCase) ||
						string.Equals(HelloFace, "Unknown", StringComparison.OrdinalIgnoreCase))
					{
						featureCheckboxes["RemoveFacialRecognition"].IsChecked = false;
						featureCheckboxes["RemoveFacialRecognition"].IsEnabled = false;
					}
					else
					{
						featureCheckboxes["RemoveFacialRecognition"].IsEnabled = true;
					}

					if (string.Equals(MicrosoftWallpapersExtended, "Not Present", StringComparison.OrdinalIgnoreCase) ||
						string.Equals(MicrosoftWallpapersExtended, "Unknown", StringComparison.OrdinalIgnoreCase))
					{
						featureCheckboxes["RemoveExtendedThemeContent"].IsChecked = false;
						featureCheckboxes["RemoveExtendedThemeContent"].IsEnabled = false;
					}
					else
					{
						featureCheckboxes["RemoveExtendedThemeContent"].IsEnabled = true;
					}


				}
				finally
				{

					// mark as activity completed
					ActivityTracker.IsActive = false;
				}
			};




			// Add click event for 'Check All' button for Apps
			SelectAllApps.Checked += (sender, e) =>
			{
				foreach (CheckBox item in GUIOptionalFeatures.appsCheckBoxes.Values)
				{
					item.IsChecked = true;

				}
			};

			// Add click event for 'Uncheck All' button for Apps
			SelectAllApps.Unchecked += (sender, e) =>
			{
				foreach (CheckBox item in GUIOptionalFeatures.appsCheckBoxes.Values)
				{
					item.IsChecked = false;
				}
			};


			// The private function that retrieves the apps list
			async Task _RetrieveRemovableApps()
			{

				// Clear any existing items in the ListView
				Apps.Items.Clear();

				// Clear the dictionary of CheckBoxes
				GUIOptionalFeatures.appsCheckBoxes.Clear();

				GUIOptionalFeatures.appNameToFullNameDictionary.Clear();

				HashSet<string> namesList = [];

				await Task.Run(() =>
				{

					// The reason we have a dictionary of names and full names is because we can't store full names in the JSON
					// Since they contain app versions, whereas Name is generic without any version limiting its applicability
					// This retrieves all installed app packages. FindProvisionedPackages() method retrieves only limited number of packages.
					foreach (Package item in GUIOptionalFeatures.packageMgr.FindPackages())
					{
						GUIOptionalFeatures.appNameToFullNameDictionary[item.Id.Name] = item.Id.FullName;
					}

					// Set the description of the package (i.e., friendlyName) to the Checkbox content
					foreach (string item in GUIOptionalFeatures.appNameToFullNameDictionary.Keys)
					{
						if (GUIOptionalFeatures.nameToDescriptionApps.TryGetValue(item, out string? description))
						{
							_ = namesList.Add(description);
						}
					}

				});


				foreach (string name in namesList)
				{
					// Create a CheckBox
					CheckBox checkBox = new()
					{
						Content = name,
						VerticalContentAlignment = VerticalAlignment.Center,
						Padding = GUIOptionalFeatures.thicc,
						ToolTip = $"Remove {name} from the system for all users",
						Template = GUIOptionalFeatures.CustomCheckBoxTemplate
					};

					// Add the checkbox to the dictionary with its Content as the key
					GUIOptionalFeatures.appsCheckBoxes[name] = checkBox;

					// Create a ListViewItem and add the CheckBox to it
					ListViewItem listViewItem = new()
					{
						ToolTip = $"Remove {name} from the system for all users",
						Content = checkBox
					};

					// Set tooltip delay
					ToolTipService.SetInitialShowDelay(listViewItem, 1000);

					// Add ListViewItem to ListView
					_ = Apps.Items.Add(listViewItem);
				}
			}


			// Event handler for the button that retrieves removable apps on the system
			RetrieveRemovableApps.Click += async (sender, e) =>
			{

				// Only continue if there is no activity other places
				if (ActivityTracker.IsActive)
				{
					return;
				}

				// mark as activity started
				ActivityTracker.IsActive = true;

				try
				{
					await _RetrieveRemovableApps();
				}
				finally
				{
					// mark as activity completed
					ActivityTracker.IsActive = false;
				}
			};



			// Event handler for the Remove Apps button
			RemoveApps.Click += async (sender, e) =>
			{

				// Only continue if there is no activity other places
				if (ActivityTracker.IsActive)
				{
					return;
				}

				// mark as activity started
				ActivityTracker.IsActive = true;

				try
				{

					// Get all checked checkboxes' contents from the dictionary
					List<string> checkedCheckboxes = [.. GUIOptionalFeatures.appsCheckBoxes
						.Where(pair => pair.Value.IsChecked is true)
						.Select(pair => pair.Value.Content.ToString())];


					HashSet<string> appsNamesToRemove = [];


					// Get the selected apps' names based on their descriptions
					foreach (string item in checkedCheckboxes)
					{
						if (GUIOptionalFeatures.descriptionToNameApps.TryGetValue(item, out string? name))
						{
							_ = appsNamesToRemove.Add(name);
						}
					}


					if (appsNamesToRemove.Count is 0)
					{
						Logger.LogMessage("No apps were selected for removal", LogTypeIntel.Information);
						return;
					}


					// Loop over each user-selected app and remove them one by one
					foreach (string appName in appsNamesToRemove)
					{

						if (GUIOptionalFeatures.appNameToFullNameDictionary.TryGetValue(appName, out string? fullName))
						{
							Logger.LogMessage($"Trying to remove the app with the FullName of '{fullName}'", LogTypeIntel.Information);

							try
							{

								await Task.Run(() =>
								   {

									   IAsyncOperationWithProgress<DeploymentResult, DeploymentProgress> deploymentOperation = GUIOptionalFeatures.packageMgr.RemovePackageAsync(fullName, RemovalOptions.RemoveForAllUsers);

									   // This event is signaled when the operation completes
									   ManualResetEvent opCompletedEvent = new(false);

									   // Define the delegate using a statement lambda
									   deploymentOperation.Completed = (depProgress, status) => { _ = opCompletedEvent.Set(); };

									   // Wait until the operation completes
									   _ = opCompletedEvent.WaitOne();

									   // Check the status of the operation
									   if (deploymentOperation.Status is AsyncStatus.Error)
									   {
										   DeploymentResult deploymentResult = deploymentOperation.GetResults();
										   Logger.LogMessage($"Error code: {deploymentOperation.ErrorCode} - Error Text: {deploymentResult.ErrorText}", LogTypeIntel.Error);
									   }
									   else if (deploymentOperation.Status is AsyncStatus.Canceled)
									   {
										   Logger.LogMessage("Removal canceled", LogTypeIntel.Information);
									   }
									   else if (deploymentOperation.Status is AsyncStatus.Completed)
									   {
										   Logger.LogMessage($"The app with the FullName of '{fullName}' has been successfully removed.", LogTypeIntel.Information);
									   }
									   else
									   {
										   Logger.LogMessage("Removal status unknown", LogTypeIntel.Information);
									   }
								   });
							}
							catch (Exception ex)
							{
								Logger.LogMessage($"There was a problem removing the app with the FullName '{fullName}'. {ex.Message}", LogTypeIntel.Error);
							}
						}
					}

					// Update the Apps list
					await _RetrieveRemovableApps();
				}
				finally
				{
					// mark as activity completed
					ActivityTracker.IsActive = false;
				}
			};



			#region Deserialize the JSON

			string SafeToRemoveAppsListJson = File.ReadAllText(Path.Combine(GlobalVars.path, "Resources", "SafeToRemoveAppsList.json"));
			GUIOptionalFeatures.SafeToRemoveAppsCol appList = JsonSerializer.Deserialize<GUIOptionalFeatures.SafeToRemoveAppsCol>(SafeToRemoveAppsListJson, GUIOptionalFeatures.JsonSerializerOptions)!;

			foreach (GUIOptionalFeatures.SafeToRemoveApp app in appList.SafeToRemoveAppsList)
			{
				GUIOptionalFeatures.nameToDescriptionApps[app.Name] = app.Description;
				GUIOptionalFeatures.descriptionToNameApps[app.Description] = app.Name;
			}

			#endregion


			// Cache the view before setting it as the CurrentView
			_viewCache["OptionalFeaturesView"] = GUIOptionalFeatures.View;

			// Set the CurrentView to the Protect view
			CurrentView = GUIOptionalFeatures.View;

		}
	}
}
