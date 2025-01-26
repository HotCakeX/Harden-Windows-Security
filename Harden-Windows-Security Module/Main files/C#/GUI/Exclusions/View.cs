using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Markup;
using Microsoft.Win32;

namespace HardenWindowsSecurity;

public partial class GUIMain
{

	// Partial class definition for handling navigation and view models
	public partial class NavigationVM : ViewModelBase
	{

		// Method to handle the Exclusions view, including loading
		private void ExclusionsView(object obj)
		{
			// Check if the view is already cached
			if (_viewCache.TryGetValue("ExclusionsView", out var cachedView))
			{
				CurrentView = cachedView;
				return;
			}

			// if Admin privileges are not available, return and do not proceed any further
			// Will prevent the page from being loaded since the CurrentView won't be set/changed
			if (!Environment.IsPrivilegedProcess)
			{
				Logger.LogMessage("Exclusions page can only be used when running the Harden Windows Security Application with Administrator privileges", LogTypeIntel.ErrorInteractionRequired);
				return;
			}

			// Read the XAML content from the file
			string xamlContent = File.ReadAllText(Path.Combine(GlobalVars.path, "Resources", "XAML", "Exclusions.xaml"));

			// Parse the XAML content to create a UserControl
			GUIExclusions.View = (UserControl)XamlReader.Parse(xamlContent);

			// Find the Parent Grid
			GUIExclusions.ParentGrid = (Grid)GUIExclusions.View.FindName("ParentGrid");

			#region Finding other elements

			ToggleButton MicrosoftDefenderToggleButton = (ToggleButton)GUIExclusions.ParentGrid.FindName("MicrosoftDefenderToggleButton");
			ToggleButton ControlledFolderAccessToggleButton = (ToggleButton)GUIExclusions.ParentGrid.FindName("ControlledFolderAccessToggleButton");
			ToggleButton AttackSurfaceReductionRulesToggleButton = (ToggleButton)GUIExclusions.ParentGrid.FindName("AttackSurfaceReductionRulesToggleButton");
			TextBox? SelectedFilePaths = (TextBox)GUIExclusions.ParentGrid.FindName("SelectedFilePaths");
			Button? BrowseForFilesButton = (Button)GUIExclusions.ParentGrid.FindName("BrowseForFilesButton");
			Button ApplyExclusionsButton = (Button)GUIExclusions.ParentGrid.FindName("ApplyExclusionsButton");

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

						Logger.LogMessage($"Selected file path: {file}", LogTypeIntel.Information);
					}
				}

			};


			// Register the elements that will be enabled/disabled based on current activity
			ActivityTracker.RegisterUIElement(ApplyExclusionsButton);
			ActivityTracker.RegisterUIElement(BrowseForFilesButton);

			// Add the path to the Controlled folder access backup list of the Harden Windows Security
			// Only if it's not already in here
			// This way after the CFA exclusions restore at the end, the changes made here will continue to exist
			static void AddItemToBackup(string itemToAdd)
			{
				// Check if CFABackup is null; if so, initialize it
				GlobalVars.CFABackup ??= [];

				// Convert GlobalVars.CFABackup to a List for easier manipulation
				List<string> CFABackupLocal = [.. GlobalVars.CFABackup!];

				// Check if the item is not already in the list
				if (!CFABackupLocal.Contains(itemToAdd))
				{
					CFABackupLocal.Add(itemToAdd);
				}

				// Convert the list back to an array
				GlobalVars.CFABackup = [.. CFABackupLocal];
			}


			// Set up the Click event handler for the main button
			ApplyExclusionsButton.Click += async (sender, e) =>
				{
					// Only continue if there is no activity other places
					if (ActivityTracker.IsActive)
					{
						return;
					}

					// mark as activity started
					ActivityTracker.IsActive = true;

					// Get the status of the toggle buttons using dispatcher and update the bool variables accordingly
					// This way, we won't need to run the actual job in the dispatcher thread
					Application.Current.Dispatcher.Invoke(() =>
					{
						GUIExclusions.MicrosoftDefenderToggleButtonStatus = MicrosoftDefenderToggleButton.IsChecked ?? false;
						GUIExclusions.ControlledFolderAccessToggleButtonStatus = ControlledFolderAccessToggleButton.IsChecked ?? false;
						GUIExclusions.AttackSurfaceReductionRulesToggleButtonStatus = AttackSurfaceReductionRulesToggleButton.IsChecked ?? false;

					});

					// Run the exclusion addition job asynchronously in a different thread
					await Task.Run(() =>
					{

						// If user selected file paths
						if (GUIExclusions.selectedFiles is not null)
						{

							#region Getting the current exclusion lists

							// These already run in the Initialize() method but we need them up to date after user adds files to the exclusions and then presses the execute button again

							// Get the MSFT_MpPreference WMI results and save them to the global variable GlobalVars.MDAVPreferencesCurrent
							GlobalVars.MDAVPreferencesCurrent = MpPreferenceHelper.GetMpPreference();


							// Attempt to retrieve the property value as string[]
							string[] ExclusionPathArray = PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "ExclusionPath");

							// Check if the result is not null, then convert to List<string>, or initialize an empty list if null
							List<string> ExclusionPathList = ExclusionPathArray is not null
								? [.. ExclusionPathArray]
								: [];


							// Attempt to retrieve the property value as string[]
							string[] ControlledFolderAccessAllowedApplicationsArray = PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "ControlledFolderAccessAllowedApplications");

							// Check if the result is not null, then convert to List<string>, or initialize an empty list if null
							List<string> ControlledFolderAccessAllowedApplicationsList = ControlledFolderAccessAllowedApplicationsArray is not null
								? [.. ControlledFolderAccessAllowedApplicationsArray]
								: [];


							// Attempt to retrieve the property value as string[]
							string[] attackSurfaceReductionOnlyExclusionsArray = PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "AttackSurfaceReductionOnlyExclusions");

							// Check if the result is not null, then convert to List<string>, or initialize an empty list if null
							// Makes it easier to check items in it later
							List<string> attackSurfaceReductionOnlyExclusionsList = attackSurfaceReductionOnlyExclusionsArray is not null
								? [.. attackSurfaceReductionOnlyExclusionsArray]
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
										ConfigDefenderHelper.ManageMpPreference<string[]>("ExclusionPath", [path], false);
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
										ConfigDefenderHelper.ManageMpPreference<string[]>("ControlledFolderAccessAllowedApplications", [path], false);

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
										ConfigDefenderHelper.ManageMpPreference<string[]>("AttackSurfaceReductionOnlyExclusions", [path], false);
									}
									else
									{
										Logger.LogMessage($"{path} already exists in the Attack Surface Reduction Rules exclusions list, skipping.", LogTypeIntel.Information);
									}
								}

							}

							// Display notification at the end if files were selected
							ToastNotification.Show(ToastNotification.Type.EndOfExclusions, null, null, null, null);

						}
						else
						{
							Logger.LogMessage("No file paths selected for exclusion addition, nothing to process.", LogTypeIntel.Information);
						}

					});

					// mark as activity completed
					ActivityTracker.IsActive = false;
				};

			// Cache the view before setting it as the CurrentView
			_viewCache["ExclusionsView"] = GUIExclusions.View;

			// Set the CurrentView to the Exclusions view
			CurrentView = GUIExclusions.View;
		}
	}
}
