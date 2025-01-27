using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Markup;
using Microsoft.Win32;

#nullable disable

namespace HardenWindowsSecurity;

public partial class GUIMain
{
	public partial class NavigationVM : ViewModelBase
	{

		// Method to handle the Protect view, including loading
		private void ProtectView(object obj)
		{
			// Check if the view is already cached
			if (_viewCache.TryGetValue("ProtectView", out var cachedView))
			{
				CurrentView = cachedView;
				return;
			}

			// Read the XAML content from the file
			string xamlContent = File.ReadAllText(Path.Combine(GlobalVars.path, "Resources", "XAML", "Protect.xaml"));

			// Parse the XAML content to create a UserControl
			UserControl View = (UserControl)XamlReader.Parse(xamlContent);

			// Finding the grids inside of each TabItem
			Grid ProtectionParentGrid = (Grid)View.FindName("ProtectionParentGrid");
			Grid OfflineConfigurationsGrid = (Grid)View.FindName("OfflineConfigurationsGrid");
			// Finding other elements
			GUIProtectWinSecurity.ProtectionPresetComboBox = (ComboBox)ProtectionParentGrid.FindName("ProtectionPresetComboBox");
			ToggleButton executeButton = (ToggleButton)ProtectionParentGrid.FindName("Execute");
			GUIProtectWinSecurity.categories = (ListView)ProtectionParentGrid.FindName("Categories");
			GUIProtectWinSecurity.subCategories = (ListView)ProtectionParentGrid.FindName("SubCategories");
			GUIProtectWinSecurity.selectAllCategories = (CheckBox)ProtectionParentGrid.FindName("SelectAllCategories");
			GUIProtectWinSecurity.selectAllSubCategories = (CheckBox)ProtectionParentGrid.FindName("SelectAllSubCategories");
			GUIProtectWinSecurity.txtFilePath = (TextBox)ProtectionParentGrid.FindName("txtFilePath");
			GUIProtectWinSecurity.logPath = (Button)ProtectionParentGrid.FindName("LogPath");
			GUIProtectWinSecurity.log = (ToggleButton)ProtectionParentGrid.FindName("Log");
			GUIProtectWinSecurity.EventLogging = (ToggleButton)ProtectionParentGrid.FindName("EventLogging");
			GUIProtectWinSecurity.enableOfflineMode = (ToggleButton)OfflineConfigurationsGrid.FindName("EnableOfflineMode");
			GUIProtectWinSecurity.microsoftSecurityBaselineZipButton = (Button)OfflineConfigurationsGrid.FindName("MicrosoftSecurityBaselineZipButton");
			GUIProtectWinSecurity.microsoftSecurityBaselineZipTextBox = (TextBox)OfflineConfigurationsGrid.FindName("MicrosoftSecurityBaselineZipTextBox");
			GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipButton = (Button)OfflineConfigurationsGrid.FindName("Microsoft365AppsSecurityBaselineZipButton");
			GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipTextBox = (TextBox)OfflineConfigurationsGrid.FindName("Microsoft365AppsSecurityBaselineZipTextBox");
			GUIProtectWinSecurity.lgpoZipButton = (Button)OfflineConfigurationsGrid.FindName("LGPOZipButton");
			GUIProtectWinSecurity.lgpoZipTextBox = (TextBox)OfflineConfigurationsGrid.FindName("LGPOZipTextBox");
			TextBlock OfflineConfigurationsNoticeTextBlock = (TextBlock)OfflineConfigurationsGrid.FindName("OfflineConfigurationsNoticeTextBlock");

			// Attach an event handler to the Preset selection ComboBox
			GUIProtectWinSecurity.ProtectionPresetComboBox.SelectionChanged += (sender, args) =>
			{
				// Cast the sender back to a ComboBox and get the selected item as a ComboBoxItem
				if (sender is ComboBox comboBox && comboBox.SelectedItem is ComboBoxItem selectedItem)
				{
					// Assign the selected content to the SelectedProtectionPreset property
					GUIProtectWinSecurity.SelectedProtectionPreset = selectedItem.Content.ToString();

					// Uncheck all categories first
					foreach (ListViewItem item in GUIProtectWinSecurity.categories.Items)
					{
						((CheckBox)item.Content).IsChecked = false;
					}

					// Uncheck all sub-categories first
					foreach (ListViewItem item in GUIProtectWinSecurity.subCategories.Items)
					{
						((CheckBox)item.Content).IsChecked = false;
					}

					// Check the categories and sub-categories based on the preset configurations
					switch (GUIProtectWinSecurity.SelectedProtectionPreset?.ToLowerInvariant())
					{
						case "preset: basic":
							{
								app.Dispatcher.Invoke(() =>
								 {

									 string presetName = "preset: basic";

									 // Check if the preset exists in the dictionary
									 if (GUIProtectWinSecurity.PresetsIntel.TryGetValue(presetName, out Dictionary<string, List<string>> categoriesAndSubcategories))
									 {
										 // Access the categories and subcategories
										 List<string> categories = categoriesAndSubcategories["Categories"];
										 List<string> subcategories = categoriesAndSubcategories["SubCategories"];

										 // Loop over each category in the dictionary
										 foreach (string category in categories)
										 {

											 // Loop over each category in the GUI
											 foreach (ListViewItem categoryItem in GUIProtectWinSecurity.categories.Items)
											 {
												 // get the name of the list view item as string
												 string categoryItemName = ((CheckBox)categoryItem.Content).Name.ToString();

												 // if the category is authorized to be available
												 if (GlobalVars.HardeningCategorieX.Contains(categoryItemName))
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
											 foreach (ListViewItem SubCategoryItem in GUIProtectWinSecurity.subCategories.Items)
											 {
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
								break;
							}
						case "preset: recommended":
							{
								app.Dispatcher.Invoke(() =>
								{

									string presetName = "preset: recommended";

									// Check if the preset exists in the dictionary
									if (GUIProtectWinSecurity.PresetsIntel.TryGetValue(presetName, out Dictionary<string, List<string>> categoriesAndSubcategories))
									{
										// Access the categories and subcategories
										List<string> categories = categoriesAndSubcategories["Categories"];
										List<string> subcategories = categoriesAndSubcategories["SubCategories"];

										// Loop over each category in the dictionary
										foreach (string category in categories)
										{
											// Loop over each category in the GUI
											foreach (ListViewItem categoryItem in GUIProtectWinSecurity.categories.Items)
											{
												// get the name of the list view item as string
												string categoryItemName = ((CheckBox)categoryItem.Content).Name.ToString();

												// if the category is authorized to be available
												if (GlobalVars.HardeningCategorieX.Contains(categoryItemName))
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
											foreach (ListViewItem SubCategoryItem in GUIProtectWinSecurity.subCategories.Items)
											{
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
								break;
							}
						case "preset: complete":
							{

								string presetName = "preset: complete";

								// Check if the preset exists in the dictionary
								if (GUIProtectWinSecurity.PresetsIntel.TryGetValue(presetName, out Dictionary<string, List<string>> categoriesAndSubcategories))
								{
									// Access the categories and subcategories
									List<string> categories = categoriesAndSubcategories["Categories"];
									List<string> subcategories = categoriesAndSubcategories["SubCategories"];

									// Loop over each category in the dictionary
									foreach (string category in categories)
									{
										// Loop over each category in the GUI
										foreach (ListViewItem categoryItem in GUIProtectWinSecurity.categories.Items)
										{
											// get the name of the list view item as string
											string categoryItemName = ((CheckBox)categoryItem.Content).Name.ToString();

											// if the category is authorized to be available
											if (GlobalVars.HardeningCategorieX.Contains(categoryItemName))
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
										foreach (ListViewItem SubCategoryItem in GUIProtectWinSecurity.subCategories.Items)
										{
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
								break;
							}

						default:
							break;
					}
				}
			};

			// Initially set the text area for the selected LogPath to disabled
			GUIProtectWinSecurity.txtFilePath.IsEnabled = false;

			// Defining event handler
			// When the Log checkbox is checked, enable the log path text area
			GUIProtectWinSecurity.log.Checked += (sender, e) =>
			{
				GUIProtectWinSecurity.txtFilePath.IsEnabled = true;
			};

			// Defining event handler
			// When the Log checkbox is unchecked, set the LogPath text area to disabled
			GUIProtectWinSecurity.log.Unchecked += (sender, e) =>
			{
				// Only disable the Log text file path element if it's not empty
				if (string.IsNullOrWhiteSpace(GUIProtectWinSecurity.txtFilePath.Text))
				{
					GUIProtectWinSecurity.txtFilePath.IsEnabled = false;
				}
			};

			// Event handler for the Log Path button click to open a file path picker dialog
			GUIProtectWinSecurity.logPath.Click += (sender, e) =>
			{
				SaveFileDialog dialog = new()
				{
					// Defining the initial directory where the file picker GUI will be opened for the user
					InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
					Filter = "Text files (*.txt)|*.txt",
					Title = "Choose where to save the log file",
					FileName = $"Harden Windows Security App Logs Export At {DateTime.Now:yyyy-MM-dd HH-mm-ss}.txt" // Default file name
				};

				// Show the dialog and process the result
				if (dialog.ShowDialog() == true)
				{
					// Set the chosen file path in the text box
					GUIProtectWinSecurity.txtFilePath.Text = dialog.FileName;
					// Log a message to indicate where the logs will be saved
					Logger.LogMessage($"Logs will be saved in: {GUIProtectWinSecurity.txtFilePath.Text}", LogTypeIntel.Information);
				}
			};

			// Initially disable the Offline Mode configuration inputs until the Offline Mode checkbox is checked
			GUIProtectWinSecurity.DisableOfflineModeConfigInputs();

			// The method that defines all of the event handlers for the UI elements
			void AddEventHandlers()
			{

				// Add Checked and Unchecked event handlers to category checkboxes
				foreach (ListViewItem item in GUIProtectWinSecurity.categories.Items)
				{
					CheckBox checkBox = (CheckBox)item.Content;
					checkBox.DataContext = item;
					checkBox.Checked += (sender, e) => GUIProtectWinSecurity.UpdateSubCategories();
					checkBox.Unchecked += (sender, e) => GUIProtectWinSecurity.UpdateSubCategories();
				}

				// Add click event for 'Check All' button
				GUIProtectWinSecurity.selectAllCategories.Checked += (sender, e) =>
				{
					foreach (ListViewItem item in GUIProtectWinSecurity.categories.Items)
					{
						if (GlobalVars.HardeningCategorieX.Contains(((CheckBox)item.Content).Name))
						{
							((CheckBox)item.Content).IsChecked = true;
						}
					}
				};

				// Add click event for 'Uncheck All' button
				GUIProtectWinSecurity.selectAllCategories.Unchecked += (sender, e) =>
				{
					foreach (ListViewItem item in GUIProtectWinSecurity.categories.Items)
					{
						((CheckBox)item.Content).IsChecked = false;
					}
				};

				// Add click event for 'Check All' button for enabled sub-categories
				GUIProtectWinSecurity.selectAllSubCategories.Checked += (sender, e) =>
				{

					foreach (ListViewItem item in GUIProtectWinSecurity.subCategories.Items)
					{
						if (item.IsEnabled)
						{
							((CheckBox)item.Content).IsChecked = true;
						}
					}
				};

				// Add click event for 'Uncheck All' button from sub-categories, regardless of whether they are enabled or disabled
				GUIProtectWinSecurity.selectAllSubCategories.Unchecked += (sender, e) =>
				{
					foreach (ListViewItem item in GUIProtectWinSecurity.subCategories.Items)
					{
						((CheckBox)item.Content).IsChecked = false;
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
					GUIProtectWinSecurity.DisableOfflineModeConfigInputs();
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
				View.Loaded += async (sender, e) =>
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
							app.Dispatcher.Invoke(() =>
							{

								string presetName = "preset: recommended";

								// Check if the preset exists in the dictionary
								if (GUIProtectWinSecurity.PresetsIntel.TryGetValue(presetName, out Dictionary<string, List<string>> categoriesAndSubcategories))
								{
									// Access the categories and subcategories
									List<string> categories = categoriesAndSubcategories["Categories"];
									List<string> subcategories = categoriesAndSubcategories["SubCategories"];

									// Loop over each category in the dictionary
									foreach (string category in categories)
									{

										// Loop over each category in the GUI
										foreach (ListViewItem item in GUIProtectWinSecurity.categories.Items)
										{
											// get the name of the list view item as string
											string categoryItemName = ((CheckBox)item.Content).Name.ToString();

											// if the category is authorized to be available
											if (GlobalVars.HardeningCategorieX!.Contains(categoryItemName))
											{
												// If the name of the current checkbox list view item in the loop is the same as the category name in the outer loop, then set the category on the GUI to checked
												if (string.Equals(categoryItemName, category, StringComparison.OrdinalIgnoreCase))
												{
													((CheckBox)item.Content).IsChecked = true;
												}

											}
										}
									}

									foreach (string subcategory in subcategories)
									{

										// Loop over each sub-category in the GUI
										foreach (ListViewItem item in GUIProtectWinSecurity.subCategories.Items)
										{
											// get the name of the list view item as string
											string SubcategoryItemName = ((CheckBox)item.Content).Name.ToString();

											// If the name of the current checkbox list view item in the loop is the same as the sub-category name in the outer loop, then set the sub-category on the GUI to checked
											if (string.Equals(SubcategoryItemName, subcategory, StringComparison.OrdinalIgnoreCase))
											{
												((CheckBox)item.Content).IsChecked = true;
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

								Logger.LogMessage(Environment.IsPrivilegedProcess ? $"Hello {Environment.UserName}, you have Administrator privileges" : $"Hello {Environment.UserName}, you don't have Administrator privileges, some categories are disabled", LogTypeIntel.Information);
								#endregion

								// Use Dispatcher.Invoke to update the UI thread
								View.Dispatcher.Invoke(() =>
							   {
								   // Set the execute button to disabled until all the prerequisites are met
								   executeButton.IsEnabled = false;

								   // Start the execute button's operation to show the files are being downloaded
								   executeButton.IsChecked = true;
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
								View.Dispatcher.Invoke(() =>
								{
									executeButton.IsEnabled = true;
									executeButton.IsChecked = false;
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
				executeButton.Click += async (sender, e) =>
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
							View.Dispatcher.Invoke(() =>
							{
								// Call the method to get the selected categories and sub-categories
								GUIProtectWinSecurity.ExecuteButtonPress();
								// Disable the TextFilePath for the log file path
								GUIProtectWinSecurity.txtFilePath!.IsEnabled = false;
							});

							// If Offline mode is used
							if (GlobalVars.Offline)
							{

								View.Dispatcher.Invoke(() =>
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
													if (GUIProtectWinSecurity.SelectedSubCategories.Contains("TLSSecurity_BattleNetClient"))
													{
														TLSSecurity.TLSSecurity_BattleNetClient();
													}
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

													if (GUIProtectWinSecurity.SelectedSubCategories.Contains("MiscellaneousConfigurations_ReducedTelemetry"))
													{
														MiscellaneousConfigurations.MiscellaneousConfigurations_ReducedTelemetry();
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

									ToastNotification.Show(ToastNotification.Type.EndOfProtection, null, null, null, null);
								}
								else
								{
									Logger.LogMessage("No category was selected", LogTypeIntel.WarningInteractionRequired);
								}
							}

							View.Dispatcher.Invoke(() =>
							{
								// Manually trigger the ToggleButton to be unchecked to trigger the ending animation
								executeButton.IsChecked = false;

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

			// Implement the event handlers for the UI elements
			AddEventHandlers();

			// Update the sub-categories based on the initial unchecked state of the categories
			GUIProtectWinSecurity.UpdateSubCategories();

			// If not running as Admin, disable the event logging since it requires Administrator privileges
			// To write to the event source
			if (!Environment.IsPrivilegedProcess)
			{
				GUIProtectWinSecurity.EventLogging.IsEnabled = false;
			}

			// Register the Execute button to be enabled/disabled based on global activity
			ActivityTracker.RegisterUIElement(executeButton);

			// Register additional elements for automatic enablement/disablement
			ActivityTracker.RegisterUIElement(GUIProtectWinSecurity.logPath);
			ActivityTracker.RegisterUIElement(GUIProtectWinSecurity.log);

			if (!GlobalVars.Offline)
			{
				// Disable the Offline mode toggle button if -Offline parameter was not used with the function
				GUIProtectWinSecurity.enableOfflineMode.IsEnabled = false;

				// Make the text block notice visible if offline mode is not used				
				OfflineConfigurationsNoticeTextBlock.Visibility = System.Windows.Visibility.Visible;
			}

			// Cache the view before setting it as the CurrentView
			_viewCache["ProtectView"] = View;

			CurrentView = View;
		}
	}
}
