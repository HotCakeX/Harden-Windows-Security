using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Markup;
using System.Windows.Media.Imaging;
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
			GUIProtectWinSecurity.View = (UserControl)XamlReader.Parse(xamlContent);

			// Finding the grids inside of each TabItem
			GUIProtectWinSecurity.ProtectionParentGrid = (Grid)GUIProtectWinSecurity.View.FindName("ProtectionParentGrid");
			GUIProtectWinSecurity.OfflineConfigurationsGrid = (Grid)GUIProtectWinSecurity.View.FindName("OfflineConfigurationsGrid");

			#region Combobox
			GUIProtectWinSecurity.ProtectionPresetComboBox = (ComboBox)GUIProtectWinSecurity.ProtectionParentGrid.FindName("ProtectionPresetComboBox");

			// Attach the event handler using a lambda expression
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

			#endregion

			// Access the grid containing the Execute Button
			GUIProtectWinSecurity.ExecuteButtonGrid = (Grid)GUIProtectWinSecurity.ProtectionParentGrid.FindName("ExecuteButtonGrid");

			// Access the Execute Button
			GUIProtectWinSecurity.ExecuteButton = (ToggleButton)GUIProtectWinSecurity.ExecuteButtonGrid!.FindName("Execute");

			// Apply the template to make sure it's available
			_ = GUIProtectWinSecurity.ExecuteButton.ApplyTemplate();

			// Access the image within the Execute Button's template
			GUIProtectWinSecurity.ExecuteButtonImage = (Image)GUIProtectWinSecurity.ExecuteButton.Template.FindName("ExecuteIconImage", GUIProtectWinSecurity.ExecuteButton);

			// Update the image source for the execute button
			// Load the Execute button image into memory and set it as the source
			BitmapImage ExecuteButtonBitmapImage = new();
			ExecuteButtonBitmapImage.BeginInit();
			ExecuteButtonBitmapImage.UriSource = new Uri(Path.Combine(GlobalVars.path, "Resources", "Media", "ExecuteButton.png"));
			ExecuteButtonBitmapImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
			ExecuteButtonBitmapImage.EndInit();

			GUIProtectWinSecurity.ExecuteButtonImage.Source = ExecuteButtonBitmapImage;

			GUIProtectWinSecurity.categories = (ListView)GUIProtectWinSecurity.ProtectionParentGrid.FindName("Categories");
			GUIProtectWinSecurity.subCategories = (ListView)GUIProtectWinSecurity.ProtectionParentGrid.FindName("SubCategories");
			GUIProtectWinSecurity.selectAllCategories = (CheckBox)GUIProtectWinSecurity.ProtectionParentGrid.FindName("SelectAllCategories");
			GUIProtectWinSecurity.selectAllSubCategories = (CheckBox)GUIProtectWinSecurity.ProtectionParentGrid.FindName("SelectAllSubCategories");

			// For Log related elements
			GUIProtectWinSecurity.txtFilePath = (TextBox)GUIProtectWinSecurity.ProtectionParentGrid.FindName("txtFilePath");
			GUIProtectWinSecurity.logPath = (Button)GUIProtectWinSecurity.ProtectionParentGrid.FindName("LogPath");
			GUIProtectWinSecurity.log = (ToggleButton)GUIProtectWinSecurity.ProtectionParentGrid.FindName("Log");
			GUIProtectWinSecurity.EventLogging = (ToggleButton)GUIProtectWinSecurity.ProtectionParentGrid.FindName("EventLogging");

			// For Offline Configurations elements
			GUIProtectWinSecurity.enableOfflineMode = (ToggleButton)GUIProtectWinSecurity.OfflineConfigurationsGrid.FindName("EnableOfflineMode");
			GUIProtectWinSecurity.microsoftSecurityBaselineZipButton = (Button)GUIProtectWinSecurity.OfflineConfigurationsGrid.FindName("MicrosoftSecurityBaselineZipButton");
			GUIProtectWinSecurity.microsoftSecurityBaselineZipTextBox = (TextBox)GUIProtectWinSecurity.OfflineConfigurationsGrid.FindName("MicrosoftSecurityBaselineZipTextBox");
			GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipButton = (Button)GUIProtectWinSecurity.OfflineConfigurationsGrid.FindName("Microsoft365AppsSecurityBaselineZipButton");
			GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipTextBox = (TextBox)GUIProtectWinSecurity.OfflineConfigurationsGrid.FindName("Microsoft365AppsSecurityBaselineZipTextBox");
			GUIProtectWinSecurity.lgpoZipButton = (Button)GUIProtectWinSecurity.OfflineConfigurationsGrid.FindName("LGPOZipButton");
			GUIProtectWinSecurity.lgpoZipTextBox = (TextBox)GUIProtectWinSecurity.OfflineConfigurationsGrid.FindName("LGPOZipTextBox");

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
						((CheckBox)(item).Content).IsChecked = false;
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
						((CheckBox)(item).Content).IsChecked = false;
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

								string nameToDisplay = (!string.IsNullOrWhiteSpace(GlobalVars.userFullName)) ? GlobalVars.userFullName : GlobalVars.userName;

								Logger.LogMessage(Environment.IsPrivilegedProcess ? $"Hello {nameToDisplay}, you have Administrator privileges" : $"Hello {nameToDisplay}, you don't have Administrator privileges, some categories are disabled", LogTypeIntel.Information);
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
			ActivityTracker.RegisterUIElement(GUIProtectWinSecurity.ExecuteButton);

			// Register additional elements for automatic enablement/disablement
			ActivityTracker.RegisterUIElement(GUIProtectWinSecurity.logPath);
			ActivityTracker.RegisterUIElement(GUIProtectWinSecurity.log);

			if (!GlobalVars.Offline)
			{
				// Disable the Offline mode toggle button if -Offline parameter was not used with the function
				GUIProtectWinSecurity.enableOfflineMode.IsEnabled = false;

				// Make the text block notice visible if offline mode is not used
				TextBlock OfflineConfigurationsNoticeTextBlock = (TextBlock)GUIProtectWinSecurity.OfflineConfigurationsGrid.FindName("OfflineConfigurationsNoticeTextBlock");
				OfflineConfigurationsNoticeTextBlock.Visibility = System.Windows.Visibility.Visible;
			}

			// Cache the view before setting it as the CurrentView
			_viewCache["ProtectView"] = GUIProtectWinSecurity.View;

			// Set the CurrentView to the Protect view
			CurrentView = GUIProtectWinSecurity.View;
		}
	}
}
