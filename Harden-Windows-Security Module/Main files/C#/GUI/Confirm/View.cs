using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Markup;
using System.Windows.Media.Imaging;

namespace HardenWindowsSecurity;

public partial class GUIMain
{

	// Partial class definition for handling navigation and view models
	public partial class NavigationVM : ViewModelBase
	{
		// Method to handle the "Confirm" view, including loading and modifying it
		private void ConfirmView(object obj)
		{
			// Check if the Confirm view is already cached
			if (_viewCache.TryGetValue("ConfirmView", out var cachedView))
			{
				// Use the cached view if available
				CurrentView = cachedView;
				return;
			}

			// if Admin privileges are not available, return and do not proceed any further
			// Will prevent the page from being loaded since the CurrentView won't be set/changed
			if (!Environment.IsPrivilegedProcess)
			{
				Logger.LogMessage("Confirmation page can only be used when running the Harden Windows Security Application with Administrator privileges", LogTypeIntel.ErrorInteractionRequired);
				return;
			}

			// Read the XAML content from the file
			string xamlContent = File.ReadAllText(Path.Combine(GlobalVars.path, "Resources", "XAML", "Confirm.xaml"));

			// Parse the XAML content to create a UserControl object
			UserControl View = (UserControl)XamlReader.Parse(xamlContent);

			// Finding elements
			DataGrid SecOpsDataGrid = (DataGrid)View.FindName("SecOpsDataGrid");
			TextBlock TotalCurrentlyDisplayedSecOpsTextBlock = (TextBlock)View.FindName("TotalCurrentlyDisplayedSecOps");
			ToggleButton CompliantItemsToggleButton = (ToggleButton)View.FindName("CompliantItemsToggleButton");
			ToggleButton NonCompliantItemsToggleButton = (ToggleButton)View.FindName("NonCompliantItemsToggleButton");
			Button ExportResultsButton = (Button)View.FindName("ExportResultsButton");
			TextBox textBoxFilter = (TextBox)View.FindName("textBoxFilter");
			TextBlock TotalCountTextBlock = (TextBlock)View.FindName("TotalCountTextBlock");
			ComboBox ComplianceCategoriesSelectionComboBox = (ComboBox)View.FindName("ComplianceCategoriesSelectionComboBox");

			// Initialize an empty security options collection
			ObservableCollection<SecOp> SecOpsObservableCollection = [];

			// Create a collection view based on the security options collection for filtering and sorting
			ICollectionView SecOpsCollectionView = CollectionViewSource.GetDefaultView(SecOpsObservableCollection);

			// Set the ItemSource of the DataGrid in the Confirm view to the collection view
			// Bind the DataGrid to the collection view
			SecOpsDataGrid.ItemsSource = SecOpsCollectionView;

			// Method to update the text block showing the total count of currently displayed items in the GUI
			void UpdateCurrentVisibleItemsTextBlock()
			{
				// Get the count of all of the current items in the CollectionView
				int totalDisplayedItemsCount = SecOpsCollectionView.OfType<SecOp>().Count();

				// Display the count in a text box in the GUI
				TotalCurrentlyDisplayedSecOpsTextBlock.Text = $"Showing {totalDisplayedItemsCount} Items";
			}

			// A Method to apply filters on the DataGrid based on the filter text and toggle buttons
			void ApplyFilters(string filterText, bool includeCompliant, bool includeNonCompliant)
			{
				// Apply a filter to the collection view based on the filter text and toggle buttons
				SecOpsCollectionView.Filter = memberObj =>
				{
					if (memberObj is SecOp member)
					{
						// Check if the item passes the text filter
						bool passesTextFilter =
							   (member.FriendlyName?.Contains(filterText, StringComparison.OrdinalIgnoreCase) ?? false) ||
							   (member.Value?.Contains(filterText, StringComparison.OrdinalIgnoreCase) ?? false) ||
							   (member.Name?.Contains(filterText, StringComparison.OrdinalIgnoreCase) ?? false) ||
							   (member.Category.ToString()?.Contains(filterText, StringComparison.OrdinalIgnoreCase) ?? false) ||
							   (member.Method?.Contains(filterText, StringComparison.OrdinalIgnoreCase) ?? false);

						// Check if the item passes the compliant toggle buttons filters
						bool passesCompliantFilter = (includeCompliant && member.Compliant) || (includeNonCompliant && !member.Compliant);

						// Return true if the item passes all filters
						return passesTextFilter && passesCompliantFilter;
					}
					return false;
				};

				SecOpsCollectionView.Refresh(); // Refresh the collection view to apply the filter

				UpdateCurrentVisibleItemsTextBlock();
			}

			#region event handlers for data filtration
			// Attach event handlers to the text box filter and toggle buttons
			textBoxFilter.TextChanged += (sender, e) => ApplyFilters(textBoxFilter.Text, CompliantItemsToggleButton.IsChecked ?? false, NonCompliantItemsToggleButton.IsChecked ?? false);

			CompliantItemsToggleButton.Checked += (sender, e) => ApplyFilters(textBoxFilter.Text, CompliantItemsToggleButton.IsChecked ?? false, NonCompliantItemsToggleButton.IsChecked ?? false);
			CompliantItemsToggleButton.Unchecked += (sender, e) => ApplyFilters(textBoxFilter.Text, CompliantItemsToggleButton.IsChecked ?? false, NonCompliantItemsToggleButton.IsChecked ?? false);

			NonCompliantItemsToggleButton.Checked += (sender, e) => ApplyFilters(textBoxFilter.Text, CompliantItemsToggleButton.IsChecked ?? false, NonCompliantItemsToggleButton.IsChecked ?? false);
			NonCompliantItemsToggleButton.Unchecked += (sender, e) => ApplyFilters(textBoxFilter.Text, CompliantItemsToggleButton.IsChecked ?? false, NonCompliantItemsToggleButton.IsChecked ?? false);
			#endregion

			#region RefreshButton
			// Find the Refresh button and attach the Click event handler

			// Access the grid containing the Refresh Button
			Grid RefreshButtonGrid = (Grid)View.FindName("RefreshButtonGrid");

			// Access the Refresh Button
			ToggleButton RefreshButton = (ToggleButton)RefreshButtonGrid.FindName("RefreshButton");

			// Apply the template to make sure it's available
			_ = RefreshButton.ApplyTemplate();

			// Access the image within the Refresh Button's template
			Image RefreshIconImage = (Image)RefreshButton.Template.FindName("RefreshIconImage", RefreshButton);

			// Update the image source for the Refresh button
			// Load the Refresh icon image into memory and set it as the source
			BitmapImage RefreshIconBitmapImage = new();
			RefreshIconBitmapImage.BeginInit();
			RefreshIconBitmapImage.UriSource = new Uri(Path.Combine(GlobalVars.path, "Resources", "Media", "ExecuteButton.png"));
			RefreshIconBitmapImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
			RefreshIconBitmapImage.EndInit();
			RefreshIconImage.Source = RefreshIconBitmapImage;

			#endregion

			#region ComboBox

			// Get the valid compliance category names
			List<string> catsList = [.. Enum.GetNames<ComplianceCategories>()];

			// Add an item to the list at the beginning to be the default value
			catsList.Insert(0, "All Categories");

			// Set the ComboBox's ItemsSource to the updated list
			ComplianceCategoriesSelectionComboBox.ItemsSource = catsList;

			#endregion

			// Register the elements that will be enabled/disabled based on current global activity
			ActivityTracker.RegisterUIElement(RefreshButton);
			ActivityTracker.RegisterUIElement(ComplianceCategoriesSelectionComboBox);

			// Set up the Click event handler for the Refresh button
			RefreshButton.Click += async (sender, e) =>
			{
				// Only continue if there is no activity other places
				if (ActivityTracker.IsActive)
				{
					return;
				}

				// mark as activity started
				ActivityTracker.IsActive = true;

				// Clear the current security options before starting data generation
				SecOpsObservableCollection.Clear();
				SecOpsCollectionView.Refresh(); // Refresh the collection view to clear the DataGrid

				// Set text blocks to empty while new data is being generated
				Application.Current.Dispatcher.Invoke(() =>
					{
						TotalCountTextBlock.Text = "Loading...";
						CompliantItemsToggleButton.Content = "Compliant Items";
						NonCompliantItemsToggleButton.Content = "Non-Compliant Items";

						UpdateCurrentVisibleItemsTextBlock();
					});

				// Run the method asynchronously in a different thread
				await Task.Run(() =>
					{
						// Get fresh data for compliance checking
						Initializer.Initialize(null, true);

						// Get the currently selected compliance category - Use the App dispatcher since this is being done in a different thread
						string SelectedCategory = app.Dispatcher.Invoke(() => ComplianceCategoriesSelectionComboBox.SelectedItem.ToString()!);

						// If all categories is selected which is the default
						if (string.Equals(SelectedCategory, "All Categories", StringComparison.OrdinalIgnoreCase))
						{
							// Perform the compliance check for all categories
							InvokeConfirmation.Invoke(null);
						}
						// if user selected a category for compliance checking
						else
						{
							// Perform the compliance check using the selected compliance category
							InvokeConfirmation.Invoke([SelectedCategory]);
						}
					});

				// After InvokeConfirmation is completed, update the security options collection
				await Application.Current.Dispatcher.InvokeAsync(() =>
					{
						LoadMembers(); // Load updated security options
						RefreshButton.IsChecked = false; // Uncheck the Refresh button

						UpdateCurrentVisibleItemsTextBlock();
					});

				// mark as activity completed
				ActivityTracker.IsActive = false;
			};

			/// <summary>
			/// Method to load security options from the FinalMegaObject and update the DataGrid
			/// Also sets custom background colors for each category
			/// </summary>
			void LoadMembers()
			{
				// Clear the current security options
				SecOpsObservableCollection.Clear();

				// Retrieve data from GlobalVars.FinalMegaObject and populate the security options collection
				foreach (KeyValuePair<ComplianceCategories, List<IndividualResult>> kvp in GlobalVars.FinalMegaObject)
				{
					// Loop over the results for the category
					foreach (IndividualResult result in kvp.Value)
					{
						// Add each result as a new SecOp object to the collection
						SecOpsObservableCollection.Add(new SecOp
						{
							FriendlyName = result.FriendlyName,
							Value = result.Value,
							Name = result.Name,
							Category = result.Category,
							Method = result.Method.ToString(),
							Compliant = result.Compliant
						});
					}
				}

				// Refresh the collection view to update the DataGrid
				SecOpsCollectionView.Refresh();

				// Update the total count display
				UpdateTotalCount(true);
			}


			/// <summary>
			/// Method to update the total count of security options displayed on the Text Block
			/// In the Confirmation page view
			/// </summary>
			/// <param name="ShowNotification">If set to true, this method will display end of confirmation toast notification</param>
			void UpdateTotalCount(bool ShowNotification)
			{
				// calculates the total number of all security options across all lists, so all the items in each category that exist in the values of the main dictionary object
				int totalCount = GlobalVars.FinalMegaObject.Values.Sum(list => list.Count);

				// Update the text of the TextBlock to show the total count
				TotalCountTextBlock.Text = $"{totalCount} Total Verifiable Security Checks";

				// Get the count of the compliant items
				string CompliantItemsCount = SecOpsCollectionView.SourceCollection
					.Cast<SecOp>()
					.Count(item => item.Compliant).ToString(CultureInfo.InvariantCulture);

				// Get the count of the Non-compliant items
				string NonCompliantItemsCount = SecOpsCollectionView.SourceCollection
					.Cast<SecOp>()
					.Count(item => !item.Compliant).ToString(CultureInfo.InvariantCulture);

				// Set the text block's text
				CompliantItemsToggleButton.Content = $"{CompliantItemsCount} Compliant Items";

				// Set the text block's text
				NonCompliantItemsToggleButton.Content = $"{NonCompliantItemsCount} Non-Compliant Items";

				// Display a notification if ShowNotification is set to true
				if (ShowNotification)
				{
					ToastNotification.Show(ToastNotification.Type.EndOfConfirmation, CompliantItemsCount, NonCompliantItemsCount, null, null);
				}
			}

			// Event handler for the Export Results button
			ExportResultsButton.Click += async (sender, e) =>
			{
				try
				{
					ExportResultsButton.IsEnabled = false;

					await Task.Run(() =>
					{
						// Show the save file dialog to let the user pick the save location
						Microsoft.Win32.SaveFileDialog saveFileDialog = new()
						{
							FileName = $"Harden Windows Security Compliance Check Results at {DateTime.Now:yyyy-MM-dd HH-mm-ss}", // Default file name
							DefaultExt = ".csv",                // Default file extension
							Filter = "CSV File (.csv)|*.csv"    // Filter files by extension
						};

						// Show the dialog and check if the user picked a file
						bool? result = saveFileDialog.ShowDialog();

						if (result == true)
						{
							// Get the selected file path from the dialog
							string filePath = saveFileDialog.FileName;

							ExportSecOpsToCsv(filePath, SecOpsObservableCollection);

							Logger.LogMessage($"Compliance check results have been successfully exported.", LogTypeIntel.InformationInteractionRequired);
						}
					});
				}
				finally
				{
					ExportResultsButton.IsEnabled = true;
				}
			};


			// To Export the results of the compliance checking to a file
			void ExportSecOpsToCsv(string filePath, ObservableCollection<SecOp> secOps)
			{
				// Defining the header row
				string[] headers = ["FriendlyName", "Compliant", "Value", "Name", "Category", "Method"];

				// Open the file for writing
				using StreamWriter writer = new(filePath);

				// Write the header row
				writer.WriteLine(string.Join(",", headers.Select(header => $"\"{header}\"")));

				// Write each SecOp object as a row in the CSV
				foreach (SecOp secOp in secOps)
				{
					string[] row = [
						EscapeForCsv(secOp.FriendlyName),
						EscapeForCsv(secOp.Compliant.ToString(CultureInfo.InvariantCulture)),
						EscapeForCsv(secOp.Value),
						EscapeForCsv(secOp.Name),
						EscapeForCsv(secOp.Category.ToString()),
						EscapeForCsv(secOp.Method)
					];

					writer.WriteLine(string.Join(",", row));
				}
			}

			// Local method to enclose values in double quotes
			string EscapeForCsv(string? value)
			{
				// If the value is null, empty or whitespace, return an empty string
				if (string.IsNullOrWhiteSpace(value)) return string.Empty;

				// Otherwise, escape double quotes and wrap the value in double quotes
				return $"\"{value.Replace("\"", "\"\"", StringComparison.OrdinalIgnoreCase)}\"";
			}

			// Cache the Confirm view for future use
			_viewCache["ConfirmView"] = View;

			// Set the CurrentView to the modified Confirm view
			CurrentView = View;
		}
	}
}
