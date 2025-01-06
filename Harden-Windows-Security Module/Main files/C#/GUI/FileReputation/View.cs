using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Controls;
using System.Windows.Markup;
using Microsoft.Win32;

namespace HardenWindowsSecurity;

public partial class GUIMain
{

	// Partial class definition for handling navigation and view models
	public partial class NavigationVM : ViewModelBase
	{

		// Method to handle the FileReputation view, including loading
		private void FileReputationView(object obj)
		{

			// Check if the view is already cached
			if (_viewCache.TryGetValue("FileReputationView", out var cachedView))
			{
				CurrentView = cachedView;
				return;
			}

			// Construct the file path for the FileReputation view XAML
			string xamlPath = Path.Combine(GlobalVars.path, "Resources", "XAML", "FileReputation.xaml");

			// Read the XAML content from the file
			string xamlContent = File.ReadAllText(xamlPath);

			// Parse the XAML content to create a UserControl
			GUIFileReputation.View = (UserControl)XamlReader.Parse(xamlContent);

			// Find the Parent Grid
			GUIFileReputation.ParentGrid = (Grid)GUIFileReputation.View.FindName("ParentGrid");

			#region finding elements

			Button BrowseForFileButton = GUIFileReputation.ParentGrid.FindName("BrowseForFileButton") as Button ?? throw new InvalidOperationException("BrowseForFileButton could not be found in the FileReputation view");
			TextBox FileReputationTextBlock = GUIFileReputation.ParentGrid.FindName("FileReputationTextBlock") as TextBox ?? throw new InvalidOperationException("FileReputationTextBlock could not be found in the FileReputation view");
			TextBox ReputationSourceTextBlock = GUIFileReputation.ParentGrid.FindName("ReputationSourceTextBlock") as TextBox ?? throw new InvalidOperationException("ReputationSourceTextBlock could not be found in the FileReputation view");
			TextBox ValidityDurationTextBlock = GUIFileReputation.ParentGrid.FindName("ValidityDurationTextBlock") as TextBox ?? throw new InvalidOperationException("ValidityDurationTextBlock could not be found in the FileReputation view");
			TextBox FileHandleTextBlock = GUIFileReputation.ParentGrid.FindName("FileHandleTextBlock") as TextBox ?? throw new InvalidOperationException("FileHandleTextBlock could not be found in the FileReputation view");
			TextBox FilePathTextBlock = GUIFileReputation.ParentGrid.FindName("FilePathTextBlock") as TextBox ?? throw new InvalidOperationException("FilePathTextBlock could not be found in the FileReputation view");


			#endregion

			// Register the elements that will be enabled/disabled based on current activity
			ActivityTracker.RegisterUIElement(BrowseForFileButton);


			// Event handler for Retrieve ASR Status Button
			BrowseForFileButton.Click += async (sender, e) =>
			{
				// Only continue if there is no activity other places
				if (ActivityTracker.IsActive)
				{
					return;
				}

				// mark as activity started
				ActivityTracker.IsActive = true;

				FileReputationTextBlock.Text = null;
				ReputationSourceTextBlock.Text = null;
				ValidityDurationTextBlock.Text = null;
				FileHandleTextBlock.Text = null;
				FilePathTextBlock.Text = null;

				try
				{

					GUIFileReputation.selectedFilePath = null;

					// Create OpenFileDialog instance
					OpenFileDialog openFileDialog = new()
					{
						// Set the title of the dialog
						Title = "Select a file to verify its reputation",

						// Allow single file selection only
						Multiselect = false,

						// Show all files
						Filter = "Any file (*.*)|*.*"
					};

					// Show the dialog and check if the user selected file
					if (openFileDialog.ShowDialog() == true)
					{
						// Retrieve selected file path
						GUIFileReputation.selectedFilePath = openFileDialog.FileName;

						Logger.LogMessage($"Selected file path: {GUIFileReputation.selectedFilePath}", LogTypeIntel.Information);

						FileTrustChecker.FileTrustResult? result = null;

						await Task.Run(() =>
						{
							try
							{

								result = FileTrustChecker.CheckFileTrust(GUIFileReputation.selectedFilePath);
							}
							catch (Exception ex)
							{
								Logger.LogMessage($"Error occurred while checking file trust: {ex.Message}", LogTypeIntel.Error);
							}
						});

						// Assign the results to the UI text blocks
						FileReputationTextBlock.Text = result?.Reputation;
						ReputationSourceTextBlock.Text = result?.Source.ToString();
						ValidityDurationTextBlock.Text = result?.Duration;
						FileHandleTextBlock.Text = result?.Handle;
						FilePathTextBlock.Text = GUIFileReputation.selectedFilePath;
					}
				}
				finally
				{
					// mark as activity completed
					ActivityTracker.IsActive = false;
				}

			};


			// Cache the view before setting it as the CurrentView
			_viewCache["FileReputationView"] = GUIFileReputation.View;

			// Set the CurrentView to the Protect view
			CurrentView = GUIFileReputation.View;
		}
	}
}
