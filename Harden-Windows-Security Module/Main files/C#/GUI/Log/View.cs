using System;
using System.IO;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Markup;
using Microsoft.Win32;

namespace HardenWindowsSecurity;

public partial class GUIMain
{
	public partial class NavigationVM : ViewModelBase
	{

		// Method to handle the Logs view, including loading
		private void LogsView(object? obj)
		{

			// Check if the view is already cached
			if (_viewCache.TryGetValue("LogsView", out var cachedView))
			{
				CurrentView = cachedView;
				return;
			}

			// Read the XAML content from the file
			string xamlContent = File.ReadAllText(Path.Combine(GlobalVars.path, "Resources", "XAML", "Logs.xaml"));

			// Parse the XAML content to create a UserControl
			GUILogs.View = (UserControl)XamlReader.Parse(xamlContent);

			// Find the Parent Grid
			GUILogs.ParentGrid = (Grid)GUILogs.View.FindName("ParentGrid");

			ToggleButton AutoScrollToggleButton = (ToggleButton)GUILogs.ParentGrid.FindName("AutoScrollToggleButton");
			Button ExportLogsButton = (Button)GUILogs.ParentGrid.FindName("ExportLogsButton");
			GUILogs.MainLoggerTextBox = (TextBox)GUILogs.ParentGrid.FindName("MainLoggerTextBox");
			GUILogs.scrollerForOutputTextBox = (ScrollViewer)GUILogs.ParentGrid.FindName("ScrollerForOutputTextBox");
			Button ClearLogsButton = (Button)GUILogs.ParentGrid.FindName("ClearLogsButton");

			// Set the AutoScrollToggleButton to checked initially when the view is loaded
			AutoScrollToggleButton.IsChecked = true;

			AutoScrollToggleButton.Checked += (sender, e) =>
			{
				GUILogs.AutoScroll = true;
			};

			AutoScrollToggleButton.Unchecked += (sender, e) =>
			{
				GUILogs.AutoScroll = false;
			};

			// Event handler for ExportLogsButton
			ExportLogsButton.Click += (sender, e) =>
			{
				// Create a SaveFileDialog
				SaveFileDialog saveFileDialog = new()
				{
					Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
					Title = "Save Log File",
					FileName = $"Harden Windows Security App Logs Export At {DateTime.Now:yyyy-MM-dd HH-mm-ss}.txt"
				};

				// Show the dialog and check if the user clicked "Save"
				if (saveFileDialog.ShowDialog() == true)
				{
					// Get the file path selected by the user
					string filePath = saveFileDialog.FileName;

					// Write the text content from the TextBox to the file
					File.WriteAllText(filePath, GUILogs.MainLoggerTextBox.Text);

					Logger.LogMessage("Logs successfully saved.", LogTypeIntel.InformationInteractionRequired);
				}
			};

			// Event handler for ClearLogsButton
			ClearLogsButton.Click += (sender, e) =>
			{
				// Set the logs text box to an empty string, clearing all the logs from the GUI logger
				GUILogs.MainLoggerTextBox.Text = string.Empty;
			};

			// Cache the view before setting it as the CurrentView
			_viewCache["LogsView"] = GUILogs.View;

			CurrentView = GUILogs.View;
		}
	}
}
