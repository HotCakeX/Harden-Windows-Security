// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Controls;
using System.Windows.Markup;
using Microsoft.Win32;

namespace HardenWindowsSecurity;

public partial class GUIMain
{
	public partial class NavigationVM : ViewModelBase
	{

		// Method to handle the FileReputation view, including loading
		private void FileReputationView(object? obj)
		{

			// Check if the view is already cached
			if (_viewCache.TryGetValue("FileReputationView", out var cachedView))
			{
				CurrentView = cachedView;
				return;
			}

			// Read the XAML content from the file
			string xamlContent = File.ReadAllText(Path.Combine(GlobalVars.path, "Resources", "XAML", "FileReputation.xaml"));

			// Parse the XAML content to create a UserControl
			GUIFileReputation.View = (UserControl)XamlReader.Parse(xamlContent);

			// Find the Parent Grid
			GUIFileReputation.ParentGrid = (Grid)GUIFileReputation.View.FindName("ParentGrid");

			#region finding elements

			Button BrowseForFileButton = (Button)GUIFileReputation.ParentGrid.FindName("BrowseForFileButton");
			TextBox FileReputationTextBlock = (TextBox)GUIFileReputation.ParentGrid.FindName("FileReputationTextBlock");
			TextBox ReputationSourceTextBlock = (TextBox)GUIFileReputation.ParentGrid.FindName("ReputationSourceTextBlock");
			TextBox ValidityDurationTextBlock = (TextBox)GUIFileReputation.ParentGrid.FindName("ValidityDurationTextBlock");
			TextBox FileHandleTextBlock = (TextBox)GUIFileReputation.ParentGrid.FindName("FileHandleTextBlock");
			TextBox FilePathTextBlock = (TextBox)GUIFileReputation.ParentGrid.FindName("FilePathTextBlock");

			#endregion

			// Event handler for Retrieve ASR Status Button
			BrowseForFileButton.Click += async (sender, e) =>
			{
				BrowseForFileButton.IsEnabled = false;

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
					BrowseForFileButton.IsEnabled = true;
				}

			};


			// Cache the view before setting it as the CurrentView
			_viewCache["FileReputationView"] = GUIFileReputation.View;

			CurrentView = GUIFileReputation.View;
		}
	}
}
