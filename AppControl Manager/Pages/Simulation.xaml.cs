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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using CommunityToolkit.WinUI.Controls;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel.DataTransfer;

namespace AppControlManager.Pages;

/// <summary>
/// Represents a simulation page that initializes components, manages file paths, and handles user interactions for
/// simulations.
/// </summary>
internal sealed partial class Simulation : Page
{

#pragma warning disable CA1822
	private SimulationVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<SimulationVM>();
	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();
#pragma warning restore CA1822

	/// <summary>
	/// Initializes a new instance of the Simulation class. Sets up the component, navigation cache mode, data context, and
	/// initializes file and folder path arrays.
	/// </summary>
	internal Simulation()
	{
		this.InitializeComponent();
		this.NavigationCacheMode = NavigationCacheMode.Required;

		this.DataContext = ViewModel;

		filePaths = [];
		folderPaths = [];
		catRootPaths = [];
	}

	#region ListView Stuff

	/// <summary>
	/// Converts the properties of a SimulationOutput row into a labeled, formatted string for copying to clipboard.
	/// </summary>
	/// <param name="row">The selected SimulationOutput row from the ListView.</param>
	/// <returns>A formatted string of the row's properties with labels.</returns>
	private static string ConvertRowToText(SimulationOutput row)
	{
		// Use StringBuilder to format each property with its label for easy reading
		return new StringBuilder()
			.AppendLine($"Path: {row.Path}")
			.AppendLine($"Source: {row.Source}")
			.AppendLine($"Is Authorized: {row.IsAuthorized}")
			.AppendLine($"Match Criteria: {row.MatchCriteria}")
			.AppendLine($"Specific File Name Criteria: {row.SpecificFileNameLevelMatchCriteria}")
			.AppendLine($"Signer ID: {row.SignerID}")
			.AppendLine($"Signer Name: {row.SignerName}")
			.AppendLine($"Signer Cert Root: {row.SignerCertRoot}")
			.AppendLine($"Signer Cert Publisher: {row.SignerCertPublisher}")
			.AppendLine($"Signer Scope: {row.SignerScope}")
			.AppendLine($"Cert Subject CN: {row.CertSubjectCN}")
			.AppendLine($"Cert Issuer CN: {row.CertIssuerCN}")
			.AppendLine($"Cert Not After: {row.CertNotAfter}")
			.AppendLine($"Cert TBS Value: {row.CertTBSValue}")
			.AppendLine($"File Path: {row.FilePath}")
			.ToString();
	}

	/// <summary>
	/// Copies the selected rows to the clipboard in a formatted manner, with each property labeled for clarity.
	/// </summary>
	/// <param name="sender">The event sender.</param>
	/// <param name="e">The event arguments.</param>
	private void ListViewFlyoutMenuCopy_Click(object sender, RoutedEventArgs e)
	{
		// Check if there are selected items in the ListView
		if (SimOutputListView.SelectedItems.Count > 0)
		{
			// Initialize StringBuilder to store all selected rows' data with labels
			StringBuilder dataBuilder = new();

			// Loop through each selected item in the ListView
			foreach (var selectedItem in SimOutputListView.SelectedItems)
			{
				if (selectedItem is SimulationOutput obj)

					// Append each row's formatted data to the StringBuilder
					_ = dataBuilder.AppendLine(ConvertRowToText(obj));

				// Add a separator between rows for readability in multi-row copies
				_ = dataBuilder.AppendLine(ListViewHelper.DefaultDelimiter);
			}

			ClipboardManagement.CopyText(dataBuilder.ToString());
		}
	}

	// Click event handlers for each property
	private void CopyPath_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.Path);
	private void CopySource_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.Source);
	private void CopyIsAuthorized_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.IsAuthorized.ToString());
	private void CopyMatchCriteria_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.MatchCriteria);
	private void CopySpecificFileNameLevelMatch_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SpecificFileNameLevelMatchCriteria);
	private void CopySignerID_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SignerID);
	private void CopySignerName_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SignerName);
	private void CopySignerCertRoot_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SignerCertRoot);
	private void CopySignerCertPublisher_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SignerCertPublisher);
	private void CopySignerScope_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SignerScope);
	private void CopyCertSubjectCN_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.CertSubjectCN);
	private void CopyCertIssuerCN_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.CertIssuerCN);
	private void CopyCertNotAfter_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.CertNotAfter);
	private void CopyCertTBSValue_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.CertTBSValue);
	private void CopyFilePath_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.FilePath);

	/// <summary>
	/// Helper method to copy a specified property to clipboard without reflection
	/// </summary>
	/// <param name="getProperty">Function that retrieves the desired property value as a string</param>
	private void CopyToClipboard(Func<SimulationOutput, string?> getProperty)
	{
		if (SimOutputListView.SelectedItem is SimulationOutput selectedItem)
		{
			string? propertyValue = getProperty(selectedItem);
			if (propertyValue is not null)
			{
				ClipboardManagement.CopyText(propertyValue);
			}
		}
	}


	#endregion

	private List<string> filePaths; // For selected file paths
	private readonly List<string> folderPaths; // For selected folder paths
	private string? xmlFilePath; // For selected XML file path
	private List<string> catRootPaths; // For selected Cat Root paths

	/// <summary>
	/// Event handler for the Begin Simulation button
	/// </summary>
	private async void BeginSimulationButton_Click()
	{
		if (xmlFilePath is null || !File.Exists(xmlFilePath))
		{
			ViewModel.MainInfoBarVisibility = Visibility.Visible;
			ViewModel.MainInfoBarIsOpen = true;
			ViewModel.MainInfoBarMessage = "You need to select an existing XML policy file";
			ViewModel.MainInfoBarSeverity = InfoBarSeverity.Warning;
			ViewModel.MainInfoBarIsClosable = true;

			return;
		}

		bool error = false;

		try
		{
			// Collect values from UI elements
			bool noCatRootScanning = NoCatRootScanningToggle.IsChecked;
			double radialGaugeValue = ScalabilityRadialGauge.Value; // Value from radial gauge

			BeginSimulationButton.IsEnabled = false;
			ScalabilityRadialGauge.IsEnabled = false;

			ViewModel.MainInfoBarVisibility = Visibility.Visible;
			ViewModel.MainInfoBarIsOpen = true;
			ViewModel.MainInfoBarMessage = "Performing the Simulation";
			ViewModel.MainInfoBarSeverity = InfoBarSeverity.Informational;
			ViewModel.MainInfoBarIsClosable = false;

			// Reset the progress bar value back to 0 if it was set from previous runs
			SimulationProgressRing.Value = 0;

			// Run the simulation
			ConcurrentDictionary<string, SimulationOutput> result = await Task.Run(() =>
			{
				return AppControlSimulation.Invoke(
					filePaths,
					folderPaths,
					xmlFilePath,
					noCatRootScanning,
					catRootPaths,
					(ushort)radialGaugeValue,
					SimulationProgressRing
				);
			});

			// Clear the current ObservableCollection and backup the full data set
			ViewModel.SimulationOutputs.Clear();
			ViewModel.AllSimulationOutputs.Clear();

			// Update the TextBox with the total count of files
			TotalCountOfTheFilesTextBox.Text = result.Count.ToString(CultureInfo.InvariantCulture);

			ViewModel.AllSimulationOutputs.AddRange(result.Values);

			// Add to the ObservableCollection bound to the UI
			foreach (KeyValuePair<string, SimulationOutput> entry in result)
			{
				// Add a reference to the ViewModel class so we can use it for navigation in the XAML
				entry.Value.ParentViewModelSimulationVM = ViewModel;
				ViewModel.SimulationOutputs.Add(entry.Value);
			}

			ViewModel.CalculateColumnWidths();
		}
		catch (NoValidFilesSelectedException ex)
		{
			error = true;

			ViewModel.MainInfoBarVisibility = Visibility.Visible;
			ViewModel.MainInfoBarIsOpen = true;
			ViewModel.MainInfoBarMessage = ex.Message;
			ViewModel.MainInfoBarSeverity = InfoBarSeverity.Warning;
			ViewModel.MainInfoBarIsClosable = true;

			return;
		}
		catch (Exception ex)
		{
			error = true;

			ViewModel.MainInfoBarVisibility = Visibility.Visible;
			ViewModel.MainInfoBarIsOpen = true;
			ViewModel.MainInfoBarMessage = $"There was a problem during the simulation: {ex.Message}";
			ViewModel.MainInfoBarSeverity = InfoBarSeverity.Error;
			ViewModel.MainInfoBarIsClosable = true;

			throw;
		}
		finally
		{
			BeginSimulationButton.IsEnabled = true;
			ScalabilityRadialGauge.IsEnabled = true;

			if (!error)
			{
				ViewModel.MainInfoBarVisibility = Visibility.Visible;
				ViewModel.MainInfoBarIsOpen = true;
				ViewModel.MainInfoBarMessage = "Simulation completed successfully.";
				ViewModel.MainInfoBarSeverity = InfoBarSeverity.Success;
				ViewModel.MainInfoBarIsClosable = true;
			}
		}
	}

	/// <summary>
	/// Event handler for the Select XML File button
	/// </summary>
	private void SelectXmlFileButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			xmlFilePath = selectedFile;

			// Update the TextBox with the selected XML file path
			SelectXmlFileButton_SelectedFilesTextBox.Text = selectedFile;
		}
	}

	/// <summary>
	/// Event handler for the Select Files button
	/// </summary>
	private void SelectFilesButton_Click()
	{
		List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.AnyFilePickerFilter);

		if (selectedFiles is { Count: > 0 })
		{
			filePaths = [.. selectedFiles];

			foreach (string file in selectedFiles)
			{
				SelectFilesButton_SelectedFilesTextBox.Text += file + Environment.NewLine;
			}
		}
	}

	/// <summary>
	/// Event handler for the Select Folders button
	/// </summary>
	private void SelectFoldersButton_Click()
	{
		List<string>? selectedFolders = FileDialogHelper.ShowMultipleDirectoryPickerDialog();

		if (selectedFolders is { Count: > 0 })
		{
			foreach (string folder in selectedFolders)
			{
				folderPaths.Add(folder);

				SelectFoldersButton_SelectedFilesTextBox.Text += folder + Environment.NewLine;
			}
		}
	}

	/// <summary>
	/// Event handler for the Cat Root Paths button
	/// </summary>
	private void CatRootPathsButton_Click()
	{
		List<string>? selectedCatRoots = FileDialogHelper.ShowMultipleDirectoryPickerDialog();

		if (selectedCatRoots is { Count: > 0 })
		{
			catRootPaths = selectedCatRoots;
		}
	}

	// Event handler for RadialGauge ValueChanged
	private void ScalabilityRadialGauge_ValueChanged(object sender, RangeBaseValueChangedEventArgs e)
	{
		// Update the button content with the current value of the gauge
		ScalabilityButton.Content = $"Scalability: {((RadialGauge)sender).Value:N0}";
	}

	// Event handler for the Clear Data button
	private void ClearDataButton_Click(object sender, RoutedEventArgs e)
	{
		// Clear the ObservableCollection
		ViewModel.SimulationOutputs.Clear();
		// Clear the full data
		ViewModel.AllSimulationOutputs.Clear();

		// set the total count to 0 after clearing all the data
		TotalCountOfTheFilesTextBox.Text = "0";
	}

	private void SelectXmlFileButton_Flyout_Clear_Click()
	{
		SelectXmlFileButton_SelectedFilesTextBox.Text = null;
		xmlFilePath = null;
	}

	private void SelectFilesButton_Flyout_Clear_Click()
	{
		SelectFilesButton_SelectedFilesTextBox.Text = null;
		filePaths.Clear();
	}

	private void SelectFoldersButton_Flyout_Clear_Click()
	{
		SelectFoldersButton_SelectedFilesTextBox.Text = null;
		folderPaths.Clear();
	}

	/// <summary>
	/// CTRL + C shortcuts event handler
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void CtrlC_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		ListViewFlyoutMenuCopy_Click(sender, new RoutedEventArgs());
		args.Handled = true;
	}

}
