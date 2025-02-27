using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

public sealed partial class Logs : Page
{
	// Holds all lines from the currently loaded log file.
	private List<string> _allLogLines = [];

	public Logs()
	{
		this.InitializeComponent();

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Enabled;

		// Load log files when the page is initialized.
		LoadLogFiles();
	}

	/// <summary>
	/// Loads log file names from the logs directory into the ComboBox.
	/// Only files matching the name pattern are included.
	/// </summary>
	private void LoadLogFiles()
	{
		// Get files matching the pattern;
		List<FileInfo> logFiles = [.. Directory.GetFiles(Logger.LogsDirectory, "AppControlManager_Logs_*.txt")
			.Select(f => new FileInfo(f))
			.OrderByDescending(f => f.CreationTime)];

		// Clear and fill the ComboBox with full file paths.
		LogFileComboBox.Items.Clear();

		foreach (FileInfo logFile in logFiles)
		{
			LogFileComboBox.Items.Add(logFile.FullName);
		}

		// If files were found, select the first one and display its content.
		if (logFiles.Count is not 0)
		{
			LogFileComboBox.SelectedIndex = 0;
			_ = DisplayLogContentAsync(logFiles[0].FullName);
		}
	}

	/// <summary>
	/// Refreshes the list of log files.
	/// </summary>
	private void RefreshButton_Click(object sender, RoutedEventArgs e)
	{
		LoadLogFiles();
	}

	/// <summary>
	/// Loads the selected log file’s content.
	/// </summary>
	private async void LogFileComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		if (LogFileComboBox.SelectedItem is not null)
		{
			string? selectedFile = LogFileComboBox.SelectedItem.ToString();
			if (!string.IsNullOrWhiteSpace(selectedFile))
			{
				await DisplayLogContentAsync(selectedFile);
			}
		}
	}

	/// <summary>
	/// Reads the log file content asynchronously and splits it into lines.
	/// Then it updates the ItemsRepeater to display the log lines.
	/// </summary>
	private async Task DisplayLogContentAsync(string filePath)
	{
		if (File.Exists(filePath))
		{
			// Read all lines from the file in a background task.
			string[] lines = await File.ReadAllLinesAsync(filePath);

			_allLogLines = [.. lines];

			// Update the displayed log lines (filtered by search text if applicable).
			UpdateLogDisplay();
		}
	}

	/// <summary>
	/// Called when the search text changes.
	/// Filters the log lines based on the search term.
	/// </summary>
	private void SearchTextBox_TextChanged(object sender, TextChangedEventArgs e)
	{
		UpdateLogDisplay();
	}

	/// <summary>
	/// Updates the ItemsRepeater with the current log lines.
	/// If a search term is entered, only lines containing that term (case-insensitive) are displayed.
	/// </summary>
	private void UpdateLogDisplay()
	{
		string? searchText = SearchTextBox.Text.Trim();

		IEnumerable<string> filteredLines = string.IsNullOrWhiteSpace(searchText)
			? _allLogLines
			: _allLogLines.Where(line => line.Contains(searchText, StringComparison.OrdinalIgnoreCase));

		// Create a list of LogLine objects.
		List<LogLine> logLines = [.. filteredLines.Select(line => new LogLine
		{
			Text = line
		})];

		LogItemsRepeater.ItemsSource = logLines;
	}
}

/// <summary>
/// Represents one log line.
/// </summary>
internal sealed class LogLine
{
	internal required string Text { get; set; }
}
