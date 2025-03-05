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

		// This forces the page to reload when user visits the page without the need to click on the refresh button
		this.NavigationCacheMode = NavigationCacheMode.Disabled;
	}

	protected override void OnNavigatedTo(NavigationEventArgs e)
	{
		base.OnNavigatedTo(e);

		// Load log files
		LoadLogFiles();
	}

	/// <summary>
	/// Loads log file names from the logs directory into the ComboBox.
	/// Only files matching the name pattern are included.
	/// </summary>
	private void LoadLogFiles()
	{
		// Get files matching the pattern;
		List<FileInfo> logFiles = [.. Directory.GetFiles(GlobalVars.LogsDirectory, "AppControlManager_Logs_*.txt")
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
	/// Reads the log file content asynchronously using a FileStream with FileShare.ReadWrite.
	/// This allows reading even while the file is in use by the logger.
	/// The file content is then split into lines and the ItemsRepeater updated.
	/// </summary>
	private async Task DisplayLogContentAsync(string filePath)
	{
		if (File.Exists(filePath))
		{
			// Since the logger might be writing to the file at the same time the UI is reading it, we open the file with FileShare.ReadWrite
			// This allows concurrent read/write operations without file locking issues.
			using FileStream stream = new(
				filePath,
				FileMode.Open,
				FileAccess.Read,
				FileShare.ReadWrite);
			using StreamReader reader = new(stream);
			string content = await reader.ReadToEndAsync();

			// Split file content into individual lines.
			_allLogLines = [.. content.Split(["\r\n", "\n"], StringSplitOptions.None)];

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
