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

using System.Collections.Generic;
using System.IO;
using System.IO.Enumeration;
using System.Security;
using System.Threading.Tasks;
using AppControlManager.ViewModels;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace AppControlManager.CustomUIElements;

internal sealed partial class FilePathWildcardRulesResources : ResourceDictionary
{
	/// <summary>
	/// Initializes the shared resource dictionary and its compiled bindings.
	/// </summary>
	internal FilePathWildcardRulesResources() => InitializeComponent();

	#region Text Suggestion

	private const int MaxDirectorySuggestions = 24;
	private static readonly TimeSpan DirectorySuggestionDelay = TimeSpan.FromMilliseconds(80);
	private static readonly EnumerationOptions DirectorySuggestionEnumerationOptions = new()
	{
		RecurseSubdirectories = false,
		IgnoreInaccessible = true,
		ReturnSpecialDirectories = false,
		AttributesToSkip = 0
	};

	private DispatcherQueueTimer? directorySuggestionTimer;
	private AutoSuggestBox? pendingDirectorySuggestionBox;
	private string? pendingDirectorySuggestionText;
	private uint directorySuggestionRequestVersion;

	private void DirectoryPathAutoSuggestBox_Unloaded(object sender, RoutedEventArgs e)
	{
		StopDirectorySuggestionTimer();
		directorySuggestionTimer?.Tick -= DirectorySuggestionTimer_Tick;
		directorySuggestionTimer = null;
	}

	/// <summary>
	/// Queues directory suggestions only for user-initiated text changes.
	/// </summary>
	private void DirectoryPathAutoSuggestBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
	{
		if (args.Reason is not AutoSuggestionBoxTextChangeReason.UserInput)
		{
			return;
		}

		QueueDirectorySuggestions(sender, sender.Text);
	}

	/// <summary>
	/// Completes the selected directory with a trailing separator so typing can continue at the next level.
	/// </summary>
	private void DirectoryPathAutoSuggestBox_SuggestionChosen(AutoSuggestBox sender, AutoSuggestBoxSuggestionChosenEventArgs args)
	{
		if (args.SelectedItem is not string selectedDirectory)
		{
			return;
		}

		string completedDirectory = selectedDirectory.EndsWith(Path.DirectorySeparatorChar)
			? selectedDirectory
			: string.Concat(selectedDirectory, Path.DirectorySeparatorChar);

		sender.Text = completedDirectory;
		QueueDirectorySuggestions(sender, completedDirectory);
	}

	/// <summary>
	/// Adds the typed rule on Enter, or continues browsing when a directory suggestion was chosen.
	/// </summary>
	private void DirectoryPathAutoSuggestBox_QuerySubmitted(AutoSuggestBox sender, AutoSuggestBoxQuerySubmittedEventArgs args)
	{
		if (args.ChosenSuggestion is not null)
		{
			return;
		}

		StopDirectorySuggestionTimer();
		sender.ItemsSource = null;
		sender.IsSuggestionListOpen = false;

		if (sender.DataContext is FilePathWildcardRulesSettings settings)
		{
			settings.AddRule();
		}
	}

	private void QueueDirectorySuggestions(AutoSuggestBox sender, string? input)
	{
		directorySuggestionRequestVersion++;
		pendingDirectorySuggestionBox = sender;
		pendingDirectorySuggestionText = input;

		directorySuggestionTimer ??= CreateDirectorySuggestionTimer(sender.DispatcherQueue);
		directorySuggestionTimer.Stop();
		directorySuggestionTimer.Start();
	}

	private DispatcherQueueTimer CreateDirectorySuggestionTimer(DispatcherQueue dispatcherQueue)
	{
		DispatcherQueueTimer timer = dispatcherQueue.CreateTimer();
		timer.Interval = DirectorySuggestionDelay;
		timer.IsRepeating = false;
		timer.Tick += DirectorySuggestionTimer_Tick;
		return timer;
	}

	private async void DirectorySuggestionTimer_Tick(DispatcherQueueTimer sender, object args)
	{
		try
		{

			AutoSuggestBox? autoSuggestBox = pendingDirectorySuggestionBox;
			string? input = pendingDirectorySuggestionText;
			uint requestVersion = directorySuggestionRequestVersion;

			pendingDirectorySuggestionBox = null;
			pendingDirectorySuggestionText = null;

			if (autoSuggestBox is null)
			{
				return;
			}

			List<string> suggestions = await Task.Run(() =>
				TryGetDirectorySuggestionParts(input, out string searchDirectory, out string namePrefix)
					? GetDirectorySuggestions(searchDirectory, namePrefix)
					: []);

			if (requestVersion != directorySuggestionRequestVersion ||
				autoSuggestBox.XamlRoot is null ||
				!string.Equals(autoSuggestBox.Text, input, StringComparison.OrdinalIgnoreCase))
			{
				return;
			}

			autoSuggestBox.ItemsSource = suggestions;
			autoSuggestBox.IsSuggestionListOpen = suggestions.Count > 0;
		}
		catch { }
	}

	private void StopDirectorySuggestionTimer()
	{
		directorySuggestionRequestVersion++;
		directorySuggestionTimer?.Stop();
		pendingDirectorySuggestionBox = null;
		pendingDirectorySuggestionText = null;
	}

	/// <summary>
	/// Accepts only fully rooted drive-letter paths such as C:\ or C:\Windows\Sys.
	/// UNC, device, relative, wildcard, and file-name-only inputs do not trigger enumeration.
	/// </summary>
	private static bool TryGetDirectorySuggestionParts(
		string? input,
		out string searchDirectory,
		out string namePrefix)
	{
		searchDirectory = string.Empty;
		namePrefix = string.Empty;

		if (string.IsNullOrWhiteSpace(input))
		{
			return false;
		}

		ReadOnlySpan<char> path = input.AsSpan().Trim();
		if (path.Length < 3 ||
			!char.IsAsciiLetter(path[0]) ||
			path[1] != Path.VolumeSeparatorChar ||
			!IsDirectorySeparator(path[2]) ||
			ContainsInvalidSuggestionCharacter(path))
		{
			return false;
		}

		int lastSeparatorIndex = path.LastIndexOfAny(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
		if (lastSeparatorIndex < 2)
		{
			return false;
		}

		if (lastSeparatorIndex == path.Length - 1)
		{
			searchDirectory = path.ToString();
		}
		else
		{
			int directoryLength = lastSeparatorIndex == 2 ? 3 : lastSeparatorIndex;
			searchDirectory = path[..directoryLength].ToString();
			namePrefix = path[(lastSeparatorIndex + 1)..].ToString();
		}

		return Directory.Exists(searchDirectory);
	}

	private static bool IsDirectorySeparator(char value) => value == Path.DirectorySeparatorChar || value == Path.AltDirectorySeparatorChar;

	/// <summary>
	/// Rejects wildcard and invalid Win32 path characters without allocating a temporary character array.
	/// </summary>
	private static bool ContainsInvalidSuggestionCharacter(ReadOnlySpan<char> path)
	{
		foreach (char character in path)
		{
			if (character is '*' or '?' or '"' or '<' or '>' or '|')
			{
				return true;
			}
		}

		return false;
	}

	private static List<string> GetDirectorySuggestions(string searchDirectory, string namePrefix)
	{
		List<string> suggestions = new(MaxDirectorySuggestions);

		try
		{
			using DirectorySuggestionEnumerator enumerator = new(searchDirectory, namePrefix);
			while (suggestions.Count < MaxDirectorySuggestions && enumerator.MoveNext())
			{
				suggestions.Add(enumerator.Current);
			}
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException or ArgumentException or NotSupportedException)
		{
			// The path can disappear, become inaccessible, or point to an unavailable drive while the user is typing.
		}

		return suggestions;
	}

	/// <summary>
	/// Enumerates only immediate child directories and allocates result strings only for matching entries.
	/// </summary>
	private sealed partial class DirectorySuggestionEnumerator : FileSystemEnumerator<string>
	{
		private readonly string namePrefix;

		internal DirectorySuggestionEnumerator(string directory, string namePrefix)
			: base(directory, DirectorySuggestionEnumerationOptions) => this.namePrefix = namePrefix;

		protected override bool ShouldRecurseIntoEntry(ref FileSystemEntry entry) => false;

		protected override bool ShouldIncludeEntry(ref FileSystemEntry entry) =>
			entry.IsDirectory && entry.FileName.StartsWith(namePrefix.AsSpan(), StringComparison.OrdinalIgnoreCase);

		protected override string TransformEntry(ref FileSystemEntry entry) => entry.ToFullPath();
	}

	#endregion

}

/// <summary>
/// A ListView for the shared file path rules template that supports proper nested scrolling
/// inside a page-level ScrollView. This is basically like <see cref="ListViewV3"/> but without the global registry key.
/// </summary>
internal sealed partial class FilePathWildcardRulesListView : ListView
{
	// Reference to the parent ScrollView external to this ListView.
	private ScrollView? parentScrollView;

	// Reference to the inner ScrollViewer that WinUI creates around the ListView.
	private ScrollViewer? innerScrollViewer;

	internal FilePathWildcardRulesListView()
	{
		ScrollViewer.SetVerticalScrollBarVisibility(this, ScrollBarVisibility.Visible);
		ShowsScrollingPlaceholders = true;

		// Subscribe to the lifecycle and pointer events
		Loaded += OnLoaded;
		Unloaded += OnUnloaded;
		PointerEntered += OnPointerEntered;
		PointerExited += OnPointerExited;
		PointerPressed += OnPointerPressed;
	}

	// Delay execution until the visual tree is ready.
	private void OnLoaded(object? sender, RoutedEventArgs e) => _ = DispatcherQueue.TryEnqueue(() => innerScrollViewer = ListViewHelper.FindScrollViewer(this));

	private void OnUnloaded(object? sender, RoutedEventArgs e)
	{
		// Ensure the outer ScrollView is re-enabled even if the pointer is inside during unload.
		_ = (parentScrollView?.VerticalScrollMode = ScrollingScrollMode.Enabled);
		parentScrollView = null;
		innerScrollViewer = null;
	}

	// Since a ScrollView surrounds the page, it captures mouse wheel input.
	// Disable its vertical scrolling while the mouse is inside this ListView.
	private void OnPointerEntered(object sender, PointerRoutedEventArgs e)
	{
		if (e.Pointer.PointerDeviceType == PointerDeviceType.Mouse)
		{
			parentScrollView ??= ListViewV3.FindParentScrollView(this, innerScrollViewer);
			_ = (parentScrollView?.VerticalScrollMode = ScrollingScrollMode.Disabled);
		}
	}

	private void OnPointerExited(object sender, PointerRoutedEventArgs e) =>
		_ = (parentScrollView?.VerticalScrollMode = ScrollingScrollMode.Enabled);

	private void OnPointerPressed(object sender, PointerRoutedEventArgs e)
	{
		// Always enable vertical scrolling for non-mouse input.
		if (e.Pointer.PointerDeviceType != PointerDeviceType.Mouse && parentScrollView is not null)
		{
			parentScrollView.VerticalScrollMode = ScrollingScrollMode.Enabled;
		}
	}
}
