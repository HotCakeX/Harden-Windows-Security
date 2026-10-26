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

using System.Globalization;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using WinRT;

namespace HardenSystemSecurity.CustomUIElements.WindowsTopBar;

internal sealed partial class TopBar
{
	private Flyout? _globalSearchSettingsFlyout;
	private CancellationTokenSource? _globalSearchSettingsCancellation;

	[DynamicWindowsRuntimeCast(typeof(Brush))]
	private static Border CreateGlobalSearchSettingsSeparator() => new()
	{
		Height = 1.0,
		HorizontalAlignment = HorizontalAlignment.Stretch,
		Background = (Brush)Application.Current.Resources["DividerStrokeColorDefaultBrush"]
	};

	private static StackPanel CreateGlobalSearchSettingsLabel(string glyph, string text) => new()
	{
		Orientation = Orientation.Horizontal,
		Spacing = 8.0,
		Children =
		{
			new FontIcon { Glyph = glyph, FontSize = 16.0, VerticalAlignment = VerticalAlignment.Center },
			new TextBlock { Text = text, VerticalAlignment = VerticalAlignment.Center }
		}
	};

	// Shows the size of the saved Global Search indexes and lets the user delete the unused ones, choose whether the
	// drives connected while the service runs are indexed, and index the drives that have no index now.
	private void OnGlobalSearchSettingsClick()
	{
		if (_isClosed || _activeView != TopBarView.Search || _globalSearchSettingsFlyout is not null) return;
		TextBlock sizeText = new() { Text = "Saved indexes size: not calculated.", TextWrapping = TextWrapping.Wrap };
		Button sizeButton = new() { Content = CreateGlobalSearchSettingsLabel("\uE8EF", "Calculate size") };
		Button deleteButton = new() { Content = CreateGlobalSearchSettingsLabel("\uEA99", "Delete unused indexes") };
		ToggleSwitch indexConnectedDrives = new()
		{
			Header = CreateGlobalSearchSettingsLabel("\uE88E", "Index drives when they are connected"),
			IsOn = Atlas.Settings.WindowsTopBarSearchIndexConnectedDrives
		};
		Button detectButton = new() { Content = CreateGlobalSearchSettingsLabel("\uEBDE", "Detect and index drives") };
		TextBlock status = new() { TextWrapping = TextWrapping.Wrap };
		StackPanel content = new()
		{
			Width = Math.Max(280.0, Math.Min(420.0, GetDisplayWidthDips() - 64.0)),
			Spacing = 12.0,
			Children =
			{
				new TextBlock { Text = "Global Search Settings", FontSize = 20.0, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold },
				sizeText,
				sizeButton,
				CreateGlobalSearchSettingsSeparator(),
				new TextBlock
				{
					Text = "Deletes the saved indexes of the drives that are not indexed now, such as disconnected drives, instead of waiting for them to be deleted after 10 days.",
					TextWrapping = TextWrapping.Wrap
				},
				deleteButton,
				CreateGlobalSearchSettingsSeparator(),
				indexConnectedDrives,
				CreateGlobalSearchSettingsSeparator(),
				new TextBlock
				{
					Text = "Indexes the drives that are connected or unlocked after the indexes were built, such as a BitLocker drive unlocked after it was connected.",
					TextWrapping = TextWrapping.Wrap
				},
				detectButton,
				status
			}
		};
		Flyout flyout = new()
		{
			ShouldConstrainToRootBounds = false,
			Content = content
		};
		_globalSearchSettingsFlyout = flyout;
		TrackFlyout(flyout);

		// Sends one request at a time and shows its result, with every button disabled meanwhile.
		async Task RunAsync<T>(byte operation, string progress, Func<BinaryReader, T> read, Action<T> show)
		{
			if (_globalSearchSettingsCancellation is not null) return;
			using CancellationTokenSource cancellation = new(TimeSpan.FromMinutes(5));
			_globalSearchSettingsCancellation = cancellation;
			sizeButton.IsEnabled = deleteButton.IsEnabled = detectButton.IsEnabled = false;
			status.Text = progress;
			try
			{
				T result = await Task.Run(() => SendGlobalSearchRequestAsync(operation, 0, read, cancellation.Token));
				cancellation.Token.ThrowIfCancellationRequested();
				if (_isClosed || !ReferenceEquals(_globalSearchSettingsFlyout, flyout)) return;
				status.Text = string.Empty;
				show(result);
			}
			catch (OperationCanceledException)
			{
				if (!_isClosed && ReferenceEquals(_globalSearchSettingsFlyout, flyout)) status.Text = "The request was canceled or timed out.";
			}
			catch (Exception exception)
			{
				Logger.Write(exception);
				if (!_isClosed && ReferenceEquals(_globalSearchSettingsFlyout, flyout)) status.Text = exception.Message;
			}
			finally
			{
				if (ReferenceEquals(_globalSearchSettingsCancellation, cancellation)) _globalSearchSettingsCancellation = null;
				if (!_isClosed && ReferenceEquals(_globalSearchSettingsFlyout, flyout))
					sizeButton.IsEnabled = deleteButton.IsEnabled = detectButton.IsEnabled = true;
			}
		}

		void ShowSize(long size) => sizeText.Text = "Saved indexes size: " + TopBarSearchClient.FormatFileSize(size);

		sizeButton.Click += async (_, _) => await RunAsync(Atlas.GlobalSearchSavedIndexSizeRequest, "Calculating the size...", ReadSize, ShowSize);
		deleteButton.Click += async (_, _) => await RunAsync(Atlas.GlobalSearchDeleteUnusedIndexesRequest, "Deleting the unused indexes...", ReadSize, ShowSize);
		detectButton.Click += async (_, _) => await RunAsync(Atlas.GlobalSearchIndexNewDrivesRequest, "Detecting and indexing drives...",
			static reader => (Indexed: reader.ReadInt32(), Total: reader.ReadInt32()),
			result => status.Text = "Drives indexed now: " + result.Indexed.ToString("N0", CultureInfo.CurrentCulture) +
				". Drives indexed in total: " + result.Total.ToString("N0", CultureInfo.CurrentCulture) + ".");
		indexConnectedDrives.Toggled += (_, _) =>
		{
			if (_isClosed) return;
			Atlas.Settings.WindowsTopBarSearchIndexConnectedDrives = indexConnectedDrives.IsOn;
			// The client sends the setting to the service now, and again after every connection.
			(_searchClient ??= new TopBarSearchClient(DispatcherQueue, OnSearchStatus, OnSearchResults)).SetIndexConnectedDrives(indexConnectedDrives.IsOn);
		};
		flyout.Closed += (_, _) =>
		{
			if (ReferenceEquals(_globalSearchSettingsFlyout, flyout))
			{
				_globalSearchSettingsCancellation?.Cancel();
				_globalSearchSettingsFlyout = null;
			}
			flyout.Content = null;
			flyout.Opened -= OnFlyoutOpened;
			flyout.Closed -= OnFlyoutClosed;
			if (!_isClosed && !_isPinned && _openFlyoutCount == 0 && !IsCursorOverBar()) _retractionTimer.Start();
		};
		flyout.ShowAt(GlobalSearchSettingsButton);
	}

	private static long ReadSize(BinaryReader reader)
	{
		long size = reader.ReadInt64();
		return size >= 0 ? size : throw new InvalidDataException("Invalid saved indexes size.");
	}
}
