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
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using AppControlManager.IntelGathering;
using AppControlManager.Others;
using CommunityToolkit.WinUI;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.UserActivities;
using Windows.System;

namespace AppControlManager.ViewModels;

/// <summary>
/// All of the ViewModel classes must inherit from this class
/// </summary>
internal abstract class ViewModelBase : INotifyPropertyChanged
{
	public event PropertyChangedEventHandler? PropertyChanged;

	// Expose the dispatcher queue so that derived classes can marshal
	// calls to the UI thread when needed.
	protected readonly Microsoft.UI.Dispatching.DispatcherQueue Dispatcher = Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread();

	/// <summary>
	/// An instance property reference to the App settings that pages can x:Bind to.
	/// </summary>
	internal AppSettings.Main AppSettings => App.Settings;

	/// <summary>
	/// An instance property so pages can bind to.
	/// </summary>
	internal bool IsElevated => App.IsElevated;

	/// <summary>
	/// Same as IsElevated but in reverse.
	/// </summary>
	internal bool IsNotElevated => !App.IsElevated;

	/// <summary>
	/// Sets the field to <paramref name="newValue"/> if it differs from its current contents,
	/// raises PropertyChanged, and returns true if a change occurred.
	/// This also prevents infinite loops where a property raises OnPropertyChanged which could trigger an update in the UI,
	/// and the UI might call set again, leading to an infinite loop.
	/// </summary>
	/// <param name="field">The existing value.</param>
	/// <param name="newValue">The new value.</param>
	/// <param name="propertyName"></param>
	protected bool SP<T>(ref T field, T newValue, [CallerMemberName] string? propertyName = null)
	{
		if (EqualityComparer<T>.Default.Equals(field, newValue))
			return false;

		field = newValue;
		OnPropertyChanged(propertyName);
		return true;
	}

	/// <summary>
	/// Raises the PropertyChanged event.
	/// </summary>
	/// <param name="propertyName">The name of the property that changed.</param>
	protected void OnPropertyChanged(string? propertyName)
	{
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	}

	internal readonly List<ScanLevelsComboBoxType> ScanLevelsSource =
	[
		new ScanLevelsComboBoxType("WHQL File Publisher", ScanLevels.WHQLFilePublisher, 5),
		new ScanLevelsComboBoxType("File Publisher", ScanLevels.FilePublisher, 4),
		new ScanLevelsComboBoxType("Publisher", ScanLevels.Publisher, 3),
		new ScanLevelsComboBoxType("Hash", ScanLevels.Hash, 5),
		new ScanLevelsComboBoxType("File Path", ScanLevels.FilePath, 2),
		new ScanLevelsComboBoxType("Wildcard Folder Path", ScanLevels.WildCardFolderPath, 1)
	];

	internal readonly List<ScanLevelsComboBoxType> ScanLevelsSourceForLogs =
	[
		new ScanLevelsComboBoxType("WHQL File Publisher", ScanLevels.WHQLFilePublisher, 5),
		new ScanLevelsComboBoxType("File Publisher", ScanLevels.FilePublisher, 4),
		new ScanLevelsComboBoxType("Publisher", ScanLevels.Publisher, 3),
		new ScanLevelsComboBoxType("Hash", ScanLevels.Hash, 5)
	];

	/// <summary>
	/// The default scan level used by the ItemsSources of ComboBoxes.
	/// </summary>
	internal static readonly ScanLevelsComboBoxType DefaultScanLevel = new("WHQL File Publisher", ScanLevels.WHQLFilePublisher, 5);

	/// <summary>
	/// User Activity tracking field
	/// </summary>
	private UserActivitySession? _previousSession;

	/// <summary>
	/// Publishes or updates user activity for the current page.
	/// https://learn.microsoft.com/windows/ai/recall/recall-relaunch
	/// </summary>
	/// <param name="action">The type of action being performed</param>
	/// <param name="filePath">The file path associated with the activity</param>
	/// <param name="displayText">The display text for the activity</param>
	internal async Task PublishUserActivityAsync(LaunchProtocolActions action, string filePath, string displayText)
	{
		// Only publish if allowed
		if (!App.Settings.PublishUserActivityInTheOS)
			return;

		try
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				_previousSession?.Dispose();
			});

			// Create the activity
			string activityId = $"AppControlManager-{action}";
			UserActivity activity = await UserActivityChannel.GetDefault().GetOrCreateUserActivityAsync(activityId);

			// Set properties
			activity.VisualElements.DisplayText = displayText;
			activity.ActivationUri = new Uri($"appcontrol-manager:--action={action}--file={filePath}");

			// Save the activity
			await activity.SaveAsync();

			TaskCompletionSource<UserActivitySession> tcs = new();

			bool enqueued = Dispatcher.TryEnqueue(() =>
			{
				try
				{
					UserActivitySession session = activity.CreateSession();
					tcs.SetResult(session);
				}
				catch (Exception ex)
				{
					tcs.SetException(ex);
				}
			});

			if (!enqueued)
			{
				throw new InvalidOperationException("Failed to enqueue CreateSession operation on UI thread");
			}

			// Wait for the UI thread operation to complete and store the result
			_previousSession = await tcs.Task;
		}
		catch (Exception ex)
		{
			Logger.Write($"Failed to publish user activity: {ex.Message}");
		}
	}

	/// <summary>
	/// All of the activations used and detected by the app, either via Protocol, Launch arguments and so on.
	/// </summary>
	internal enum LaunchProtocolActions
	{
		PolicyEditor,
		FileSignature,
		FileHashes
	}


	/// <summary>
	/// Handles different types of exceptions, used mainly by methods that deal with cancellable workflows.
	/// </summary>
	/// <param name="exception"></param>
	/// <param name="errorsOccurred"></param>
	/// <param name="wasCancelled"></param>
	/// <param name="infoBarSettings"></param>
	/// <param name="errorMessage"></param>
	internal static void HandleExceptions(
	   Exception exception,
	   ref bool errorsOccurred,
	   ref bool wasCancelled,
	   InfoBarSettings infoBarSettings,
	   string? errorMessage = null)
	{

		// Check if it's an OperationCanceledException directly
		if (exception is OperationCanceledException)
		{
			wasCancelled = true;
			// Don't log this as an error, it's expected behavior
			return;
		}

		// Check if it's an AggregateException
		else if (exception is AggregateException aggregateEx)
		{

			// Check if any of the inner exceptions is an OperationCanceledException
			bool containsCancellation = false;
			aggregateEx.Handle(innerEx =>
			{
				if (innerEx is OperationCanceledException)
				{
					containsCancellation = true;
					return true; // Mark this exception as handled
				}
				return false; // Don't handle other exceptions
			});

			if (containsCancellation)
			{
				wasCancelled = true;
				// Don't log this as an error, it's expected behavior
			}
			else
			{
				errorsOccurred = true;
				infoBarSettings.WriteError(aggregateEx);
			}
		}
		else
		{
			// Handle any other exception type
			errorsOccurred = true;

			infoBarSettings.WriteError(exception, errorMessage);
		}
	}

	/// <summary>
	/// Opens the directory where a file is located in File Explorer.
	/// </summary>
	/// <param name="ListViewKey"></param>
	internal static void OpenInFileExplorer(ListViewHelper.ListViewsRegistry ListViewKey)
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewKey);
		if (lv is null) return;

		string? fileToOpen = null;

		FileIdentity? attempt1 = lv.SelectedItem as FileIdentity;

		if (attempt1 is not null)
		{
			fileToOpen = attempt1.FilePath;
		}
		else
		{
			IList<object> attempt2 = lv.SelectedItems;

			if (attempt2.Count > 0)
			{
				FileIdentity? attempt3 = attempt2[0] as FileIdentity;

				if (attempt3 is not null)
				{
					fileToOpen = attempt3.FilePath;
				}
			}
		}

		if (fileToOpen is not null)
		{
			string? Dir = Path.GetDirectoryName(fileToOpen);

			if (Dir is not null)
			{
				ProcessStartInfo processInfo = new()
				{
					FileName = "explorer.exe",
					Arguments = Dir,
					Verb = "runas",
					UseShellExecute = true
				};

				_ = Process.Start(processInfo);
			}
		}
	}

	/// <summary>
	/// Opens a file in the default file handler in the OS.
	/// </summary>
	/// <param name="filePath"></param>
	internal static async Task OpenInDefaultFileHandler(string? filePath)
	{
		try
		{
			if (filePath is not null)
				_ = await Launcher.LaunchUriAsync(new Uri(filePath));
		}
		catch (Exception ex)
		{
			Logger.Write(ErrorWriter.FormatException(ex));
		}
	}
}
