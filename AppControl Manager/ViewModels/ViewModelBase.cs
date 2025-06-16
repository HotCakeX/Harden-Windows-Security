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
using System.Collections.Frozen;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using AppControlManager.IntelGathering;
using AppControlManager.Others;
using CommunityToolkit.WinUI;
using Microsoft.UI.Dispatching;
using Windows.ApplicationModel.UserActivities;

namespace AppControlManager.ViewModels;

/// <summary>
/// All of the ViewModel classes must inherit from this class
/// </summary>
internal abstract class ViewModelBase : INotifyPropertyChanged
{
	public event PropertyChangedEventHandler? PropertyChanged;

	// Expose the dispatcher queue so that derived classes can marshal
	// calls to the UI thread when needed.
	protected readonly DispatcherQueue Dispatcher = DispatcherQueue.GetForCurrentThread();

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

	// Dictionaries used for quick conversion and parsing of ScanLevels.
	internal static readonly FrozenDictionary<string, ScanLevels> StringToScanLevel = new Dictionary<string, ScanLevels>
	{
		{ "File Publisher", ScanLevels.FilePublisher },
		{ "Publisher", ScanLevels.Publisher },
		{ "Hash", ScanLevels.Hash },
		{ "File Path", ScanLevels.FilePath },
		{ "WildCard Folder Path", ScanLevels.WildCardFolderPath },
		{ "PFN", ScanLevels.PFN },
		{ "Custom File Rule Pattern", ScanLevels.CustomFileRulePattern }
	}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);


	internal static readonly FrozenDictionary<ScanLevels, string> ScanLevelToString = new Dictionary<ScanLevels, string>
	{
		{ ScanLevels.FilePublisher, "File Publisher" },
		{ ScanLevels.Publisher, "Publisher" },
		{ ScanLevels.Hash, "Hash" },
		{ ScanLevels.FilePath, "File Path" },
		{ ScanLevels.WildCardFolderPath, "WildCard Folder Path" },
		{ ScanLevels.PFN, "PFN" },
		{ ScanLevels.CustomFileRulePattern, "Custom File Rule Pattern" }
	}.ToFrozenDictionary();

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
}
