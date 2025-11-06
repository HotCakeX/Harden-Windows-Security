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
using System.ComponentModel;
using System.Runtime.CompilerServices;
using Windows.Media.Core;
using Windows.Media.Playback;
using System.Threading.Tasks;
using Windows.System;
using Windows.ApplicationModel.UserActivities;
using CommunityToolkit.WinUI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;

#if HARDEN_SYSTEM_SECURITY
using HardenSystemSecurity.AppSettings;
using HardenSystemSecurity;
#endif

#if APP_CONTROL_MANAGER
using Microsoft.UI.Xaml.Controls;
using System.Diagnostics;
using AppControlManager.IntelGathering;
using System.Collections.ObjectModel;
using AppControlManager.Others;
#endif

namespace AppControlManager.ViewModels;

/// <summary>
/// All of the ViewModel classes must inherit from this class
/// </summary>
internal abstract class ViewModelBase : INotifyPropertyChanged
{
	public event PropertyChangedEventHandler? PropertyChanged;

	// Expose the dispatcher queue so that derived classes can marshal
	// calls to the UI thread when needed.

	// This won't always be available, especially when a type inheriting from this is being instantiated before the app is fully initialized,
	//protected readonly Microsoft.UI.Dispatching.DispatcherQueue Dispatcher = Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread();

	// Get it from the App class.
	protected Microsoft.UI.Dispatching.DispatcherQueue Dispatcher => App.AppDispatcher;

#if APP_CONTROL_MANAGER
	/// <summary>
	/// An instance property reference to the App settings that pages can x:Bind to.
	/// </summary>
	internal AppSettings.Main AppSettings => App.Settings;
#endif

#if HARDEN_SYSTEM_SECURITY
	/// <summary>
	/// An instance property reference to the App settings that pages can x:Bind to.
	/// </summary>
	internal Main AppSettings => App.Settings;
#endif

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

		if (App.AppDispatcher.HasThreadAccess)
		{
			OnPropertyChanged(propertyName);
		}
		else
		{
			_ = App.AppDispatcher.TryEnqueue(() => OnPropertyChanged(propertyName));
		}

		return true;
	}

	/// <summary>
	/// Only for properties that are nullable texts.
	/// This plays type writing audio if Sound is enabled in the app settings.
	/// </summary>
	/// <param name="field"></param>
	/// <param name="newValue"></param>
	/// <param name="propertyName"></param>
	/// <returns></returns>
	protected bool SPT(ref string? field, string? newValue, [CallerMemberName] string? propertyName = null)
	{
		if (string.Equals(field, newValue, StringComparison.Ordinal))
			return false;

		field = newValue;

		if (App.AppDispatcher.HasThreadAccess)
		{
			OnPropertyChanged(propertyName);
		}
		else
		{
			_ = App.AppDispatcher.TryEnqueue(() => OnPropertyChanged(propertyName));
		}

		if (App.Settings.SoundSetting && !string.IsNullOrEmpty(field))
		{
			TypeWriterMediaPlayer.Position = TypeWriterAudioStartTime;
			TypeWriterMediaPlayer.Play();
		}

		return true;
	}

	/// <summary>
	/// Raises the PropertyChanged event.
	/// </summary>
	/// <param name="propertyName">The name of the property that changed.</param>
	protected void OnPropertyChanged(string? propertyName) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

#if APP_CONTROL_MANAGER
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

#endif

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
	internal enum LaunchProtocolActions : uint
	{
		PolicyEditor = 0,
		FileSignature = 1,
		FileHashes = 2,
		DeployRMMAuditPolicy = 3,
		DeployRMMBlockPolicy = 4
	}


	/// <summary>
	/// Handles different types of exceptions, used mainly by methods that deal with cancellable workflows.
	/// It can detect OperationCanceledException at any nesting level within any exception hierarchy.
	/// </summary>
	/// <param name="exception">The exception to analyze</param>
	/// <param name="errorsOccurred">Reference to error flag</param>
	/// <param name="wasCancelled">Reference to cancellation flag</param>
	/// <param name="infoBarSettings">InfoBar for displaying messages</param>
	/// <param name="errorMessage">Optional error message</param>
	internal static void HandleExceptions(
		Exception exception,
		ref bool errorsOccurred,
		ref bool wasCancelled,
		InfoBarSettings infoBarSettings,
		string? errorMessage = null)
	{
		// Find OperationCanceledException at any nesting level
		bool containsCancellation = ContainsOperationCanceledException(exception);

		if (containsCancellation)
		{
			wasCancelled = true;
			// Don't log this as an error, it's expected behavior
		}
		else
		{
			errorsOccurred = true;
			infoBarSettings.WriteError(exception, errorMessage);
		}
	}

	/// <summary>
	/// Recursively searches for OperationCanceledException in any exception hierarchy.
	/// Handles deeply nested exceptions including AggregateExceptions, regular InnerException chains,
	/// and any combination thereof.
	/// </summary>
	/// <param name="exception">The exception to search</param>
	/// <returns>True if OperationCanceledException is found at any nesting level</returns>
	private static bool ContainsOperationCanceledException(Exception exception)
	{
		// A HashSet to prevent infinite loops in case of circular references
		HashSet<Exception> visited = new(ReferenceEqualityComparer.Instance);
		return ContainsOperationCanceledExceptionRecursive(exception, visited);
	}

	/// <summary>
	/// Recursive helper method to search for OperationCanceledException in any exception hierarchy.
	/// This method comprehensively searches through:
	/// - Direct exception type checking
	/// - AggregateException.InnerExceptions collections
	/// - Regular Exception.InnerException chains
	/// - Any combination and nesting of the above
	/// </summary>
	/// <param name="exception">Current exception to examine</param>
	/// <param name="visited">Set of already visited exceptions to prevent cycles</param>
	/// <returns>True if OperationCanceledException is found</returns>
	private static bool ContainsOperationCanceledExceptionRecursive(Exception exception, HashSet<Exception> visited)
	{
		// Prevent infinite loops from circular exception references
		if (!visited.Add(exception))
		{
			return false;
		}

		// Check if current exception is OperationCanceledException
		if (exception is OperationCanceledException)
		{
			return true;
		}

		// Handle AggregateException's inner exceptions collection
		if (exception is AggregateException aggregateEx)
		{
			foreach (Exception innerEx in aggregateEx.InnerExceptions)
			{
				if (ContainsOperationCanceledExceptionRecursive(innerEx, visited))
				{
					return true;
				}
			}
		}

		// Handle regular InnerException chain (applies to ALL exception types)
		// This is crucial for detecting nested exceptions in non-AggregateException hierarchies
		if (exception.InnerException != null)
		{
			if (ContainsOperationCanceledExceptionRecursive(exception.InnerException, visited))
			{
				return true;
			}
		}

		return false;
	}


	/// <summary>
	/// Determines if an exception hierarchy contains an OperationCanceledException at any nesting level.
	/// This method can handle deeply nested exceptions including AggregateExceptions and regular InnerException chains.
	/// Returns true if cancellation was detected, false otherwise.
	/// </summary>
	/// <param name="exception">The exception to analyze</param>
	/// <returns>True if OperationCanceledException is found at any nesting level, false otherwise</returns>
	internal static bool IsCancellationException(Exception exception)
	{
		HashSet<Exception> visited = new(ReferenceEqualityComparer.Instance);
		return ContainsOperationCanceledExceptionRecursive(exception, visited);
	}

#if APP_CONTROL_MANAGER
	/// <summary>
	/// Opens the directory where a file is located in File Explorer.
	/// </summary>
	/// <param name="ListViewKey"></param>
	internal static void OpenInFileExplorer(ListViewHelper.ListViewsRegistry ListViewKey)
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewKey);
		OpenInFileExplorerCore(lv);
	}

	internal static void OpenInFileExplorer(ListView? lv) => OpenInFileExplorerCore(lv);

	private static void OpenInFileExplorerCore(ListView? lv)
	{
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
			ProcessStartInfo processInfo = new()
			{
				FileName = "explorer.exe",
				Arguments = $"/select,\"{fileToOpen}\"", // Scroll to the file in File Explorer and highlight it.
				Verb = "runas",
				UseShellExecute = true
			};

			_ = Process.Start(processInfo);
		}
	}
#endif

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
			Logger.Write(ex);
		}
	}

	private static readonly MediaPlayer TypeWriterMediaPlayer = new()
	{
		Source = MediaSource.CreateFromUri(new Uri("ms-appx:///Assets/Audio/TypeWriter.wav")),
		// https://learn.microsoft.com/uwp/api/windows.media.systemmediatransportcontrols
		CommandManager = { IsEnabled = false } // Disable System Media Transport Controls (SMTC) to prevent the audio from being displayed by the OS.
	};

	private static readonly TimeSpan TypeWriterAudioStartTime = TimeSpan.FromMilliseconds(167);

	internal static void EmitTypingSound()
	{
		if (!App.Settings.SoundSetting) return;

		TypeWriterMediaPlayer.Position = TypeWriterAudioStartTime;
		TypeWriterMediaPlayer.Play();
	}

	/// <summary>
	/// The current user's profile directory path.
	/// </summary>
	internal static readonly string UserProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

#if APP_CONTROL_MANAGER

	// Create PropertyFilterItem collections only once lazily.
	private static readonly Lazy<ObservableCollection<ListViewHelper.PropertyFilterItem>> _lazyItems
		= new(valueFactory: ListViewHelper.CreatePropertyFilterItems, isThreadSafe: true);

	internal ObservableCollection<ListViewHelper.PropertyFilterItem> PropertyFilterItems => _lazyItems.Value;

#endif

	/// <summary>
	/// Traverses the visual tree breadth-first and disposes any descendant control that:
	///  - Implements IExplicitDisposalOptIn (meaning it skipped disposal on Unloaded)
	///  - Implements IDisposable
	/// This keeps the logic generic (works for AnimatedCancellableButton, LinkButtonV2, StatusIndicatorV2, etc.).
	/// </summary>
	internal static void DisposeExplicitOptInDescendants(FrameworkElement root)
	{
		if (root == null)
		{
			return;
		}

		Queue<DependencyObject> queue = new();
		queue.Enqueue(root);

		while (queue.Count > 0)
		{
			DependencyObject current = queue.Dequeue();
			int childCount = VisualTreeHelper.GetChildrenCount(current);
			for (int i = 0; i < childCount; i++)
			{
				DependencyObject child = VisualTreeHelper.GetChild(current, i);

				// If it opted in and is disposable, dispose it.
				if (child is IExplicitDisposalOptIn explicitOptIn &&
					child is IDisposable disposable &&
					explicitOptIn.DisposeOnlyOnExplicitCall)
				{
					try
					{
						disposable.Dispose();
					}
					catch
					{
						// Swallow: disposal errors should not block the rest.
					}
				}

				queue.Enqueue(child);
			}
		}
	}

}

/// <summary>
/// Classes that already inherit from something else can implement this interface for easy access to the SP method.
/// </summary>
internal interface INPCImplant : INotifyPropertyChanged
{
	// Must raise PropertyChanged for the given property name with this instance as sender.
	void RaisePropertyChanged(string? propertyName);
}

internal static class PropertyChangeExtensions
{
	/// <summary>
	/// Extension Method.
	/// Sets the field to <paramref name="newValue"/> if it differs from its current contents,
	/// raises PropertyChanged, and returns true if a change occurred.
	/// This also prevents infinite loops where a property raises OnPropertyChanged which could trigger an update in the UI,
	/// and the UI might call set again, leading to an infinite loop.
	/// </summary>
	/// <param name="field">The existing value.</param>
	/// <param name="newValue">The new value.</param>
	/// <param name="propertyName"></param>
	internal static bool SP<T>(this INPCImplant host, ref T field, T newValue, [CallerMemberName] string? propertyName = null)
	{
		if (EqualityComparer<T>.Default.Equals(field, newValue))
			return false;

		field = newValue;

		if (App.AppDispatcher.HasThreadAccess)
		{
			host.RaisePropertyChanged(propertyName);
		}
		else
		{
			_ = App.AppDispatcher.TryEnqueue(() => host.RaisePropertyChanged(propertyName));
		}

		return true;
	}
}
