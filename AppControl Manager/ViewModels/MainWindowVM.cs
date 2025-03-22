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
using System.Runtime.CompilerServices;
using AppControlManager.Others;
using Microsoft.UI.Dispatching;

namespace AppControlManager.ViewModels;

/// <summary>
/// ViewModel for the MainWindow, responsible for managing UI properties and
/// handling updates to the InfoBadge visibility when an application update is available.
/// Implements INotifyPropertyChanged to support data binding to UI elements.
/// </summary>
internal sealed partial class MainWindowVM : INotifyPropertyChanged
{
	// DispatcherQueue provides access to the UI thread dispatcher, allowing for UI updates from background threads.
	private readonly DispatcherQueue Dispatch;

	// Event triggered when a bound property value changes, allowing the UI to reactively update.
	public event PropertyChangedEventHandler? PropertyChanged;

	/// <summary>
	/// Backing field for InfoBadgeOpacity, which controls the visibility of the InfoBadge in the UI.
	/// https://learn.microsoft.com/en-us/windows/apps/design/controls/info-badge
	/// Opacity level of the InfoBadge icon in the UI. When set to 1, the badge is visible.
	/// When set to 0, the badge is hidden.
	/// </summary>
	private double _infoBadgeOpacity;
	internal double InfoBadgeOpacity
	{
		get => _infoBadgeOpacity;
		set => SetProperty(_infoBadgeOpacity, value, newValue => _infoBadgeOpacity = newValue);
	}

	/// <summary>
	/// Constructor initializes the ViewModel and subscribes to the update notification event.
	/// </summary>
	public MainWindowVM()
	{
		Dispatch = DispatcherQueue.GetForCurrentThread();

		// Subscribe to the UpdateAvailable event to handle updates to the InfoBadge visibility
		AppUpdate.UpdateAvailable += OnUpdateAvailable!;
	}

	/// <summary>
	/// Event handler triggered when the UpdateAvailable event is raised, indicating an update is available.
	/// Updates InfoBadgeOpacity to show the InfoBadge in the UI if an update is available.
	/// </summary>
	/// <param name="sender">Sender of the event, in this case, AppUpdate class.</param>
	/// <param name="e">Boolean indicating whether an update is available.</param>
	private void OnUpdateAvailable(object sender, UpdateAvailableEventArgs e)
	{
		// Marshal back to the UI thread using the dispatcher to safely update UI-bound properties
		_ = Dispatch.TryEnqueue(() =>
		{
			// Set InfoBadgeOpacity based on update availability: 1 to show, 0 to hide
			InfoBadgeOpacity = e.IsUpdateAvailable ? 1 : 0;
		});
	}



	/// <summary>
	/// The state of the OpenConfigDirectoryButton button which is on the Sidebar
	/// </summary>
	private bool _OpenConfigDirectoryButtonState = App.IsElevated;
	internal bool OpenConfigDirectoryButtonState
	{
		get => _OpenConfigDirectoryButtonState;
		set => SetProperty(_OpenConfigDirectoryButtonState, value, newValue => _OpenConfigDirectoryButtonState = newValue);
	}


	/// <summary>
	/// Event handler for the Sidebar button to open the user config directory
	/// </summary>
	internal void OpenConfigDirectoryButton_Click()
	{
		_ = Process.Start(new ProcessStartInfo
		{
			FileName = GlobalVars.UserConfigDir,
			UseShellExecute = true
		});
	}


	/// <summary>
	/// Sets the property and raises the PropertyChanged event if the value has changed.
	/// This also prevents infinite loops where a property raises OnPropertyChanged which could trigger an update in the UI, and the UI might call set again, leading to an infinite loop.
	/// </summary>
	/// <typeparam name="T"></typeparam>
	/// <param name="currentValue"></param>
	/// <param name="newValue"></param>
	/// <param name="setter"></param>
	/// <param name="propertyName"></param>
	/// <returns></returns>
	private bool SetProperty<T>(T currentValue, T newValue, Action<T> setter, [CallerMemberName] string? propertyName = null)
	{
		if (EqualityComparer<T>.Default.Equals(currentValue, newValue))
			return false;
		setter(newValue);
		OnPropertyChanged(propertyName);
		return true;
	}

	private void OnPropertyChanged(string? propertyName)
	{
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	}
}
