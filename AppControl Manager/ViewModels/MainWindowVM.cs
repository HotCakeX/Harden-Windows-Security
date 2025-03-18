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

using System.ComponentModel;
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
	// Backing field for InfoBadgeOpacity, which controls the visibility of the InfoBadge in the UI.
	// https://learn.microsoft.com/en-us/windows/apps/design/controls/info-badge
	private double _infoBadgeOpacity;

	// Instance of the AppUpdate service to handle update checks.
	private readonly AppUpdate _updateService;

	// DispatcherQueue provides access to the UI thread dispatcher, allowing for UI updates from background threads.
	private readonly DispatcherQueue _dispatcher;

	// Event triggered when a bound property value changes, allowing the UI to reactively update.
	public event PropertyChangedEventHandler? PropertyChanged;

	/// <summary>
	/// Opacity level of the InfoBadge icon in the UI. When set to 1, the badge is visible.
	/// When set to 0, the badge is hidden.
	/// </summary>
	internal double InfoBadgeOpacity
	{
		get => _infoBadgeOpacity;
		set
		{
			// Only update if the value has changed to avoid unnecessary notifications
			if (_infoBadgeOpacity != value)
			{
				_infoBadgeOpacity = value;

				// Notify UI of property change to update the binding
				PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(InfoBadgeOpacity)));
			}
		}
	}

	/// <summary>
	/// Constructor initializes the ViewModel with the AppUpdate service instance
	/// and subscribes to the update notification event.
	/// </summary>
	/// <param name="updateService">Instance of AppUpdate service used for update checks.</param>
	internal MainWindowVM(AppUpdate updateService)
	{
		_updateService = updateService; // Store AppUpdate service instance

		// Retrieve the dispatcher queue associated with the main (UI) thread
		// for safe UI updates from event handlers or background threads.
		// Because the update check always happens on another thread via Task.Run.
		_dispatcher = DispatcherQueue.GetForCurrentThread();

		// Subscribe to the UpdateAvailable event to handle updates to the InfoBadge visibility
		_updateService.UpdateAvailable += OnUpdateAvailable!;
	}

	/// <summary>
	/// Event handler triggered when the UpdateAvailable event is raised, indicating an update is available.
	/// Updates InfoBadgeOpacity to show the InfoBadge in the UI if an update is available.
	/// </summary>
	/// <param name="sender">Sender of the event, in this case, AppUpdate instance.</param>
	/// <param name="e">Boolean indicating whether an update is available.</param>
	private void OnUpdateAvailable(object sender, UpdateAvailableEventArgs e)
	{
		// Marshal back to the UI thread using the dispatcher to safely update UI-bound properties
		_ = _dispatcher.TryEnqueue(() =>
		{
			// Set InfoBadgeOpacity based on update availability: 1 to show, 0 to hide
			InfoBadgeOpacity = e.IsUpdateAvailable ? 1 : 0;
		});
	}

}
