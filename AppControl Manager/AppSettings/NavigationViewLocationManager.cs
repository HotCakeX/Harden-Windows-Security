using System;

namespace AppControlManager.AppSettings;

// Custom EventArgs class for navigation view location changes
internal sealed class NavigationViewLocationChangedEventArgs(string newLocation) : EventArgs
{
	internal string NewLocation { get; } = newLocation;
}

internal static class NavigationViewLocationManager
{
	// The static event for NavigationView location changes
	// MainWindow listens to this to set the NavigationView's location
	internal static event EventHandler<NavigationViewLocationChangedEventArgs>? NavigationViewLocationChanged;

	// Method to raise the event when the location changes
	internal static void OnNavigationViewLocationChanged(string newLocation)
	{
		// Raise the NavigationViewLocationChanged event with the new location
		NavigationViewLocationChanged?.Invoke(
			null,
			new NavigationViewLocationChangedEventArgs(newLocation)
		);
	}
}
