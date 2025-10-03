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

namespace AppControlManager.AppSettings;

// Custom EventArgs class for navigation view location changes
internal sealed class NavigationViewLocationChangedEventArgs(string newLocation) : EventArgs
{
	internal string NewLocation => newLocation;
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
