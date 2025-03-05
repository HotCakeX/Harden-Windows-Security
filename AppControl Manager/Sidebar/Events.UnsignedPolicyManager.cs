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

namespace AppControlManager.Sidebar;

/// <summary>
/// The Events class encapsulates event-related logic for Sidebar
/// </summary>
internal sealed partial class Events
{

	// Custom EventArgs subclass to hold the data related to changes in UnsignedPolicyInUserConfig.
	internal sealed class UnsignedPolicyInUserConfigChangedEventArgs(string unsignedPolicyInUserConfig) : EventArgs
	{
		// Property to store the updated unsigned policy XML file paths.
		internal string UnsignedPolicyInUserConfig { get; } = unsignedPolicyInUserConfig;
	}

	// Static class to manage the event and its related operations.
	internal static class UnsignedPolicyManager
	{
		// Static event that can be subscribed to by other classes to be notified when the unsigned policy path in user config changes.
		internal static event EventHandler<UnsignedPolicyInUserConfigChangedEventArgs>? UnsignedPolicyInUserConfigChanged;

		// Method to trigger (raise) the UnsignedPolicyInUserConfigChanged event.
		// This method allows other classes to notify all subscribers about a change in the unsigned policy.
		internal static void OnUnsignedPolicyInUserConfigChanged(string unsignedPolicyInUserConfig)
		{
			// Invoke the event, passing 'null' as the sender since it's a static context.
			// A new instance of UnsignedPolicyInUserConfigChangedEventArgs is created to carry the updated configuration.
			UnsignedPolicyInUserConfigChanged?.Invoke(
				null, // Sender of the event (null because it's a static context).
				new UnsignedPolicyInUserConfigChangedEventArgs(unsignedPolicyInUserConfig) // EventArgs containing the new Unsigned policy XML file path.
			);
		}

	}
}
