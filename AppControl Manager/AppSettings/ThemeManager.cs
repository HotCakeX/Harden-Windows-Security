using System;

namespace AppControlManager;

// Custom EventArgs class for the event
internal sealed class BackgroundChangedEventArgs(string? newBackground) : EventArgs
{
	internal string? NewBackground { get; } = newBackground;
}

internal static class ThemeManager
{
	// The static event for background changes
	// MainWindow listens to this to set the app theme
	internal static event EventHandler<BackgroundChangedEventArgs>? BackDropChanged;

	// Method to raise the event when the background is changed
	internal static void OnBackgroundChanged(string newBackground)
	{
		BackDropChanged?.Invoke(null, new BackgroundChangedEventArgs(newBackground));
	}
}
