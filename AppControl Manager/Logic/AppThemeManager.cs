using System;

namespace AppControlManager
{
    // Custom EventArgs class for app theme changes
    internal sealed class AppThemeChangedEventArgs(string? newTheme) : EventArgs
    {
        internal string? NewTheme { get; } = newTheme;
    }

    internal static class AppThemeManager
    {
        // The static event for App theme dark/light changes
        // MainWindow listens to this
        internal static event EventHandler<AppThemeChangedEventArgs>? AppThemeChanged;

        // Method to raise the event
        internal static void OnAppThemeChanged(string newTheme)
        {
            // Trigger the AppThemeChanged event with the new theme
            AppThemeChanged?.Invoke(null, new AppThemeChangedEventArgs(newTheme));
        }
    }
}
