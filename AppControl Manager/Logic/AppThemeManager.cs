using System;

namespace WDACConfig
{
    public static class AppThemeManager
    {

        // The static event for App theme dark/light changes
        // MainWindow listens to this
        public static event Action<string>? AppThemeChanged;

        // Method to raise the event
        public static void OnAppThemeChanged(string newLocation)
        {
            AppThemeChanged?.Invoke(newLocation);
        }

    }
}
