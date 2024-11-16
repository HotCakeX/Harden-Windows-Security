using System;

namespace WDACConfig
{
    public static class ThemeManager
    {
        // The static event for background changes
        // MainWindow listens to this to set the app theme
        public static event Action<string>? BackDropChanged;

        // Method to raise the event when the background is changed
        public static void OnBackgroundChanged(string newBackground)
        {
            BackDropChanged?.Invoke(newBackground);
        }
    }
}
