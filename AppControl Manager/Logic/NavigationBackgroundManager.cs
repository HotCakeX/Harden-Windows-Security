using System;

namespace WDACConfig
{
    public static class NavigationBackgroundManager
    {
        // Event for when the NavigationView background changes
        public static event Action<bool>? NavViewBackgroundChange;

        // Method to invoke the event
        public static void OnNavigationBackgroundChanged(bool isBackgroundOn)
        {
            NavViewBackgroundChange?.Invoke(isBackgroundOn);
        }
    }
}
