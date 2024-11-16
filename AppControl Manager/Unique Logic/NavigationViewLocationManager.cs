using System;

namespace WDACConfig
{
    public static class NavigationViewLocationManager
    {
        // The static event for NavigationView location changes
        // MainWindow listens to this to set the NavigationView's location
        public static event Action<string>? NavigationViewLocationChanged;

        // Method to raise the event when the background is changed
        public static void OnNavigationViewLocationChanged(string newLocation)
        {
            NavigationViewLocationChanged?.Invoke(newLocation);
        }
    }
}
