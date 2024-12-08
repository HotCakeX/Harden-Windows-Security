using System;

namespace AppControlManager
{
    // Custom EventArgs class for navigation background changes
    internal sealed class NavigationBackgroundChangedEventArgs(bool isBackgroundOn) : EventArgs
    {
        internal bool IsBackgroundOn { get; } = isBackgroundOn;
    }

    internal static class NavigationBackgroundManager
    {
        // Event for when the NavigationView background changes
        internal static event EventHandler<NavigationBackgroundChangedEventArgs>? NavViewBackgroundChange;

        // Method to invoke the event
        internal static void OnNavigationBackgroundChanged(bool isBackgroundOn)
        {
            // Raise the NavViewBackgroundChange event with the new background status
            NavViewBackgroundChange?.Invoke(
                null,
                new NavigationBackgroundChangedEventArgs(isBackgroundOn)
            );
        }
    }
}
