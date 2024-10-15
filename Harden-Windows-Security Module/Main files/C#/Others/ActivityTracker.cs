using System.Collections.Generic;
using System.Windows;

#nullable enable

namespace HardenWindowsSecurity
{
    /// <summary>
    /// This class is responsible for tracking the activity status of the application and managing the
    /// enabled/disabled state of registered UI elements based on this status. It is thread-safe to ensure
    /// that concurrent access to the activity state and UI elements list is handled properly.
    /// </summary>
    public static class ActivityTracker
    {
        // A volatile boolean to indicate whether the application is currently active or not.
        // The 'volatile' keyword ensures that the value is always read directly from memory,
        // not from a processor cache, which is important in a multithreaded environment.
        private static volatile bool _isActive;

        // An object used for locking critical sections of code to make them thread-safe.
        // This ensures that only one thread can access the locked section at a time.
        private static readonly object _lock = new();

        // A list to keep track of UIElements that should be disabled/enabled based on the application's activity status.
        private static readonly List<UIElement> _uiElements = [];

        /// <summary>
        /// Gets or sets the current activity status of the application.
        /// When setting the status, it also updates the state of all registered UI elements.
        /// </summary>
        public static bool IsActive
        {
            get
            {
                // Lock the critical section to ensure thread-safe access to the _isActive variable.
                lock (_lock)
                {
                    return _isActive;
                }
            }
            set
            {
                // Lock the critical section to ensure thread-safe update of the _isActive variable.
                lock (_lock)
                {
                    _isActive = value;

                    // Update the enabled/disabled state of all registered UI elements when the activity status changes.
                    UpdateUIElements();

                    // Update the visibility of the main progress bar based on the activity status.
                    UpdateMainProgressBarVisibility();
                }
            }
        }

        /// <summary>
        /// Registers a UI element to be managed by the ActivityTracker.
        /// The element's enabled/disabled state will be controlled based on the application's activity status.
        /// If the application is currently active, the element will be immediately disabled.
        /// </summary>
        /// <param name="element">The UI element to register.</param>
        public static void RegisterUIElement(UIElement element)
        {
            // Lock the critical section to ensure thread-safe access to the _uiElements list.
            lock (_lock)
            {
                // Check if the element is not already in the list to prevent duplicate entries.
                if (!_uiElements.Contains(element))
                {
                    _uiElements.Add(element);

                    // If the application is currently active, disable the newly registered element immediately.
                    if (_isActive)
                    {
                        // Ensure that the update to the UI element happens on the UI thread.
                        GUIMain.app!.Dispatcher.Invoke(() =>
                        {
                            element.IsEnabled = false; // Disable the element if the application is active.
                        });
                    }
                }
            }
        }

        /// <summary>
        /// Unregisters a UI element from being managed by the ActivityTracker.
        /// The element's enabled/disabled state will no longer be controlled by the application's activity status.
        /// </summary>
        /// <param name="element">The UI element to unregister.</param>
        public static void UnregisterUIElement(UIElement element)
        {
            // Lock the critical section to ensure thread-safe access to the _uiElements list.
            lock (_lock)
            {
                // Remove the element from the list if it exists.
                _ = _uiElements.Remove(element);
            }
        }

        /// <summary>
        /// Updates the enabled/disabled state of all registered UI elements based on the current activity status.
        /// This method is called whenever the activity status changes.
        /// </summary>
        private static void UpdateUIElements()
        {
            // Iterate through each registered UI element.
            foreach (var element in _uiElements)
            {
                // Ensure that the update to each UI element happens on the UI thread.
                GUIMain.app!.Dispatcher.Invoke(() =>
                {
                    // Set the IsEnabled property of the element based on the current activity status.
                    // If the application is active (_isActive is true), disable the element (IsEnabled = false).
                    // If the application is not active (_isActive is false), enable the element (IsEnabled = true).
                    element.IsEnabled = !_isActive;
                });
            }
        }

        /// <summary>
        /// Updates the visibility of the main progress bar based on the current activity status.
        /// This method is called whenever the activity status changes.
        /// </summary>
        private static void UpdateMainProgressBarVisibility()
        {
            // Ensure that the update to the progress bar's visibility happens on the UI thread.
            GUIMain.app!.Dispatcher.Invoke(() =>
            {
                // Set the Visibility property of the main progress bar based on the current activity status.
                // If the application is active (_isActive is true), set Visibility to Visible.
                // If the application is not active (_isActive is false), set Visibility to Collapsed.
                GUIMain.mainProgressBar!.Visibility = _isActive ? Visibility.Visible : Visibility.Collapsed;
            });
        }
    }
}
