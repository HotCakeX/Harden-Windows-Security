using HardenWindowsSecurity;
using System;
using System.Collections.Generic;
using System.Windows;

#nullable enable

namespace HardenWindowsSecurity
{
    /// <summary>
    /// This class defines a member that is responsible for tracking activity across the Harden Windows Security Application
    /// It is thread safe
    /// It also offers methods for registering UI elements to be enabled/disabled based on the global Application activity
    /// </summary>
    internal static class ActivityTracker
    {
        private static volatile bool _isActive;
        private static readonly object _lock = new object();

        // A list to keep track of UIElements that should be disabled/enabled
        private static readonly List<UIElement> _uiElements = new List<UIElement>();

        public static bool IsActive
        {
            get
            {
                lock (_lock)
                {
                    return _isActive;
                }
            }
            set
            {
                lock (_lock)
                {
                    _isActive = value;

                    // Update UI elements when the activity status changes
                    UpdateUIElements();
                }
            }
        }

        // Method to register UI elements to be managed by ActivityTracker
        public static void RegisterUIElement(UIElement element)
        {
            lock (_lock)
            {
                // Ensure the element is not already in the list
                if (!_uiElements.Contains(element))
                {
                    _uiElements.Add(element);
                }
            }
        }

        // Method to unregister UI elements
        public static void UnregisterUIElement(UIElement element)
        {
            lock (_lock)
            {
                if (_uiElements.Contains(element))
                {
                    _uiElements.Remove(element);
                }
            }
        }

        // Method to update the enabled/disabled state of registered UI elements
        private static void UpdateUIElements()
        {
            foreach (var element in _uiElements)
            {
                // Ensure the update happens on the UI thread
                HardenWindowsSecurity.GUIMain.app!.Dispatcher.Invoke(() =>
                {
                    element.IsEnabled = !_isActive;
                });
            }
        }
    }
}
