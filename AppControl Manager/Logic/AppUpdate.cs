
using System;
using System.Net.Http;

namespace WDACConfig
{
    /// <summary>
    /// AppUpdate class is responsible for checking for application updates.
    /// This class is implemented as a Singleton to ensure only one instance is created and used throughout the app.
    /// Providing a single access point for update-related operations.
    /// </summary>
    public class AppUpdate
    {
        // Singleton instance of AppUpdate, created lazily to optimize memory usage and control instantiation.
        private static readonly Lazy<AppUpdate> _instance = new(() => new AppUpdate());

        // Public property to access the single AppUpdate instance, enforcing Singleton pattern.
        // The Instance property returns the one and only instance of this class.
        public static AppUpdate Instance => _instance.Value;

        // Event triggered when an update is available
        public event EventHandler<bool>? UpdateAvailable;

        // Private constructor prevents instantiation from outside, ensuring only one instance.
        private AppUpdate() { }

        /// <summary>
        /// Downloads the version file from GitHub,
        /// Checks the online version against the current app version,
        /// and raises the UpdateAvailable event if an update is found.
        /// </summary>
        public UpdateCheckResponse Check()
        {
            using HttpClient client = new();

            string versionsResponse = client.GetStringAsync(GlobalVars.AppVersionLinkURL).GetAwaiter().GetResult();

            Version onlineAvailableVersion = new(versionsResponse);
            bool isUpdateAvailable = onlineAvailableVersion > App.currentAppVersion;

            // Raise the UpdateAvailable event if there's an update and there are subscribers
            UpdateAvailable?.Invoke(this, isUpdateAvailable);

            return new UpdateCheckResponse(
                isUpdateAvailable,
                onlineAvailableVersion
            );
        }
    }
}
