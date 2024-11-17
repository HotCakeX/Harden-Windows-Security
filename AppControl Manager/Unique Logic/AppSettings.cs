using Windows.Storage;

namespace WDACConfig
{
    // https://learn.microsoft.com/en-us/uwp/api/windows.storage.applicationdata.localsettings

    public static class AppSettings
    {
        // Save setting to local storage with a specific key and value
        public static void SaveSetting(SettingKeys key, object? value)
        {
            ApplicationDataContainer localSettings = ApplicationData.Current.LocalSettings;
            localSettings.Values[key.ToString()] = value;
        }

        // Retrieve setting from local storage with a specific key
        public static T? GetSetting<T>(SettingKeys key)
        {
            var localSettings = ApplicationData.Current.LocalSettings;

            // Check if the key exists and get the value
            if (localSettings.Values.TryGetValue(key.ToString(), out object? value))
            {
                // Return value cast to T (for value types, this works with nullable types as well)
                return value is T result ? result : default;
            }

            // Return default value (null for reference types, or default(T) for value types)
            return default;
        }


        // Enum for the setting keys
        // Used when saving and retrieving settings
        public enum SettingKeys
        {
            SoundSetting,
            NavViewBackground,
            NavViewPaneDisplayMode,
            AppTheme,
            BackDropBackground,
            IconsStyle
        }
    }
}
