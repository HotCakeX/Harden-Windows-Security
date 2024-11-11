using System;

namespace WDACConfig
{
    public static class SoundManager
    {
        // Event to notify when the sound setting is changed
        public static event Action<bool>? SoundSettingChanged;

        // Method to invoke the event
        public static void OnSoundSettingChanged(bool isSoundOn)
        {
            SoundSettingChanged?.Invoke(isSoundOn);
        }
    }
}
