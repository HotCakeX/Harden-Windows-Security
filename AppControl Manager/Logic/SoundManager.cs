using System;

namespace AppControlManager
{
    // Custom EventArgs class for sound setting changes
    internal sealed class SoundSettingChangedEventArgs(bool isSoundOn) : EventArgs
    {
        internal bool IsSoundOn { get; } = isSoundOn;
    }

    internal static class SoundManager
    {
        // Event to notify when the sound setting is changed
        internal static event EventHandler<SoundSettingChangedEventArgs>? SoundSettingChanged;

        // Method to invoke the event
        internal static void OnSoundSettingChanged(bool isSoundOn)
        {
            // Raise the SoundSettingChanged event with the new sound setting status
            SoundSettingChanged?.Invoke(
                null,
                new SoundSettingChangedEventArgs(isSoundOn)
            );
        }
    }
}
