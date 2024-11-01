#nullable enable

using System;

namespace WDACConfig
{
    /// <summary>
    /// Represents an object that is the response of an update check for the AppControl Manager app
    /// </summary>
    /// <param name="isNewVersionAvailable"></param>
    /// <param name="onlineVersion"></param>
    public sealed class UpdateCheckResponse(bool isNewVersionAvailable, Version onlineVersion)
    {
        public bool IsNewVersionAvailable { get; set; } = isNewVersionAvailable;
        public Version OnlineVersion { get; set; } = onlineVersion;
    }
}
