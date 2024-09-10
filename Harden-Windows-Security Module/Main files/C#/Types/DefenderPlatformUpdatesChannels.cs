using System.Collections.Generic;

#nullable enable

namespace HardenWindowsSecurity
{
    public class DefenderPlatformUpdatesChannels
    {
        public static readonly Dictionary<ushort, string> Channels = new()
    {
            { 0, "NotConfigured" },
            { 2, "Beta" },
            { 3, "Preview" },
            { 4, "Staged" },
            { 5, "Broad" },
            { 6, "Delayed" }
    };
    }
}
