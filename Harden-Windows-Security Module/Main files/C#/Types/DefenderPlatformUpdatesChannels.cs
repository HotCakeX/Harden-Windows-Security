using System;
using System.Collections.Generic;

namespace HardeningModule
{
    public class DefenderPlatformUpdatesChannels
    {
        public static readonly Dictionary<ushort, string> Channels = new Dictionary<ushort, string>
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
