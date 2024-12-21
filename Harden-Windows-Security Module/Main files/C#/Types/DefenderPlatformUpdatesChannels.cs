using System.Collections.Generic;

namespace HardenWindowsSecurity;

/// <summary>
/// Microsoft Defender Update channel names for Platform and Engine
/// </summary>
internal static class DefenderPlatformUpdatesChannels
{
	internal static readonly Dictionary<ushort, string> Channels = new()
	{
			{ 0, "NotConfigured" },
			{ 2, "Beta" },
			{ 3, "Preview" },
			{ 4, "Staged" },
			{ 5, "Broad" },
			{ 6, "Delayed" }
	};
}
