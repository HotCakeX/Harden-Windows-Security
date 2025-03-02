using System;

namespace AppControlManager.Others;

/// <summary>
/// Represents an object that is the response of an update check for the AppControl Manager app
/// </summary>
internal sealed class UpdateCheckResponse(bool isNewVersionAvailable, Version onlineVersion)
{
	internal bool IsNewVersionAvailable { get; set; } = isNewVersionAvailable;
	internal Version OnlineVersion { get; set; } = onlineVersion;
}
