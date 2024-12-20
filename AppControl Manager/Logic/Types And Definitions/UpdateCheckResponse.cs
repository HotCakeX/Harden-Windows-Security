using System;

namespace AppControlManager;

/// <summary>
/// Represents an object that is the response of an update check for the AppControl Manager app
/// </summary>
public sealed class UpdateCheckResponse(bool isNewVersionAvailable, Version onlineVersion)
{
	public bool IsNewVersionAvailable { get; set; } = isNewVersionAvailable;
	public Version OnlineVersion { get; set; } = onlineVersion;
}
