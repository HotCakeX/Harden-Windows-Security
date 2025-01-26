using System;
using System.Text.RegularExpressions;
using System.Windows.Controls;
using Windows.Management.Deployment;

namespace HardenWindowsSecurity;

internal static class GUIAppControlManager
{
	internal static UserControl? View;

	internal static Grid? ParentGrid;

	internal static PackageManager packageMgr = new();

	// Pattern for AppControl Manager version and architecture extraction from file path and download link URL
	internal static readonly Regex regex = new(@"_(?<Version>\d+\.\d+\.\d+\.\d+)_(?<Architecture>x64|arm64)\.msix$", RegexOptions.IgnoreCase);

	internal static readonly Uri AppUpdateDownloadLinkURL = new("https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/refs/heads/main/AppControl%20Manager/DownloadURL.txt");
}
