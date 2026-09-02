// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using System.Threading.Tasks;
using Windows.UI.StartScreen;

namespace HardenSystemSecurity.WindowComponents;

/// <summary>
/// https://learn.microsoft.com/uwp/api/windows.ui.startscreen.jumplistitem
/// </summary>
internal static class JumpListMgr
{
	private const string LiveSystemIntelligenceArgument = "--live-system-intelligence";
	internal const string CpuTemperatureTarget = "cpu-temperature", CpuUsageTarget = "cpu-usage", StorageTemperatureTarget = "storage-temperature",
		NetworkUsageTarget = "network-usage", SystemMemoryTarget = "system-memory", DiskActivityTarget = "disk-activity",
		TotalSystemPowerTarget = "total-system-power", BatteryDischargeTarget = "battery-discharge";

	private static readonly (string Target, string DisplayName, string Logo)[] LiveSystemIntelligenceTargets =
	[
		(CpuTemperatureTarget, "CPU Temperature", "CPUTemp"),
		(CpuUsageTarget, "CPU Usage", "CPU"),
		(StorageTemperatureTarget, "Storage Temperature", "Temperature"),
		(NetworkUsageTarget, "Network Usage", "Network"),
		(SystemMemoryTarget, "RAM Usage", "RAM"),
		(DiskActivityTarget, "Disk Activity", "SSD"),
		(TotalSystemPowerTarget, "Total System Power", "Power"),
		(BatteryDischargeTarget, "Battery Discharge", "Battery")
	];

	/// <summary>
	/// Gets the requested Live System Intelligence target from the first launch argument.
	/// </summary>
	internal static string? GetLiveSystemIntelligenceLaunchTarget(string[] args) =>
		args.Length == 0 || !string.Equals(args[0], LiveSystemIntelligenceArgument, StringComparison.OrdinalIgnoreCase)
			? null
			: args.Length > 1 ? args[1] : string.Empty;

	// The same file name but with .ico extension is used for taskbar icon and with .png extension is used for JumpList logo icon.
	internal static string? GetLiveSystemIntelligenceIconPath(string target)
	{
		foreach ((string itemTarget, string _, string logo) in LiveSystemIntelligenceTargets)
		{
			if (string.Equals(target, itemTarget, StringComparison.OrdinalIgnoreCase))
			{
				return $@"Assets\External\{logo}.ico";
			}
		}
		return null;
	}

	/// <summary>
	/// Rebuilds the app jump list with the Live System Intelligence window targets.
	/// </summary>
	internal static async Task EnsureJumpListAsync()
	{
		if (!JumpList.IsSupported())
		{
			return;
		}
		try
		{
			JumpList jumpList = await JumpList.LoadCurrentAsync();
			jumpList.SystemGroupKind = JumpListSystemGroupKind.None;
			jumpList.Items.Clear();

			// Create the Windows top bar entry in the JumpList.
			JumpListItem topBarItem = JumpListItem.CreateWithArguments(
				CustomUIElements.WindowsTopBar.TopBarStartupManager.WindowsTopBarLaunchArgument,
				"Windows Top Bar");
			topBarItem.Description = "Display the Windows top bar";
			topBarItem.Logo = new Uri("ms-appx:///Assets/Square44x44Logo.targetsize-48.png");
			jumpList.Items.Add(topBarItem);

			// Create the Live System Intelligence entry in the JumpList
			JumpListItem dashboardItem = JumpListItem.CreateWithArguments(
				LiveSystemIntelligenceArgument,
				"Live System Intelligence");

			dashboardItem.Description = "Open Live System Intelligence";
			dashboardItem.Logo = new Uri("ms-appx:///Assets/Square44x44Logo.targetsize-48.png");
			jumpList.Items.Add(dashboardItem);

			// Create the individual target entries in the JumpList for overlay charts
			foreach ((string target, string displayName, string logo) in LiveSystemIntelligenceTargets)
			{
				JumpListItem item = JumpListItem.CreateWithArguments(
					$"{LiveSystemIntelligenceArgument} {target}",
					displayName);

				item.GroupName = "Live System Intelligence Widgets";
				item.Description = $"Open {displayName}";
				item.Logo = new Uri($"ms-appx:///Assets/External/{logo}.png");
				jumpList.Items.Add(item);
			}

			await jumpList.SaveAsync();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}
}
