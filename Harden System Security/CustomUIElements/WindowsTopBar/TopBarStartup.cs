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
using Windows.ApplicationModel;

namespace HardenSystemSecurity.CustomUIElements.WindowsTopBar;

/// <summary>
/// What Windows reports about running the app at sign in, reduced to only the outcomes that the bar has to act on.
/// </summary>
internal enum TopBarStartupState
{
	/// <summary>
	/// Windows runs the app at sign in.
	/// </summary>
	Enabled = 0,

	/// <summary>
	/// Windows does not run the app at sign in, and it can be switched back on from inside the app.
	/// </summary>
	Disabled = 1,

	/// <summary>
	/// The user switched the entry off in Task Manager or in the Startup page of the Settings app.
	/// Windows forbids any API from overriding that choice, so only the user can switch it back on.
	/// </summary>
	BlockedByUser = 2,

	/// <summary>
	/// An administrator switched the entry off through policy, so it cannot be switched back on at all.
	/// </summary>
	BlockedByPolicy = 3,

	/// <summary>
	/// Windows did not hand out the startup task, so nothing can be said about it.
	/// </summary>
	Unavailable = 4
}

/// <summary>
/// Drives the startup tasks of the package: the one that puts the top bar on the desktop when the user signs in to Windows,
/// and the one that starts the Global Search service so it builds its index at sign in.
/// The tasks are declared as disabled in the package manifest, so they only ever run after the user asks for them here.
/// </summary>
internal static class TopBarStartupManager
{
	/// <summary>
	/// Has to stay identical to the TaskId of the windows.startupTask extension of the package manifest.
	/// </summary>
	private const string StartupTaskId = "HardenSystemSecurityWindowsTopBar";

	/// <summary>
	/// Has to stay identical to the TaskId of the Global Search windows.startupTask extension of the package manifest.
	/// </summary>
	internal const string GlobalSearchStartupTaskId = "HardenSystemSecurityGlobalSearch";

	/// <summary>
	/// Used by the Startup task and JumpList to detect TopBar-only launches.
	/// </summary>
	internal const string WindowsTopBarLaunchArgument = "--windows-top-bar";

	/// <summary>
	/// Used by the Global Search startup task to start the service with indexing at startup.
	/// </summary>
	internal const string GlobalSearchLaunchArgument = "--startGlobalSearch";

	/// <summary>
	/// Reduces what Windows reports to the outcomes that the bar acts on.
	/// </summary>
	private static TopBarStartupState Translate(StartupTaskState state) => state switch
	{
		StartupTaskState.Enabled or StartupTaskState.EnabledByPolicy => TopBarStartupState.Enabled,
		StartupTaskState.DisabledByUser => TopBarStartupState.BlockedByUser,
		StartupTaskState.DisabledByPolicy => TopBarStartupState.BlockedByPolicy,
		_ => TopBarStartupState.Disabled
	};

	/// <summary>
	/// Asks Windows what it currently does with the startup task, without changing anything about it.
	/// </summary>
	internal static async Task<TopBarStartupState> GetStateAsync(string taskId = StartupTaskId)
	{
		try
		{
			StartupTask task = await StartupTask.GetAsync(taskId);

			return Translate(task.State);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);

			return TopBarStartupState.Unavailable;
		}
	}

	/// <summary>
	/// Asks Windows to start running the app at sign in, or to stop doing so.
	/// The state that comes back is the one that Windows settled on, which is not always the one that was asked for,
	/// because a user or a policy that switched the entry off cannot be overridden by any API.
	/// </summary>
	internal static async Task<TopBarStartupState> SetAsync(bool enabled, string taskId = StartupTaskId)
	{
		try
		{
			StartupTask task = await StartupTask.GetAsync(taskId);

			if (!enabled)
			{
				// Disable() is only meaningful while Windows is actually running the app at sign in.
				if (task.State is StartupTaskState.Enabled or StartupTaskState.EnabledByPolicy)
				{
					task.Disable();
				}

				// Reading the task again is what tells the truth, because an entry that a policy forces on
				// stays on no matter what was just asked of it.
				StartupTask refreshedTask = await StartupTask.GetAsync(taskId);

				return Translate(refreshedTask.State);
			}

			// A packaged desktop app never gets a consent dialog out of this call.
			StartupTaskState resultingState = await task.RequestEnableAsync();

			return Translate(resultingState);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);

			return TopBarStartupState.Unavailable;
		}
	}
}
