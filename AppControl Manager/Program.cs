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

#if HARDEN_SYSTEM_SECURITY
namespace HardenSystemSecurity;
#else
namespace AppControlManager;
#endif

/// <summary>
/// Custom managed entry point used because the project defines the
/// DISABLE_XAML_GENERATED_MAIN compilation symbol. When that symbol is defined, the
/// XAML compiler renames its generated program class to "XamlGeneratedProgram" and its
/// entry method to "XamlGeneratedMain".
/// </summary>
internal static class Program
{
	private static string[] _launchArguments = [];

	/// <summary>
	/// Gets the command-line arguments supplied to the managed entry point for the current process.
	/// </summary>
	internal static string[] GetLaunchArguments() => _launchArguments;

	[STAThread]
	private static void Main(string[] args)
	{
		// Unelevated startup operations use: args[0] == "STARTUPREDIRECT", args[1] == operation name,
		// followed by any operation-specific value in args[2]. Normal launches skip all operation checks.
		if (args.Length >= 2 && string.Equals(args[0], "STARTUPREDIRECT", StringComparison.OrdinalIgnoreCase))
		{
			// args[1] == "TOAST", args[2] == Base64.
			if (args.Length >= 3 && string.Equals(args[1], "TOAST", StringComparison.OrdinalIgnoreCase))
			{
				UnelevatedOperations.ToastNotifications.Startup_ShowToastNotification(args[2]);
			}
			// args[1] == "BADGE", args[2] == integer value of the BadgeNotificationGlyph enum.
			else if (args.Length >= 3 && string.Equals(args[1], "BADGE", StringComparison.OrdinalIgnoreCase))
			{
				UnelevatedOperations.TaskbarBadge.Startup_SetTaskbarBadge(args[2]);
			}
			// args[1] == "BADGECLEAR", clears the active taskbar badge (no value needed).
			else if (string.Equals(args[1], "BADGECLEAR", StringComparison.OrdinalIgnoreCase))
			{
				UnelevatedOperations.TaskbarBadge.Startup_ClearTaskbarBadge();
			}
			// args[1] == "TOASTCLEARALL", removes all app notifications from Notification Center.
			else if (string.Equals(args[1], "TOASTCLEARALL", StringComparison.OrdinalIgnoreCase))
			{
				UnelevatedOperations.ToastNotifications.Startup_ClearAllToastNotifications().GetAwaiter().GetResult();
			}
			// args[1] == "TASKBARPIN", requests taskbar pinning from the unelevated session.
			else if (string.Equals(args[1], "TASKBARPIN", StringComparison.OrdinalIgnoreCase))
			{
				UnelevatedOperations.AppShortcuts.Startup_PinToTaskbar().GetAwaiter().GetResult();
			}
			// args[1] == "STARTPIN", requests Start menu pinning from the unelevated session.
			else if (string.Equals(args[1], "STARTPIN", StringComparison.OrdinalIgnoreCase))
			{
				UnelevatedOperations.AppShortcuts.Startup_PinToStartMenu().GetAwaiter().GetResult();
			}

			// A STARTUPREDIRECT launch must never continue into the normal XAML application startup path.
			Environment.Exit(0);
		}

#if HARDEN_SYSTEM_SECURITY
		if (args.Length >= 1)
		{
			// The Widgets Board launches the app with this argument in order to activate the widget provider COM server.
			// It is a completely headless code path that must never reach the XAML application startup.
			// The COM runtime can supply additional ones such as "-Embedding" but we don't need them.
			if (string.Equals(args[0], Widgets.WidgetProviderHost.ComServerArgument, StringComparison.OrdinalIgnoreCase))
			{
				Widgets.WidgetProviderHost.Run();
				Environment.Exit(0);
			}

			// MCP is a headless stdio protocol path and must run before WinUI initialization.
			if (string.Equals(args[0], "--mcp", StringComparison.OrdinalIgnoreCase))
			{
				MCP.McpServer.RunAsync().GetAwaiter().GetResult();
				return;
			}
		}
#endif

		// Assign the launch arguments to the static property so that they can be accessed from the OnLaunched method.
		_launchArguments = args;

		// Nothing can run after this, so this should always be at the end.
		XamlGeneratedProgram.XamlGeneratedMain();
	}
}
