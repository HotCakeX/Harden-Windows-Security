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

using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Web.WebView2.Core;

namespace CommonCore;

internal static class WebView2Config
{
	/// <summary>
	/// The directory that the app uses to store WebView2 profile data, accessible by all users.
	/// It is unique to be deleted when the app is closed.
	/// </summary>
#if APP_CONTROL_MANAGER
	private static readonly string WebView2Dir = Path.Combine(
		Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
				"AppControlManager", "WebView2", Guid.CreateVersion7().ToString("N"));
#endif
#if HARDEN_SYSTEM_SECURITY
	private static readonly string WebView2Dir = Path.Combine(
		Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
				"HardenSystemSecurity", "WebView2", Guid.CreateVersion7().ToString("N"));
#endif

	/// <summary>
	/// Used by all WebView2 elements in the entier app.
	/// </summary>
	private static readonly Lazy<CoreWebView2Environment> CoreWebView2Instance = new(() =>
	{
		_ = Directory.CreateDirectory(WebView2Dir);

		// Create environment with the profile directory
		CoreWebView2EnvironmentOptions envOptions = new()
		{
			AreBrowserExtensionsEnabled = false
		};

		return CoreWebView2Environment.CreateWithOptionsAsync(
			browserExecutableFolder: null,
			userDataFolder: WebView2Dir,
			options: envOptions).GetAwaiter().GetResult();

	}, LazyThreadSafetyMode.ExecutionAndPublication);

	/// <summary>
	/// Called when the app is closing.
	/// </summary>
	internal static void CleanUpWebView2()
	{
		// Only attempt cleanup if the shared environment was actually created during the app's current lifetime.
		if (!CoreWebView2Instance.IsValueCreated)
			return;

		// https://learn.microsoft.com/dotnet/api/microsoft.web.webview2.core.corewebview2environment.getprocessinfos
		IReadOnlyList<CoreWebView2ProcessInfo> processInfos;

		processInfos = CoreWebView2Instance.Value.GetProcessInfos();

		foreach (CoreWebView2ProcessInfo item in processInfos)
		{
			try
			{
				// GetProcessById can throw if the process already exite, aka process with the specified ID is not running.
				Process proc = Process.GetProcessById(item.ProcessId);

				try
				{
					// Kill entire process tree to release locks faster
					proc.Kill(true);
				}
				catch { }

				try
				{
					// Wait briefly for exit to let file handles be released
					_ = proc.WaitForExit(3000);
				}
				catch { }
			}
			catch { }
		}

		// Delete the entire WebView2's unique directory once all WebView2 processes have been terminated.
		if (Directory.Exists(WebView2Dir))
		{
			TryDeleteDirectoryWithRetries(WebView2Dir, 10, 500);
		}
	}

	/// <summary>
	/// Attempts to delete a directory recursively with retries to tolerate transient locks (e.g., Crashpad metrics files).
	/// Also normalizes attributes to avoid access issues due to read-only flags.
	/// </summary>
	/// <param name="path">Target directory path to delete.</param>
	/// <param name="maxAttempts">Maximum number of attempts.</param>
	/// <param name="delayMs">Delay between attempts in milliseconds.</param>
	internal static void TryDeleteDirectoryWithRetries(string path, int maxAttempts, int delayMs)
	{
		for (int attempt = 1; attempt <= maxAttempts; attempt++)
		{
			try
			{
				NormalizeAttributesRecursively(path);
				Directory.Delete(path, true);
				return;
			}
			catch (DirectoryNotFoundException) { return; } // Already deleted
			catch (IOException)
			{
				// Transient file lock (e.g., CrashpadMetrics-active.pma). Retry after delay.
			}
			catch (UnauthorizedAccessException)
			{
				// Attribute/ACL related; attributes are normalized each attempt. Retry after delay.
			}
			catch { } // Ignore unexpected cleanup errors; will retry.

			if (attempt < maxAttempts)
			{
				try
				{
					Thread.Sleep(delayMs);
				}
				catch { } // Ignore interruptions.
			}
		}
	}

	/// <summary>
	/// Clears read-only and special attributes on a directory tree to make recursive deletion more reliable.
	/// </summary>
	/// <param name="directoryPath">Root directory to normalize.</param>
	private static void NormalizeAttributesRecursively(string directoryPath)
	{
		try
		{
			if (!Directory.Exists(directoryPath))
				return;

			DirectoryInfo root = new(directoryPath);

			FileInfo[] files = root.GetFiles("*", SearchOption.AllDirectories);
			for (int i = 0; i < files.Length; i++)
			{
				FileInfo file = files[i];
				try
				{
					file.Attributes = FileAttributes.Normal;
				}
				catch { } // Ignore per-file failures.
			}

			DirectoryInfo[] dirs = root.GetDirectories("*", SearchOption.AllDirectories);
			for (int i = 0; i < dirs.Length; i++)
			{
				DirectoryInfo dir = dirs[i];
				try
				{
					dir.Attributes = FileAttributes.Normal;
				}
				catch { } // Ignore per-directory failures.
			}

			try
			{
				root.Attributes = FileAttributes.Normal;
			}
			catch { } // Ignore if we cannot set attributes on the root.
		}
		catch { } // Ignore any unexpected errors during normalization.
	}

	/// <summary>
	/// https://learn.microsoft.com/microsoft-edge/webview2/concepts/user-data-folder
	/// https://learn.microsoft.com/microsoft-edge/webview2/concepts/multi-profile-support
	/// https://learn.microsoft.com/microsoft-edge/webview2/reference/winrt/microsoft_web_webview2_core/corewebview2environmentoptions
	/// https://learn.microsoft.com/microsoft-edge/webview2/reference/winrt/microsoft_web_webview2_core/corewebview2controlleroptions
	/// Configures WebView2:
	///	- Assigns a custom profile data directory which is accessible by all users.
	///	  Required for environments where Administrator Protection is active.
	///	- Enables InPrivate mode.
	///	- Disables browser extensions.
	/// </summary>
	/// <returns></returns>
	internal static async Task ConfigureWebView2(WebView2 webView, Uri initialSource)
	{
		try
		{
			CoreWebView2ControllerOptions options = CoreWebView2Instance.Value.CreateCoreWebView2ControllerOptions();
			options.IsInPrivateModeEnabled = true;
			options.DefaultBackgroundColor = Windows.UI.Color.FromArgb(0, 0, 0, 0);
			options.ProfileName = "CORE";

			// Initialize the existing XAML WebView2 with the custom environment.
			await webView.EnsureCoreWebView2Async(CoreWebView2Instance.Value, options);

			webView.Source = initialSource;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}
}
