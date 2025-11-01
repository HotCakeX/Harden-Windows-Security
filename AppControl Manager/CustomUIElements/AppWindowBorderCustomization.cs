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

using System.Diagnostics;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Windowing;
using Windows.Foundation;
using WinRT;

#if APP_CONTROL_MANAGER
namespace AppControlManager.CustomUIElements;
#endif

#if HARDEN_SYSTEM_SECURITY
namespace HardenSystemSecurity.CustomUIElements;
#endif

/// <summary>
/// Manage's App Window's border.
/// </summary>
internal static class AppWindowBorderCustomization
{
	private static DispatcherQueueTimer? Timer;

	private const double Speed = 4.0;
	private static long LastTimestamp; // Last Stopwatch tick count
	private static float Hue; // Current hue in [0,1)
	private static readonly float TickToSeconds = (float)(1.0 / Stopwatch.Frequency); // Conversion factor from ticks to seconds
	private const float InverseSpeed = 1f / (float)Speed;   // Precomputed inverse of Speed
	private static readonly TimeSpan FrameInterval = TimeSpan.FromMilliseconds(16);

	/// <summary>
	/// Used to track last known presenter state to avoid redundant start/stop calls.
	/// </summary>
	private static OverlappedPresenterState? LastPresenterState;

	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/dwmapi/ne-dwmapi-dwmwindowattribute
	/// </summary>
	private const int DWMWA_BORDER_COLOR = 34;

	/// <summary>
	/// Tick handler to allow unsubscription.
	/// </summary>
	private static readonly TypedEventHandler<DispatcherQueueTimer, object> TickHandler = static (t, o) => TickUpdate();

	/// <summary>
	/// Track start state to prevent duplicate initializations.
	/// </summary>
	private static bool IsStarted;

	/// <summary>
	/// Track AppWindow.Changed subscription to avoid multiple subscriptions.
	/// </summary>
	private static bool AppWindowSubscribed;


	private static bool IsStopping;

	/// <summary>
	/// Starts the animated frame effect. No effect if already started.
	/// </summary>
	internal static void StartAnimatedFrame()
	{
		// Prevent double-start.
		if (IsStarted)
			return;

		IsStarted = true;

		App.Settings.IsAnimatedRainbowEnabled = true;

		// Initialize timing and hue state.
		LastTimestamp = Stopwatch.GetTimestamp();
		Hue = 0f;

		// Create a fresh timer (previous one, if any, would have been cleaned in Stop).
		Timer = App.AppDispatcher.CreateTimer();
		Timer.IsRepeating = true;

		// Attach the single stored handler.
		Timer.Tick += TickHandler;

		// Ensure AppWindow change monitoring is hooked only once.
		if (!AppWindowSubscribed && App.MainWindow?.AppWindow is not null)
		{
			App.MainWindow.AppWindow.Changed += AppWindow_Changed;
			AppWindowSubscribed = true;

			// Initialize last presenter state so first change comparison is valid.
			OverlappedPresenter initPresenter = App.MainWindow.AppWindow.Presenter.As<OverlappedPresenter>();
			LastPresenterState = initPresenter.State;
		}

		Timer.Stop();
		Timer.Interval = FrameInterval;
		Timer.Start();
	}

	/// <summary>
	/// Used to stop the animated frame effect. No effect if already stopped.
	/// </summary>
	internal static void StopAnimatedFrame()
	{
		if (!IsStarted && Timer is null)
			return; // Already stopped / never started.

		if (Timer is not null)
		{
			try
			{
				// Stop timer first to avoid race with handler firing during detach.
				if (Timer.IsRunning)
				{
					Timer.Stop();
				}

				// Detach the stored handler.
				Timer.Tick -= TickHandler;
			}
			catch (Exception ex)
			{
				Logger.Write($"Exception while stopping animated frame timer: {ex}", LogTypeIntel.Error);
			}
			finally
			{
				Timer = null;
			}
		}

		// Unsubscribe from AppWindow changes if we had subscribed.
		if (AppWindowSubscribed)
		{
			try
			{
				App.MainWindow?.AppWindow.Changed -= AppWindow_Changed;
			}
			catch (Exception ex)
			{
				Logger.Write($"Exception while removing AppWindow.Changed handler: {ex}", LogTypeIntel.Error);
			}
			finally
			{
				AppWindowSubscribed = false;
			}
		}

		ResetBorderColor(); // Make sure the border won't have the last color in the cycle when we stop.

		IsStarted = false;

		App.Settings.IsAnimatedRainbowEnabled = false;
	}

	/// <summary>
	/// Handles AppWindow state changes.
	/// </summary>
	private static void AppWindow_Changed(AppWindow sender, AppWindowChangedEventArgs args)
	{
		// Ignore if animation not started or timer disposed or if only visibility changed (which is fired a Lot).
		if (!IsStarted || Timer is null || args.DidVisibilityChange)
			return;

		OverlappedPresenter presenter = sender.Presenter.As<OverlappedPresenter>();

		OverlappedPresenterState currentState = presenter.State;

		// If state didn't actually change, do nothing.
		if (LastPresenterState.HasValue && LastPresenterState.Value == currentState)
			return;

		// Update cached state.
		LastPresenterState = currentState;

		// Handle transitions.
		if (currentState is OverlappedPresenterState.Minimized && Timer.IsRunning)
		{
#if DEBUG
			Logger.Write("Animation stopped; Window minimized.");
#endif
			Timer.Stop();
		}
		else if (!Timer.IsRunning) // Only start when becoming non-minimized and currently not running.
		{
#if DEBUG
			Logger.Write("Animation started; Window no longer minimized.");
#endif
			// Reset timestamp to avoid a large hue jump after pause.
			LastTimestamp = Stopwatch.GetTimestamp();
			Timer.Start();
		}
	}

	/// <summary>
	/// Timer callback.
	/// </summary>
	private static void TickUpdate()
	{
		long currentTimestamp = Stopwatch.GetTimestamp();
		long deltaTicks = currentTimestamp - LastTimestamp;
		LastTimestamp = currentTimestamp;

		// Convert ticks to seconds.
		float deltaSeconds = deltaTicks * TickToSeconds;

		// Increment hue based on elapsed time and speed.
		Hue += deltaSeconds * InverseSpeed;

		// Wrap hue to [0,1) without using modulo.
		if (Hue >= 1f)
		{
			// (int)Hue removes the integer portion (if a long pause made it exceed by more than 1).
			Hue -= (int)Hue;
		}

		#region Convert hue to RGB border color.

		float t = Hue * 6f;

		float r = MathF.Abs(t - 3f) - 1f;
		float g = 2f - MathF.Abs(t - 2f);
		float b = 2f - MathF.Abs(t - 4f);

		r = r < 0f ? 0f : (r > 1f ? 1f : r);
		g = g < 0f ? 0f : (g > 1f ? 1f : g);
		b = b < 0f ? 0f : (b > 1f ? 1f : b);

		byte rr = (byte)(r * 255f);
		byte gg = (byte)(g * 255f);
		byte bb = (byte)(b * 255f);

		// https://learn.microsoft.com/windows/win32/gdi/colorref
		// COLORREF format expected: 0x00BBGGRR
		uint computedBorderColor = (uint)((bb << 16) | (gg << 8) | rr);

		#endregion

		// Main Apply
		int result = NativeMethods.DwmSetWindowAttribute(GlobalVars.hWnd, DWMWA_BORDER_COLOR, ref computedBorderColor, sizeof(uint));
		if (result != 0)
		{
			// If setting the border color failed, stop the timer to avoid further errors.
			if (Timer is not null && Timer.IsRunning)
			{
				Timer.Stop();
			}

			Logger.Write($"Failed to set window border color. DwmSetWindowAttribute returned error code: {result}", LogTypeIntel.Error);
		}
	}

	/// <summary>
	/// Sets a static border color for the app window.
	/// </summary>
	internal static void SetBorderColor(byte r, byte g, byte b)
	{
		// Stop any ongoing animations first before setting a static color.
		StopAnimatedFrame();

		try
		{
			uint color = (uint)((b << 16) | (g << 8) | r); // COLORREF 0x00BBGGRR

			int result = NativeMethods.DwmSetWindowAttribute(GlobalVars.hWnd, DWMWA_BORDER_COLOR, ref color, sizeof(uint));
			if (result != 0)
				Logger.Write($"Failed to set static window border color. DwmSetWindowAttribute returned: {result}", LogTypeIntel.Error);

			// Save the color as hex in the App settings.
			App.Settings.CustomAppWindowsBorder = RGBHEX.ToHex(r, g, b);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// Resets the border color to 0 (clears custom color).
	/// </summary>
	internal static void ResetBorderColor()
	{
		try
		{
			uint color = 0;
			int result = NativeMethods.DwmSetWindowAttribute(GlobalVars.hWnd, DWMWA_BORDER_COLOR, ref color, sizeof(uint));
			if (result != 0)
				Logger.Write($"Failed to reset window border color. DwmSetWindowAttribute returned: {result}", LogTypeIntel.Error);

			// Clear any saved color for app window's border in the App settings.
			App.Settings.CustomAppWindowsBorder = string.Empty;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// Stops the animation for application shutdown without modifying persisted settings or clearing the saved custom color.
	/// </summary>
	internal static void StopAnimatedFrameForAppShutdown()
	{
		// Quick exit if nothing active.
		if (!IsStarted && Timer is null)
			return;

		if (IsStopping)
			return;

		IsStopping = true;
		IsStarted = false;

		if (Timer is not null)
		{
			try
			{
				if (Timer.IsRunning)
				{
					Timer.Stop();
				}
				Timer.Tick -= TickHandler;
			}
			catch { }
			finally
			{
				Timer = null;
			}
		}

		if (AppWindowSubscribed)
		{
			try
			{
				App.MainWindow?.AppWindow.Changed -= AppWindow_Changed;
			}
			catch { }
			finally
			{
				AppWindowSubscribed = false;
			}
		}

		IsStopping = false;
	}
}
