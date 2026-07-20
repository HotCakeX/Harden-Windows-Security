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
using System.ComponentModel;
using System.Threading.Tasks;
using CommonCore.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Foundation;
using Windows.Management;
using Windows.System;

namespace AppControlManager.CustomUIElements;

/// <summary>
/// A self-contained Intune check-in button that uses the official Windows MDM session API.
/// </summary>
internal sealed partial class IntuneCheckInButton : UserControl, INPCImplant
{
	#region INPCImplant Implementation
	public event PropertyChangedEventHandler? PropertyChanged;
	public void RaisePropertyChanged(string? propertyName) => PropertyChanged?.Invoke(this, new(propertyName));
	#endregion

	internal IntuneCheckInButton()
	{
		InitializeComponent();

#if HARDEN_SYSTEM_SECURITY // Only for HSS because ACM is more enterprise-oriented.
		// Updates the control visibility based on the device MDM registration state.
		Visibility = IsDeviceRegisteredWithMdm() ? Visibility.Visible : Visibility.Collapsed;
#endif
	}

	private const double InitialProgressValue = 0D;
	private const double SessionCreatedProgressValue = 20D;
	private const double SessionStartedProgressValue = 35D;
	private const double MaximumRunningProgressValue = 92D;
	private const double CompletedProgressValue = 100D;
	private const int ProgressPollingDelayMilliseconds = 500;

	private bool IsCheckInButtonEnabled { get; set => this.SP(ref field, value); } = true;
	private double ProgressValue { get; set => this.SP(ref field, value); }
	private string StatusText { get; set => this.SP(ref field, value); } = "Ready to check in.";
	private string SessionIdText { get; set => this.SP(ref field, value); } = "Not available yet";
	private string SessionStateText { get; set => this.SP(ref field, value); } = "Not started";
	private string SessionNoteText { get; set => this.SP(ref field, value); } = "Use this to request the latest organization updates for this device.";
	private string LatestSessionIdText { get; set => this.SP(ref field, value); } = "Not retrieved";
	private string LatestSessionStateText { get; set => this.SP(ref field, value); } = "Not retrieved";
	private string LatestSessionNoteText { get; set => this.SP(ref field, value); } = "Use the retrieve button to read the most recent local MDM session record exposed by Windows.";

	/// <summary>
	/// Checks whether Windows reports this device as registered with an MDM service.
	/// </summary>
	private static bool IsDeviceRegisteredWithMdm()
	{
		try
		{
			int hResult = NativeMethods.IsDeviceRegisteredWithManagement(
				out bool isRegisteredWithMdm,
				0U,
				IntPtr.Zero);

			if (hResult != 0)
			{
				Logger.Write($"MDM enrollment detection failed. Error code: 0x{hResult:X8}.");
				return false;
			}

			return isRegisteredWithMdm;
		}
		catch (Exception ex)
		{
			Logger.Write($"MDM enrollment detection failed. Error code: 0x{ex.HResult:X8}. {ex.Message}");
			return false;
		}
	}

	private async void StartCheckInAsync()
	{
		IsCheckInButtonEnabled = false;
		ProgressValue = InitialProgressValue;
		ApplySessionStatus("Starting check-in.", "Pending", "Preparing", "Getting things ready.");

		try
		{
			Progress<IntuneCheckInProgress> progress = new(ApplyProgress);
			await RunCheckInOnBackgroundThreadAsync(progress);
		}
		catch (Exception ex)
		{
			ApplyProgress(new IntuneCheckInProgress(
				InitialProgressValue,
				"Intune check-in failed.",
				"Unavailable",
				"Failed",
				$"Error code: 0x{ex.HResult:X8}. {ex.Message}",
				true,
				true));
		}
		finally
		{
			IsCheckInButtonEnabled = true;
		}
	}

	/// <summary>
	/// Reads the most recent local MDM session record exposed by Windows for the current enterprise account.
	/// </summary>
	private void RetrieveLatestLocalMdmSession()
	{
		try
		{
			IReadOnlyList<string> sessionIds = MdmSessionManager.SessionIds;

			if (sessionIds.Count == 0)
			{
				ApplyLatestSessionStatus("Not found", "No local session", "Windows did not return any persisted local MDM sessions for the current enterprise account.");
				return;
			}

			string sessionId = sessionIds[sessionIds.Count - 1];
			MdmSession? mdmSession = MdmSessionManager.GetSessionById(sessionId);

			if (mdmSession is null)
			{
				ApplyLatestSessionStatus(sessionId, "Unavailable", "Windows returned the session ID, but the session details could not be opened.");
				return;
			}

			string stateText = GetMdmSessionStateText(mdmSession);
			string noteText = string.Equals(stateText, nameof(MdmSessionState.Completed), StringComparison.OrdinalIgnoreCase)
				? "This local MDM session completed. Cloud processing and reporting may still have continued after the local session finished."
				: $"Extended error: {GetMdmSessionExtendedErrorText(mdmSession)}";

			ApplyLatestSessionStatus(GetMdmSessionIdText(mdmSession), stateText, noteText);
		}
		catch (Exception ex)
		{
			ApplyLatestSessionStatus("Unavailable", "No MDM session", "Windows did not return an app-visible local MDM session. This device might not currently be enrolled in MDM.");
			Logger.Write($"Latest local MDM session retrieval failed. Error code: 0x{ex.HResult:X8}. {ex.Message}");
		}
	}

	private async void OpenWorkSchoolSettingsAsync() => await Launcher.LaunchUriAsync(new Uri("ms-settings:workplace"));

	private static async Task RunCheckInOnBackgroundThreadAsync(IProgress<IntuneCheckInProgress> progress)
	{
		await Task.Run(async () =>
		{
			progress.Report(new IntuneCheckInProgress(
				10D,
				"Creating MDM session.",
				"Pending",
				"Creating local session",
				"Requesting a Windows MDM session for the current enterprise account.",
				true));

			MdmSession? mdmSession = MdmSessionManager.TryCreateSession();

			if (mdmSession is null)
			{
				progress.Report(new IntuneCheckInProgress(
					InitialProgressValue,
					"No MDM session is available.",
					"Unavailable",
					"No local session",
					"This device might not be enrolled in Intune or another MDM service for the current enterprise account.",
					true,
					true));
				return;
			}

			progress.Report(new IntuneCheckInProgress(
				SessionCreatedProgressValue,
				"MDM session created.",
				"Assigned after start",
				"Ready to start",
				"Starting the check-in request.",
				true));

			IAsyncAction startAction = mdmSession.StartAsync();
			double runningProgressValue = SessionStartedProgressValue;

			while (startAction.Status is AsyncStatus.Started)
			{
				string stateText = GetMdmSessionStateText(mdmSession);

				progress.Report(new IntuneCheckInProgress(
					runningProgressValue,
					$"MDM session state: {stateText}.",
					GetMdmSessionIdText(mdmSession),
					stateText,
					"The local MDM session is running.",
					false));

				runningProgressValue = Math.Min(MaximumRunningProgressValue, runningProgressValue + 4D);
				await Task.Delay(ProgressPollingDelayMilliseconds).ConfigureAwait(false);
			}

			await startAction;

			string finalStateText = GetMdmSessionStateText(mdmSession);
			string noteText = string.Equals(finalStateText, nameof(MdmSessionState.Completed), StringComparison.OrdinalIgnoreCase)
				? "Intune policy processing and cloud reporting can continue asynchronously after this local MDM session completes."
				: $"Extended error: {GetMdmSessionExtendedErrorText(mdmSession)}";

			progress.Report(new IntuneCheckInProgress(
				CompletedProgressValue,
				"Intune check-in completed locally.",
				GetMdmSessionIdText(mdmSession),
				finalStateText,
				noteText,
				true));
		});
	}

	private void ApplyProgress(IntuneCheckInProgress progress)
	{
		if (!progress.ForceApply && progress.ProgressValue < ProgressValue)
		{
			return;
		}

		ProgressValue = progress.ProgressValue;
		ApplySessionStatus(progress.StatusText, progress.SessionIdText, progress.SessionStateText, progress.NoteText);

		if (progress.Log)
			Logger.Write($"{progress.StatusText} - Session ID: {progress.SessionIdText}. State: {progress.SessionStateText}. {progress.NoteText}");
	}

	private void ApplySessionStatus(string statusText, string sessionIdText, string sessionStateText, string noteText)
	{
		StatusText = statusText;
		SessionIdText = sessionIdText;
		SessionStateText = sessionStateText;
		SessionNoteText = noteText;
	}

	private void ApplyLatestSessionStatus(string sessionIdText, string sessionStateText, string noteText)
	{
		LatestSessionIdText = sessionIdText;
		LatestSessionStateText = sessionStateText;
		LatestSessionNoteText = noteText;
	}

	private static string GetMdmSessionIdText(MdmSession mdmSession)
	{
		try
		{
			return string.IsNullOrWhiteSpace(mdmSession.Id) ? "Unavailable" : mdmSession.Id;
		}
		catch (Exception ex)
		{
			return $"Unavailable, error code: 0x{ex.HResult:X8}";
		}
	}

	private static string GetMdmSessionStateText(MdmSession mdmSession)
	{
		try
		{
			return mdmSession.State.ToString();
		}
		catch (Exception ex)
		{
			return $"Unavailable, error code: 0x{ex.HResult:X8}";
		}
	}

	private static string GetMdmSessionExtendedErrorText(MdmSession mdmSession)
	{
		try
		{
			return $"0x{mdmSession.ExtendedError.HResult:X8}";
		}
		catch (Exception ex)
		{
			return $"Unavailable, error code: 0x{ex.HResult:X8}";
		}
	}

	private readonly record struct IntuneCheckInProgress(
		double ProgressValue,
		string StatusText,
		string SessionIdText,
		string SessionStateText,
		string NoteText,
		bool Log,
		bool ForceApply = false);
}
