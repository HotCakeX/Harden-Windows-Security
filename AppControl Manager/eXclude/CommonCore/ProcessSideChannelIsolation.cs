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

using System.Runtime.InteropServices;
using System.Text;

namespace CommonCore;

/// <summary>
/// Applies and verifies Windows process side-channel isolation mitigations for the current process.
/// https://learn.microsoft.com/he-il/windows/win32/api/winnt/ns-winnt-process_mitigation_side_channel_isolation_policy
/// </summary>
internal static class ProcessSideChannelIsolation
{
	/// <summary>
	/// Requests SMT branch target isolation for the process.
	/// </summary>
	internal const uint SmtBranchTargetIsolation = 1U << 0;

	/// <summary>
	/// Requests isolation of the process from other security domains.
	/// </summary>
	internal const uint IsolateSecurityDomain = 1U << 1;

	/// <summary>
	/// Disables memory page combining for the process.
	/// </summary>
	internal const uint DisablePageCombine = 1U << 2;

	/// <summary>
	/// Disables speculative store bypass for the process.
	/// </summary>
	internal const uint SpeculativeStoreBypassDisable = 1U << 3;

	/// <summary>
	/// Restricts sharing processor cores with processes from other security domains.
	/// </summary>
	internal const uint RestrictCoreSharing = 1U << 4;

	/// <summary>
	/// Combines all documented PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY flags currently requested by the app.
	/// </summary>
	internal const uint AllDocumentedFlags = SmtBranchTargetIsolation | IsolateSecurityDomain | DisablePageCombine | SpeculativeStoreBypassDisable | RestrictCoreSharing;

	/// <summary>
	/// Provides stable names for formatting policy status and failure details.
	/// </summary>
	private static readonly (uint Flag, string Name)[] KnownFlags =
	[
		(SmtBranchTargetIsolation, nameof(SmtBranchTargetIsolation)),
		(IsolateSecurityDomain, nameof(IsolateSecurityDomain)),
		(DisablePageCombine, nameof(DisablePageCombine)),
		(SpeculativeStoreBypassDisable, nameof(SpeculativeStoreBypassDisable)),
		(RestrictCoreSharing, nameof(RestrictCoreSharing))
	];

	/// <summary>
	/// Applies any missing documented side-channel isolation flags, then returns the effective policy reported by Windows.
	/// </summary>
	internal static unsafe ProcessSideChannelIsolationResult ApplyToCurrentProcess()
	{
		uint failedFlags = 0U;
		StringBuilder failures = new();

		// Preserve the full policy returned by Windows, including any future/unknown bits,
		// before attempting to add documented flags known to this app.

		PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY currentPolicy = QueryCurrentPolicy();
		uint desiredFlags = currentPolicy.Flags;

		for (int i = 0; i < KnownFlags.Length; i++)
		{
			uint flag = KnownFlags[i].Flag;
			if ((desiredFlags & flag) == flag)
			{
				continue;
			}

			PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY policy = new()
			{
				Flags = desiredFlags | flag
			};

			bool setSucceeded = NativeMethods.SetProcessMitigationPolicy(
				PROCESS_MITIGATION_POLICY.SideChannelIsolation,
				ref policy,
				(nuint)sizeof(PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY));

			if (setSucceeded)
			{
				desiredFlags |= flag;
			}
			else
			{
				int error = Marshal.GetLastPInvokeError();
				failedFlags |= flag;
				if (failures.Length > 0)
				{
					_ = failures.Append("; ");
				}

				_ = failures.Append(KnownFlags[i].Name);
				_ = failures.Append(" failed with Win32 error ");
				_ = failures.Append(error);
			}
		}

		// Query again after all attempts so the result reflects the effective process policy, not only requested flags.
		PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY verifiedPolicy = QueryCurrentPolicy();
		uint enabledDocumentedFlags = verifiedPolicy.Flags & AllDocumentedFlags;

		return new ProcessSideChannelIsolationResult(
			enabledDocumentedFlags,
			AllDocumentedFlags & ~enabledDocumentedFlags,
			failedFlags,
			failures.ToString());
	}

	/// <summary>
	/// Reads the effective side-channel isolation policy without changing the current process policy.
	/// </summary>
	internal static ProcessSideChannelIsolationResult VerifyCurrentProcess()
	{
		PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY verifiedPolicy = QueryCurrentPolicy();
		uint enabledDocumentedFlags = verifiedPolicy.Flags & AllDocumentedFlags;

		return new ProcessSideChannelIsolationResult(
			enabledDocumentedFlags,
			AllDocumentedFlags & ~enabledDocumentedFlags,
			0U,
			string.Empty);
	}

	/// <summary>
	/// Queries Windows for the current PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY value.
	/// </summary>
	/// <exception cref="InvalidOperationException">Thrown when Windows fails to return the policy.</exception>
	private static PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY QueryCurrentPolicy()
	{
		int policyFlags = 0;

		bool getSucceeded = NativeMethods.GetProcessMitigationPolicy(
			NativeMethods.GetCurrentProcess(),
			PROCESS_MITIGATION_POLICY.SideChannelIsolation,
			ref policyFlags,
			sizeof(uint));

		if (!getSucceeded)
		{
			int error = Marshal.GetLastPInvokeError();
			throw new InvalidOperationException($"GetProcessMitigationPolicy(SideChannelIsolation) failed with Win32 error {error}.");
		}

		return new PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY { Flags = unchecked((uint)policyFlags) };
	}

	/// <summary>
	/// Formats each documented flag as Enabled or NotEnabled, and includes per-flag apply errors when any occurred.
	/// </summary>
	internal static string FormatStatus(ProcessSideChannelIsolationResult result)
	{
		StringBuilder builder = new("Process side-channel isolation mitigations: ");

		for (int i = 0; i < KnownFlags.Length; i++)
		{
			if (i > 0)
			{
				_ = builder.Append(", ");
			}

			_ = builder.Append(KnownFlags[i].Name);
			_ = builder.Append('=');
			_ = builder.Append((result.EnabledFlags & KnownFlags[i].Flag) == KnownFlags[i].Flag ? "Enabled" : "NotEnabled");
		}

		if (result.FailedFlags != 0U)
		{
			_ = builder.Append(". Apply failures: ");
			_ = builder.Append(result.FailureDetails);
		}

		return builder.ToString();
	}
}

/// <summary>
/// Contains the effective side-channel isolation flags and any failures encountered while applying them.
/// </summary>
/// <param name="enabledFlags">side-channel isolation flags reported as enabled by Windows.</param>
/// <param name="missingFlags">side-channel isolation flags that Windows did not report as enabled.</param>
/// <param name="failedFlags">side-channel isolation flags that failed during SetProcessMitigationPolicy calls.</param>
/// <param name="failureDetails">Formatted Win32 error details for failed SetProcessMitigationPolicy calls.</param>
internal readonly struct ProcessSideChannelIsolationResult(uint enabledFlags, uint missingFlags, uint failedFlags, string failureDetails)
{
	internal uint EnabledFlags => enabledFlags;
	internal uint MissingFlags => missingFlags;
	internal uint FailedFlags => failedFlags;
	internal string FailureDetails => failureDetails;
	internal bool AllDocumentedFlagsEnabled => MissingFlags == 0U;
}
