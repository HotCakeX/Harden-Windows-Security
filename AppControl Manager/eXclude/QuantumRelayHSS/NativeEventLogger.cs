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

using System;
using System.Text;

namespace QuantumRelayHSS;

internal static partial class NativeEventLogger
{
	internal enum EventLogEntryType
	{
		Error = 1,       // EVENTLOG_ERROR_TYPE
		Warning = 2,     // EVENTLOG_WARNING_TYPE
		Information = 4  // EVENTLOG_INFORMATION_TYPE
	}

	/// <summary>
	/// Used to write logs to Windows Event Logs when the log can't be sent to the client because
	/// the client is unavailable or the log need to be written before client is connected or after it is disconnected.
	/// </summary>
	/// <param name="message"></param>
	/// <param name="type"></param>
	internal static void WriteEntry(string message, EventLogEntryType type)
	{
		try
		{
			// Register the source (returns handle even if registry not pre-created)
			IntPtr hEventLog = NativeMethods.RegisterEventSourceW(null, Atlas.QuantumRelayHSSServiceName);
			if (hEventLog == IntPtr.Zero)
			{
				return;
			}

			try
			{
				ushort wType = type switch
				{
					EventLogEntryType.Error => 0x0001,       // EVENTLOG_ERROR_TYPE
					EventLogEntryType.Warning => 0x0002,     // EVENTLOG_WARNING_TYPE
					_ => 0x0004                              // EVENTLOG_INFORMATION_TYPE
				};

				string[] strings = [message ?? string.Empty];

				// Category = 0, EventID = 0, no SID, one insertion string, no raw data
				_ = NativeMethods.ReportEventW(
					hEventLog,
					wType,
					0,
					0,
					IntPtr.Zero,
					(ushort)strings.Length,
					0,
					strings,
					IntPtr.Zero);
			}
			finally
			{
				_ = NativeMethods.DeregisterEventSource(hEventLog);
			}
		}
		catch
		{
			// Intentionally swallow logging failures to never impact service flow
		}
	}

	internal static void EnsureSourceRegistered(string source)
	{
		try
		{
			string subKey = $"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\{source}";

			IntPtr hKey = IntPtr.Zero;

			int rc = NativeMethods.RegCreateKeyExW(
				new IntPtr(unchecked(0x80000002)), // HKEY_LOCAL_MACHINE
				subKey,
				0,
				null,
				0,
				0x0002 | 0x0004, // KEY_SET_VALUE | KEY_CREATE_SUB_KEY
				IntPtr.Zero,
				out hKey,
				out uint disposition);

			if (rc != 0 || hKey == IntPtr.Zero)
			{
				return;
			}

			try
			{
				// TypesSupported = 7 (Error | Warning | Information)
				byte[] typesSupported = BitConverter.GetBytes((uint)7);
				_ = NativeMethods.RegSetValueExW(hKey, "TypesSupported", 0, 4 /* REG_DWORD */, typesSupported, (uint)typesSupported.Length);

				// EventMessageFile = %SystemRoot%\System32\EventCreate.exe (expandable string)
				string emf = "%SystemRoot%\\System32\\EventCreate.exe";
				byte[] emfBytes = Encoding.Unicode.GetBytes(emf + "\0"); // include terminating null
				_ = NativeMethods.RegSetValueExW(hKey, "EventMessageFile", 0, 2 /* REG_EXPAND_SZ */, emfBytes, (uint)emfBytes.Length);
			}
			finally
			{
				_ = NativeMethods.RegCloseKey(hKey);
			}
		}
		catch { } // Ignore any registry errors
	}
}
