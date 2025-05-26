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
using System.ComponentModel;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Threading;
using AppControlManager.ViewModels;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace AppControlManager.Others;

/// <summary>
/// Monitors the max-size of a Windows Event Log channel via registry notifications
/// and exposes it as a bindable property.
/// </summary>
#pragma warning disable CA1812
internal sealed partial class EventLogUtility : ViewModelBase, IDisposable
{
	internal EventLogUtility()
	{
		// Kick off the registry monitor
		// (this will also read the initial MaxSize into)
		EventLogMaxSizeWatcher();
	}

	private readonly Lock _syncRoot = new();

	private static bool _suppressRegistryCallback;

	/// <summary>
	/// Bound to the max value of NumberBoxes in the XAML.
	/// </summary>
	internal string MaxNumberBoxValue = "17592186044000";

	/// <summary>
	/// Current maximum log size in megabytes (MB).
	/// </summary>
	private double _MaxSizeMB;
	internal double MaxSizeMB
	{
		get
		{
			lock (_syncRoot)
			{
				return _MaxSizeMB;
			}
		}
		set
		{
			lock (_syncRoot)
			{
				if (_MaxSizeMB != value)
				{
					_MaxSizeMB = value;
					OnPropertyChanged(nameof(MaxSizeMB));
				}
			}
		}
	}

	[Flags]
	internal enum RegNotifyFilter : uint
	{
		Name = 1,
		Attributes = 2,
		LastSet = 4,
		Security = 8
	}

	private RegistryKey? _regKey;
	private SafeRegistryHandle? _regHandle;
	private AutoResetEvent? _notificationEvent;
	private RegisteredWaitHandle? _waitHandle;

	internal void EventLogMaxSizeWatcher()
	{
		_regKey = Registry.LocalMachine.OpenSubKey(KeyPath, false)
				  ?? throw new ArgumentException($"Cannot open registry key: {KeyPath}");

		// Read and calculate initial size
		ulong initialBytes = ReadMaxSizeBytes();
		_ = Dispatcher.TryEnqueue(() => MaxSizeMB = initialBytes / 1024d / 1024d);

		// Prepare for change notifications
		_regHandle = _regKey.Handle;
		_notificationEvent = new AutoResetEvent(false);
		_waitHandle = ThreadPool.RegisterWaitForSingleObject(
			_notificationEvent,
			OnRegistryKeyChanged,
			state: null,
			millisecondsTimeOutInterval: -1,
			executeOnlyOnce: false
		);

		ReArmNotification();
	}

	private void OnRegistryKeyChanged(object? state, bool timedOut)
	{
		// If we just did the write ourselves, skip the update.
		if (_suppressRegistryCallback)
		{
			ReArmNotification();
			return;
		}

		// Read and calculate updated size
		ulong newBytes = ReadMaxSizeBytes();
		double newMegabytes = newBytes / 1024d / 1024d;
		_ = Dispatcher.TryEnqueue(() => MaxSizeMB = newMegabytes);

		ReArmNotification();
	}

	/// <summary>
	/// Reads the 64-bit MaxSize split across two 32-bit values: MaxSize (low) and MaxSizeUpper (high).
	/// Handles negative Int32 values by wrapping to the correct uint.
	/// </summary>
	private ulong ReadMaxSizeBytes()
	{
		object? rawLow = _regKey!.GetValue("MaxSize");
		object? rawHigh = _regKey.GetValue("MaxSizeUpper");

		uint low = ToUInt32Wrapped(rawLow);
		uint high = ToUInt32Wrapped(rawHigh);

		return ((ulong)high << 32) | low;
	}

	/// <summary>
	/// Safely convert registry raw value (int, long, ulong, uint, byte) to uint,
	/// wrapping negative signed values to the corresponding unsigned representation.
	/// </summary>
	private static uint ToUInt32Wrapped(object? raw)
	{
		return raw switch
		{
			int i => unchecked((uint)i),
			long l => unchecked((uint)l),
			ulong ul => unchecked((uint)ul),
			uint u => u,
			byte b => b,
			_ => 0u,
		};
	}

	private void ReArmNotification()
	{
		const RegNotifyFilter filter = RegNotifyFilter.LastSet;
		int result = NativeMethods.RegNotifyChangeKeyValue(
			_regHandle!,
			watchSubtree: false,
			notifyFilter: filter,
			hEvent: _notificationEvent!.SafeWaitHandle.DangerousGetHandle(),
			asynchronous: true
		);
		if (result != 0)
			throw new Win32Exception(result, "Failed to arm registry change notification");
	}

	void IDisposable.Dispose()
	{
		_suppressRegistryCallback = true;
		_ = _waitHandle?.Unregister(_notificationEvent);
		_notificationEvent?.Dispose();
		_regKey?.Dispose();
		_regHandle?.Dispose();
		GC.SuppressFinalize(this);
	}

	private const string logName = "Microsoft-Windows-CodeIntegrity/Operational";

	private const string KeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CodeIntegrity/Operational";

	/// <summary>
	/// Increase Code Integrity Operational Event Logs size from the default 1MB to user-defined size.
	/// Also automatically increases the log size by 1MB if the current free space is less than 1MB and the current maximum log size is less than or equal to 10MB.
	/// This is to prevent infinitely expanding the max log size automatically.
	/// Caps user-defined sizes at Int64.MaxValue to avoid overflow.
	/// </summary>
	/// <param name="logSize">Size of the Code Integrity Operational Event Log (in MB)</param>
	internal static void SetLogSize(double logSize = 0)
	{
		Logger.Write(GlobalVars.Rizz.GetString("SettingCodeIntegrityLogSizeMessageOnly"));

		try
		{
			_suppressRegistryCallback = true;

			using EventLogConfiguration logConfig = new(logName);
			string logFilePath = Environment.ExpandEnvironmentVariables(logConfig.LogFilePath);
			FileInfo logFileInfo = new(logFilePath);
			long currentLogFileSize = logFileInfo.Length;
			long currentLogMaxSize = logConfig.MaximumSizeInBytes;

			if (logSize == 0)
			{
				// Only increase by 1MB if there's less than 1MB free and under 10MB max
				if ((currentLogMaxSize - currentLogFileSize) < (1L * 1024 * 1024) && currentLogMaxSize <= (10L * 1024 * 1024))
				{
					Logger.Write(GlobalVars.Rizz.GetString("IncreasingCodeIntegrityLogSizeMessage"));
					logConfig.MaximumSizeInBytes = SafeAdd(currentLogMaxSize, 1L * 1024 * 1024);
					logConfig.IsEnabled = true;
					logConfig.SaveChanges();
				}
			}
			else
			{
				// Convert desired MB to bytes
				double bytesDesiredD = logSize * 1024d * 1024d;
				ulong bytesDesired = (ulong)bytesDesiredD;

				// Cap to Int64.MaxValue to avoid overflow
				long bytesToSet = bytesDesired >= long.MaxValue
					? long.MaxValue
					: (long)bytesDesired;

				if (bytesToSet > (1L * 1024 * 1024))
				{
					Logger.Write(
						string.Format(
							GlobalVars.Rizz.GetString("SettingCodeIntegrityLogSizeMessage"),
							bytesToSet / (1024d * 1024d)
						)
					);

					logConfig.MaximumSizeInBytes = bytesToSet;
					logConfig.IsEnabled = true;
					logConfig.SaveChanges();
				}
				else
				{
					Logger.Write(
						GlobalVars.Rizz.GetString("ProvidedLogSizeLessThanOrEqualOneMbNoChangesMadeMessage")
					);
				}
			}
		}
		finally
		{
			_suppressRegistryCallback = false;
		}
	}

	/// <summary>
	/// Adds two Int64 values safely, capping at Int64.MaxValue to prevent overflow.
	/// </summary>
	private static long SafeAdd(long a, long b)
	{
		try
		{
			return checked(a + b);
		}
		catch (OverflowException)
		{
			return long.MaxValue;
		}
	}


	/* Retired method - the log size is now retrieved in real time

	/// <summary>
	/// Gets the Code Integrity Operational Log Max capacity in Double
	/// </summary>
	/// <returns></returns>
	internal static double GetCurrentLogSize()
	{
		Logger.Write("Getting the Code Integrity Log Capacity");

		try
		{
			using EventLogConfiguration logConfig = new(logName);
			long logCapacityBytes = logConfig.MaximumSizeInBytes;

			// Convert bytes to megabytes
			double logCapacityMB = logCapacityBytes / (1024.0 * 1024.0);

			Logger.Write($"Log capacity: {logCapacityMB:F2} MB.");

			return logCapacityMB;
		}
		catch (Exception ex)
		{
			Logger.Write($"An error occurred while retrieving the log capacity: {ex.Message}");
			throw;
		}
	}
	*/


}
