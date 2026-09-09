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
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using AppControlManager.Pages;
using HardenSystemSecurity.Widgets;

namespace HardenSystemSecurity.CustomUIElements.WindowsTopBar;

/// <summary>
/// An immutable reading of every metric that the performance view of the top bar displays.
/// A metric that the machine cannot report is expressed as <see cref="double.NaN"/>.
/// </summary>
internal readonly struct TopBarMetricsSnapshot(
	double cpuUsagePercent,
	double cpuTemperatureCelsius,
	double memoryUsagePercent,
	ulong usedPhysicalBytes,
	ulong totalPhysicalBytes,
	double storageTemperatureCelsius,
	double diskReadBytesPerSecond,
	double diskWriteBytesPerSecond,
	double networkReceiveBytesPerSecond,
	double networkSendBytesPerSecond,
	double totalSystemPowerWatts,
	double batteryDischargeWatts,
	ulong appMemoryBytes)
{
	internal double CpuUsagePercent => cpuUsagePercent;
	internal double CpuTemperatureCelsius => cpuTemperatureCelsius;
	internal double MemoryUsagePercent => memoryUsagePercent;
	internal ulong UsedPhysicalBytes => usedPhysicalBytes;
	internal ulong TotalPhysicalBytes => totalPhysicalBytes;
	internal double StorageTemperatureCelsius => storageTemperatureCelsius;
	internal double DiskReadBytesPerSecond => diskReadBytesPerSecond;
	internal double DiskWriteBytesPerSecond => diskWriteBytesPerSecond;
	internal double NetworkReceiveBytesPerSecond => networkReceiveBytesPerSecond;
	internal double NetworkSendBytesPerSecond => networkSendBytesPerSecond;
	internal double TotalSystemPowerWatts => totalSystemPowerWatts;
	internal double BatteryDischargeWatts => batteryDischargeWatts;
	internal ulong AppMemoryBytes => appMemoryBytes;
}

internal readonly struct TopBarForegroundProcessSnapshot(string name, double cpuUsagePercent, ulong memoryBytes, int processCount)
{
	internal string Name => name;
	internal double CpuUsagePercent => cpuUsagePercent;
	internal ulong MemoryBytes => memoryBytes;
	internal int ProcessCount => processCount;
}

/// <summary>
/// Collects every metric that the live system intelligence page of the app displays, so that the performance view of
/// the top bar can show the very same numbers without having to open that page.
/// The samplers that already exist in the app are reused wherever one is available, and the remaining counters are
/// opened here and kept alive for the lifetime of the instance, because a rate counter needs at least two collections
/// that are spaced apart in time before it can produce a meaningful value.
/// </summary>
internal sealed partial class TopBarMetricsSampler : IDisposable
{
	// https://learn.microsoft.com/windows/win32/perfctrs/pdh-error-codes
	private const uint ERROR_SUCCESS = 0x00000000;
	private const uint PDH_FMT_DOUBLE = 0x00000200;

	// The English (locale independent) counter paths of the machine wide physical disk throughput.
	private const string DiskReadCounterPath = @"\PhysicalDisk(_Total)\Disk Read Bytes/sec";
	private const string DiskWriteCounterPath = @"\PhysicalDisk(_Total)\Disk Write Bytes/sec";

	/// <summary>
	/// The information level of the battery state.
	/// https://learn.microsoft.com/windows/win32/api/powerbase/nf-powerbase-callntpowerinformation
	/// </summary>
	private const int SystemBatteryState = 5;

	private PerformanceMetricsSampler? _performanceSampler;
	private NetworkThroughputSampler? _networkSampler;
	private List<EnergyMeterDevice>? _energyMeterDevices;

	private IntPtr _diskQuery;
	private IntPtr _diskReadCounter;
	private IntPtr _diskWriteCounter;
	private bool _diskCountersInitialized;
	private bool _disposed;
	private IntPtr _processBuffer;
	private uint _processBufferSize = 256U * 1024U;
	private uint _previousGroupRootId;
	private ulong _previousGroupCpuTime;
	private long _previousGroupTimestamp;
	private uint _cachedDescriptionProcessId;
	private string _cachedDescription = string.Empty;

	/// <summary>
	/// Reads every metric once. It never throws; a metric that is unavailable is reported as <see cref="double.NaN"/>.
	/// </summary>
	internal TopBarMetricsSnapshot Sample()
	{
		InitializeExpandedResources();
		PerformanceMetricsSampler performanceSampler = _performanceSampler ?? throw new InvalidOperationException();
		PerformanceSnapshot performance = performanceSampler.Sample(includeStorageTemperature: true);

		double memoryUsagePercent = performance.TotalPhysicalBytes > 0UL
			? (double)performance.UsedPhysicalBytes / performance.TotalPhysicalBytes * 100.0
			: double.NaN;

		SampleDiskActivity(out double diskReadBytesPerSecond, out double diskWriteBytesPerSecond);
		SampleNetworkThroughput(out double networkReceiveBytesPerSecond, out double networkSendBytesPerSecond);

		return new TopBarMetricsSnapshot(
			performance.CpuUsagePercent,
			performance.CpuTemperatureCelsius,
			memoryUsagePercent,
			performance.UsedPhysicalBytes,
			performance.TotalPhysicalBytes,
			performance.StorageTemperatureCelsius,
			diskReadBytesPerSecond,
			diskWriteBytesPerSecond,
			networkReceiveBytesPerSecond,
			networkSendBytesPerSecond,
			SampleTotalSystemPower(),
			SampleBatteryDischarge(),
			SampleAppMemory());
	}

	private void InitializeExpandedResources()
	{
		if (_performanceSampler is not null)
		{
			return;
		}
		_performanceSampler = new PerformanceMetricsSampler();
		_networkSampler = new NetworkThroughputSampler();
		_energyMeterDevices = [];
		InitializeDiskCounters();
		try
		{
			_energyMeterDevices.AddRange(EnergyMeterDevice.Enumerate());
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// Opens the physical disk throughput counters and primes them with a first collection.
	/// </summary>
	private void InitializeDiskCounters()
	{
		try
		{
			if (NativeMethods.PdhOpenQueryW(null, 0U, out _diskQuery) != ERROR_SUCCESS || _diskQuery == IntPtr.Zero)
			{
				return;
			}

			if (NativeMethods.PdhAddEnglishCounterW(_diskQuery, DiskReadCounterPath, 0U, out _diskReadCounter) != ERROR_SUCCESS)
			{
				CloseDiskCounters();
				return;
			}

			if (NativeMethods.PdhAddEnglishCounterW(_diskQuery, DiskWriteCounterPath, 0U, out _diskWriteCounter) != ERROR_SUCCESS)
			{
				CloseDiskCounters();
				return;
			}

			// A rate counter only becomes meaningful from the second collection onwards.
			_ = NativeMethods.PdhCollectQueryData(_diskQuery);

			_diskCountersInitialized = true;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);

			CloseDiskCounters();
		}
	}

	private void SampleDiskActivity(out double readBytesPerSecond, out double writeBytesPerSecond)
	{
		readBytesPerSecond = double.NaN;
		writeBytesPerSecond = double.NaN;

		if (!_diskCountersInitialized)
		{
			return;
		}

		try
		{
			if (NativeMethods.PdhCollectQueryData(_diskQuery) != ERROR_SUCCESS)
			{
				return;
			}

			readBytesPerSecond = ReadCounter(_diskReadCounter);
			writeBytesPerSecond = ReadCounter(_diskWriteCounter);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	private static double ReadCounter(IntPtr counterHandle)
	{
		uint status = NativeMethods.PdhGetFormattedCounterValue(counterHandle, PDH_FMT_DOUBLE, out uint _, out PDH_FMT_COUNTERVALUE_DOUBLE counterValue);

		return status == ERROR_SUCCESS && counterValue.CStatus == ERROR_SUCCESS ? Math.Max(0.0, counterValue.Value) : double.NaN;
	}

	/// <summary>
	/// Sums the throughput of every adapter of the machine that is currently connected.
	/// </summary>
	private void SampleNetworkThroughput(out double receiveBytesPerSecond, out double sendBytesPerSecond)
	{
		receiveBytesPerSecond = double.NaN;
		sendBytesPerSecond = double.NaN;

		try
		{
			NetworkThroughputSampler networkSampler = _networkSampler ?? throw new InvalidOperationException();
			IReadOnlyList<NetworkAdapter> adapters = networkSampler.GetAdapters();

			// Every adapter has to be measured within the same cycle so that a rate is only derived once per adapter.
			networkSampler.BeginSampleCycle();

			double receiveTotal = 0.0;
			double sendTotal = 0.0;
			bool measured = false;

			foreach (NetworkAdapter adapter in adapters)
			{
				if (!adapter.IsConnected)
				{
					continue;
				}

				if (!networkSampler.TrySample(adapter.InterfaceLuid, out NetworkAdapterSample sample))
				{
					continue;
				}

				receiveTotal += sample.ReceiveBytesPerSecond;
				sendTotal += sample.SendBytesPerSecond;
				measured = true;
			}

			if (measured)
			{
				receiveBytesPerSecond = receiveTotal;
				sendBytesPerSecond = sendTotal;
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// Sums the average power of every energy meter that the machine exposes.
	/// </summary>
	private double SampleTotalSystemPower()
	{
		try
		{
			double totalWatts = 0.0;
			bool measured = false;

			foreach (EnergyMeterDevice device in _energyMeterDevices ?? [])
			{
				if (device.TryReadTotalAveragePower(out double deviceWatts))
				{
					totalWatts += deviceWatts;
					measured = true;
				}
			}

			return measured ? totalWatts : double.NaN;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);

			return double.NaN;
		}
	}

	/// <summary>
	/// Reads how much power the battery is currently giving away. A battery that is not discharging reports zero.
	/// </summary>
	private static unsafe double SampleBatteryDischarge()
	{
		try
		{
			SYSTEM_BATTERY_STATE batteryState = default;

			int status = NativeMethods.CallNtPowerInformation(SystemBatteryState, null, 0U, &batteryState, (uint)sizeof(SYSTEM_BATTERY_STATE));

			// A rate of int.MinValue means that the driver cannot report the current rate at all.
			if (status != 0 || batteryState.BatteryPresent == 0 || batteryState.Rate == int.MinValue)
			{
				return double.NaN;
			}

			// The rate is expressed in milliwatts and it is negative while the battery is discharging.
			return batteryState.Discharging != 0 && batteryState.Rate < 0
				? -(double)batteryState.Rate / 1000.0
				: 0.0;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);

			return double.NaN;
		}
	}

	/// <summary>
	/// Reads the private working set of the app, which is the very same figure that the live system intelligence page
	/// reports and that the task manager displays.
	/// The counters are read natively because building a managed process object would make the whole process table of
	/// the machine be captured and parsed on every single sample.
	/// </summary>
	private static ulong SampleAppMemory()
	{
		PROCESS_MEMORY_COUNTERS_EX2 counters = default;
		counters.cb = (uint)Unsafe.SizeOf<PROCESS_MEMORY_COUNTERS_EX2>();

		if (!NativeMethods.K32GetProcessMemoryInfo(NativeMethods.GetCurrentProcess(), ref counters, counters.cb))
		{
			return 0UL;
		}

		// The private working set is preferred so that the figure matches the task manager, and the whole working set
		// is only fallen back on when the machine cannot report the private part of it.
		return counters.PrivateWorkingSetSize != 0U ? counters.PrivateWorkingSetSize : counters.WorkingSetSize;
	}

	internal unsafe TopBarForegroundProcessSnapshot SampleForegroundProcess(uint foregroundProcessId)
	{
		if (foregroundProcessId == 0U || !TryCollectProcesses())
			return new(string.Empty, double.NaN, 0UL, 0);

		SYSTEM_PROCESS_INFORMATION* foreground = FindProcess(foregroundProcessId);

		if (foreground is null || foreground->ImageName.Buffer == IntPtr.Zero)
			return new(string.Empty, double.NaN, 0UL, 0);

		ReadOnlySpan<char> foregroundName = GetImageName(foreground);
		uint rootId = foregroundProcessId;
		SYSTEM_PROCESS_INFORMATION* root = foreground;

		while (true)
		{
			uint parentId = (uint)(nuint)root->InheritedFromUniqueProcessId;

			SYSTEM_PROCESS_INFORMATION* parent = FindProcess(parentId);

			if (parent is null || !GetImageName(parent).Equals(foregroundName, StringComparison.OrdinalIgnoreCase))
				break;

			root = parent;
			rootId = parentId;
		}

		ulong cpuTime = 0UL;
		ulong memoryBytes = 0UL;
		int processCount = 0;
		byte* current = (byte*)_processBuffer;

		while (true)
		{
			SYSTEM_PROCESS_INFORMATION* process = (SYSTEM_PROCESS_INFORMATION*)current;
			uint processId = (uint)(nuint)process->UniqueProcessId;

			if (processId == rootId || IsDescendantOf(process, rootId))
			{
				cpuTime += (ulong)Math.Max(0L, process->KernelTime) + (ulong)Math.Max(0L, process->UserTime);
				memoryBytes += (ulong)Math.Max(0L, process->WorkingSetPrivateSize);
				processCount++;
			}

			if (process->NextEntryOffset == 0U)
				break;

			current += process->NextEntryOffset;
		}
		long timestamp = Stopwatch.GetTimestamp();
		double cpuUsage = double.NaN;

		if (_previousGroupRootId == rootId && timestamp > _previousGroupTimestamp && cpuTime >= _previousGroupCpuTime)
		{
			double seconds = (timestamp - _previousGroupTimestamp) / (double)Stopwatch.Frequency;
			cpuUsage = Math.Clamp((cpuTime - _previousGroupCpuTime) / 10_000_000.0 / seconds / Environment.ProcessorCount * 100.0, 0.0, 100.0);
		}

		_previousGroupRootId = rootId;
		_previousGroupCpuTime = cpuTime;
		_previousGroupTimestamp = timestamp;

		string fallback = Path.GetFileNameWithoutExtension(GetImageName(root).ToString());

		return new(GetDisplayName(rootId, fallback), cpuUsage, memoryBytes, processCount);
	}

	private unsafe ReadOnlySpan<char> GetImageName(SYSTEM_PROCESS_INFORMATION* process) =>
		process->ImageName.Buffer == IntPtr.Zero ? [] : new ReadOnlySpan<char>((void*)process->ImageName.Buffer, process->ImageName.Length / sizeof(char));

	private unsafe SYSTEM_PROCESS_INFORMATION* FindProcess(uint processId)
	{
		if (processId == 0U)
			return null;

		byte* current = (byte*)_processBuffer;

		while (true) { SYSTEM_PROCESS_INFORMATION* process = (SYSTEM_PROCESS_INFORMATION*)current; if ((uint)(nuint)process->UniqueProcessId == processId) return process; if (process->NextEntryOffset == 0U) return null; current += process->NextEntryOffset; }
	}

	private unsafe bool IsDescendantOf(SYSTEM_PROCESS_INFORMATION* process, uint rootId)
	{
		uint parentId = (uint)(nuint)process->InheritedFromUniqueProcessId;
		for (int depth = 0; depth < 16 && parentId != 0U; depth++)
		{
			if (parentId == rootId)
				return true;

			SYSTEM_PROCESS_INFORMATION* parent = FindProcess(parentId);

			if (parent is null)
				break;

			uint next = (uint)(nuint)parent->InheritedFromUniqueProcessId;

			if (next == parentId)
				break;

			parentId = next;
		}
		return false;
	}

	private unsafe string GetDisplayName(uint processId, string fallback)
	{
		if (_cachedDescriptionProcessId == processId)
			return _cachedDescription;

		string description = fallback;
		const uint ProcessQueryLimitedInformation = 0x1000;
		IntPtr process = NativeMethods.OpenProcess(ProcessQueryLimitedInformation, false, processId);

		if (process != IntPtr.Zero)
		{
			try
			{
				Span<char> pathBuffer = stackalloc char[1024];
				uint length = (uint)pathBuffer.Length;
				fixed (char* path = pathBuffer)
				{
					if (NativeMethods.QueryFullProcessImageNameW(process, 0U, path, ref length) && length > 0U)
					{
						string fullPath = new(path, 0, checked((int)length));
						string? fileDescription = FileVersionInfo.GetVersionInfo(fullPath).FileDescription;

						if (!string.IsNullOrWhiteSpace(fileDescription))
							description = fileDescription.Trim();
					}
				}
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}
			finally
			{
				_ = NativeMethods.CloseHandle(process);
			}
		}
		_cachedDescriptionProcessId = processId;
		_cachedDescription = description;

		return description;
	}

	private unsafe bool TryCollectProcesses()
	{
		const int SystemProcessInformation = 5;
		const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);

		if (_processBuffer == IntPtr.Zero)
			_processBuffer = (IntPtr)NativeMemory.Alloc(_processBufferSize);

		for (int attempt = 0; attempt < 2; attempt++)
		{
			int required = 0;
			int status = NativeMethods.NtQuerySystemInformation(SystemProcessInformation, _processBuffer, checked((int)_processBufferSize), ref required);

			if (status >= 0)
				return true;

			if (status != StatusInfoLengthMismatch || required <= 0)
				return false;

			_processBufferSize = checked((uint)required + 65536U);
			_processBuffer = (IntPtr)NativeMemory.Realloc((void*)_processBuffer, _processBufferSize);
		}
		return false;
	}

	internal void ReleaseExpandedResources()
	{
		CloseDiskCounters();
		_performanceSampler?.Dispose();
		_performanceSampler = null;
		_networkSampler = null;
		if (_energyMeterDevices is null)
		{
			return;
		}
		foreach (EnergyMeterDevice device in _energyMeterDevices)
		{
			device.Dispose();
		}
		_energyMeterDevices.Clear();
		_energyMeterDevices = null;
	}

	private void CloseDiskCounters()
	{
		if (_diskQuery != IntPtr.Zero)
		{
			_ = NativeMethods.PdhCloseQuery(_diskQuery);
			_diskQuery = IntPtr.Zero;
		}

		_diskReadCounter = IntPtr.Zero;
		_diskWriteCounter = IntPtr.Zero;
		_diskCountersInitialized = false;
	}

	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_disposed = true;
		if (_processBuffer != IntPtr.Zero)
		{
			unsafe
			{
				NativeMemory.Free((void*)_processBuffer);
			}
			_processBuffer = IntPtr.Zero;
		}
		ReleaseExpandedResources();
	}
}
