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
using System.Runtime.CompilerServices;
using AppControlManager.Pages;
using CommonCore.ThermalMonitors;

namespace HardenSystemSecurity.Widgets;

/// <summary>
/// An immutable snapshot of the live metrics that the Performance widget displays.
/// Any metric that the current hardware/OS cannot report is expressed as <see cref="double.NaN"/> or as a zero total.
/// </summary>
internal readonly struct PerformanceSnapshot(
		double cpuTemperatureCelsius,
		double cpuUsagePercent,
		ulong usedPhysicalBytes,
		ulong totalPhysicalBytes,
		double storageTemperatureCelsius)
{
	/// <summary>
	/// The CPU thermal zone temperature in Celsius. <see cref="double.NaN"/> when the device exposes no usable thermal zone.
	/// </summary>
	internal double CpuTemperatureCelsius => cpuTemperatureCelsius;

	/// <summary>
	/// Total CPU utilization across all logical processors, from 0 to 100. <see cref="double.NaN"/> when unavailable.
	/// </summary>
	internal double CpuUsagePercent => cpuUsagePercent;

	/// <summary>
	/// Physical memory that is currently in use, in bytes.
	/// </summary>
	internal ulong UsedPhysicalBytes => usedPhysicalBytes;

	/// <summary>
	/// Total installed physical memory that is visible to the OS, in bytes. Zero when unavailable.
	/// </summary>
	internal ulong TotalPhysicalBytes => totalPhysicalBytes;

	/// <summary>
	/// The temperature of the hottest physical drive in Celsius. <see cref="double.NaN"/> when no drive reports one or
	/// when the metric was not requested because no widget that displays it is visible.
	/// </summary>
	internal double StorageTemperatureCelsius => storageTemperatureCelsius;
}

/// <summary>
/// Collects the CPU temperature, the total CPU utilization, the physical memory utilization and the disk temperature
/// of the machine.
/// It has no UI/dispatcher dependency at all so that it can run inside of the headless widget provider COM server process.
/// The PDH query handles are kept alive for the lifetime of the instance because "% Processor Time" is a rate counter
/// which requires at least two collections spaced apart in time in order to produce a meaningful value.
/// </summary>
internal sealed partial class PerformanceMetricsSampler : IDisposable
{
	// https://learn.microsoft.com/windows/win32/perfctrs/pdh-error-codes
	private const uint ERROR_SUCCESS = 0x00000000;
	private const uint PDH_FMT_DOUBLE = 0x00000200;

	// The English (locale independent) counter path of the machine wide processor utilization.
	private const string CpuUsageCounterPath = @"\Processor Information(_Total)\% Processor Time";

	private IntPtr _cpuUsageQuery;
	private IntPtr _cpuUsageCounter;
	private TemperatureSampler? _temperatureSampler;
	private bool _disposed;

	internal PerformanceMetricsSampler()
	{
		InitializeCpuUsageCounters();

		try
		{
			// Devices without ACPI thermal zones (most virtual machines) simply yield no data, which is not an error condition.
			_temperatureSampler = new TemperatureSampler();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// Reads every metric once. It never throws; unavailable metrics are reported as NaN/zero.
	/// </summary>
	/// <param name="includeStorageTemperature">
	/// Whether the disk temperature has to be sampled as well. It is only displayed on the medium and the large widget,
	/// so scanning the physical drives is skipped entirely when none of the visible widgets shows it.
	/// </param>
	internal PerformanceSnapshot Sample(bool includeStorageTemperature)
	{
		ulong usedPhysicalBytes = SampleUsedPhysicalBytes(out ulong totalPhysicalBytes);

		return new PerformanceSnapshot(
			SampleCpuTemperature(),
			SampleCpuUsage(),
			usedPhysicalBytes,
			totalPhysicalBytes,
			includeStorageTemperature ? SampleStorageTemperature() : double.NaN);
	}

	private void InitializeCpuUsageCounters()
	{
		uint status = NativeMethods.PdhOpenQueryW(null, 0U, out _cpuUsageQuery);
		if (status != ERROR_SUCCESS || _cpuUsageQuery == IntPtr.Zero)
		{
			_cpuUsageQuery = IntPtr.Zero;
			return;
		}

		status = NativeMethods.PdhAddEnglishCounterW(_cpuUsageQuery, CpuUsageCounterPath, 0U, out _cpuUsageCounter);
		if (status != ERROR_SUCCESS || _cpuUsageCounter == IntPtr.Zero)
		{
			CloseCpuUsageCounters();
			return;
		}

		// Priming collection so that the very first real sample already has a baseline to compare against.
		_ = NativeMethods.PdhCollectQueryData(_cpuUsageQuery);
	}

	private double SampleCpuTemperature()
	{
		if (_temperatureSampler is null)
		{
			return double.NaN;
		}

		try
		{
			return _temperatureSampler.SampleCelsiusOneShot();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return double.NaN;
		}
	}

	private double SampleCpuUsage()
	{
		if (_cpuUsageQuery == IntPtr.Zero || _cpuUsageCounter == IntPtr.Zero)
		{
			return double.NaN;
		}

		if (NativeMethods.PdhCollectQueryData(_cpuUsageQuery) != ERROR_SUCCESS)
		{
			return double.NaN;
		}

		uint status = NativeMethods.PdhGetFormattedCounterValue(_cpuUsageCounter, PDH_FMT_DOUBLE, out uint _, out PDH_FMT_COUNTERVALUE_DOUBLE counterValue);
		if (status != ERROR_SUCCESS || counterValue.CStatus != ERROR_SUCCESS)
		{
			return double.NaN;
		}

		return Math.Clamp(counterValue.Value, 0.0, 100.0);
	}

	/// <summary>
	/// Returns the temperature of the hottest physical drive, which is exactly the value that the Home page of the app
	/// and its system intelligence graphs plot, so that both surfaces always agree on the same number.
	/// </summary>
	private static double SampleStorageTemperature()
	{
		try
		{
			List<int> temperatures = StorageTemperature.GetDriveTemperatures();

			if (temperatures.Count == 0)
			{
				return double.NaN;
			}

			int hottestTemperature = temperatures[0];

			for (int index = 1; index < temperatures.Count; index++)
			{
				int temperature = temperatures[index];

				if (temperature > hottestTemperature)
				{
					hottestTemperature = temperature;
				}
			}

			return hottestTemperature;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return double.NaN;
		}
	}

	private static ulong SampleUsedPhysicalBytes(out ulong totalPhysicalBytes)
	{
		MEMORYSTATUSEX memoryStatus = default;
		memoryStatus.dwLength = (uint)Unsafe.SizeOf<MEMORYSTATUSEX>();

		if (!NativeMethods.GlobalMemoryStatusEx(ref memoryStatus) || memoryStatus.ullTotalPhys == 0UL)
		{
			totalPhysicalBytes = 0UL;
			return 0UL;
		}

		totalPhysicalBytes = memoryStatus.ullTotalPhys;

		// The available amount can momentarily be reported higher than the total, so it is clamped before the subtraction.
		ulong availablePhysicalBytes = Math.Min(memoryStatus.ullAvailPhys, memoryStatus.ullTotalPhys);
		return memoryStatus.ullTotalPhys - availablePhysicalBytes;
	}

	private void CloseCpuUsageCounters()
	{
		if (_cpuUsageCounter != IntPtr.Zero)
		{
			_ = NativeMethods.PdhRemoveCounter(_cpuUsageCounter);
			_cpuUsageCounter = IntPtr.Zero;
		}

		if (_cpuUsageQuery != IntPtr.Zero)
		{
			_ = NativeMethods.PdhCloseQuery(_cpuUsageQuery);
			_cpuUsageQuery = IntPtr.Zero;
		}
	}

	public void Dispose()
	{
		if (_disposed)
			return;

		_disposed = true;

		CloseCpuUsageCounters();

		_temperatureSampler?.Dispose();
		_temperatureSampler = null;
	}
}
