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
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;

namespace HardenSystemSecurity.CustomUIElements.WindowsTopBar;

/// <summary>
/// A single immutable network quality reading produced by <see cref="TopBarNetworkQualitySampler"/>.
/// </summary>
internal readonly struct TopBarNetworkQualitySnapshot(
	long currentRoundtripMilliseconds,
	double averageRoundtripMilliseconds,
	double jitterMilliseconds,
	double packetLossPercent,
	long minimumRoundtripMilliseconds,
	long maximumRoundtripMilliseconds,
	bool succeeded)
{
	internal long CurrentRoundtripMilliseconds => currentRoundtripMilliseconds;
	internal double AverageRoundtripMilliseconds => averageRoundtripMilliseconds;
	internal double JitterMilliseconds => jitterMilliseconds;
	internal double PacketLossPercent => packetLossPercent;
	internal long MinimumRoundtripMilliseconds => minimumRoundtripMilliseconds;
	internal long MaximumRoundtripMilliseconds => maximumRoundtripMilliseconds;
	internal bool Succeeded => succeeded;
}

/// <summary>
/// Sends one cancellable ICMP echo at a time and keeps only the bounded history required by the Top Bar graph.
/// </summary>
internal sealed partial class TopBarNetworkQualitySampler : IDisposable
{
	private const int HistoryCapacity = 24;
	private static readonly TimeSpan PingTimeout = TimeSpan.FromSeconds(2.0);
	private readonly Ping _ping = new();
	private readonly Queue<long?> _history = new(HistoryCapacity);
	private long _successfulRoundtripTotal;
	private long _minimumRoundtripMilliseconds = long.MaxValue;
	private long _maximumRoundtripMilliseconds;
	private long _previousSuccessfulRoundtripMilliseconds;
	private double _jitterTotal;
	private int _attemptCount;
	private int _successCount;
	private int _jitterSampleCount;
	private bool _hasPreviousSuccessfulRoundtrip;
	private bool _disposed;

	internal IReadOnlyCollection<long?> History => _history;

	internal async Task<TopBarNetworkQualitySnapshot> SampleAsync(string destination, CancellationToken cancellationToken)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		PingReply? reply = null;
		try
		{
			reply = await _ping.SendPingAsync(destination, PingTimeout, null, null, cancellationToken);
		}
		catch (PingException)
		{
			// A failed DNS lookup or ICMP operation is represented as a lost packet.
		}

		cancellationToken.ThrowIfCancellationRequested();
		_attemptCount++;
		bool succeeded = reply?.Status == IPStatus.Success;
		long currentRoundtripMilliseconds = succeeded ? reply!.RoundtripTime : -1L;
		AddHistory(succeeded ? currentRoundtripMilliseconds : null);

		if (succeeded)
		{
			_successCount++;
			_successfulRoundtripTotal += currentRoundtripMilliseconds;
			_minimumRoundtripMilliseconds = Math.Min(_minimumRoundtripMilliseconds, currentRoundtripMilliseconds);
			_maximumRoundtripMilliseconds = Math.Max(_maximumRoundtripMilliseconds, currentRoundtripMilliseconds);
			if (_hasPreviousSuccessfulRoundtrip)
			{
				_jitterTotal += Math.Abs(currentRoundtripMilliseconds - _previousSuccessfulRoundtripMilliseconds);
				_jitterSampleCount++;
			}
			_previousSuccessfulRoundtripMilliseconds = currentRoundtripMilliseconds;
			_hasPreviousSuccessfulRoundtrip = true;
		}

		double average = _successCount > 0 ? _successfulRoundtripTotal / (double)_successCount : double.NaN;
		double jitter = _jitterSampleCount > 0 ? _jitterTotal / _jitterSampleCount : double.NaN;
		double packetLoss = _attemptCount > 0 ? (_attemptCount - _successCount) * 100.0 / _attemptCount : 0.0;
		return new TopBarNetworkQualitySnapshot(
			currentRoundtripMilliseconds,
			average,
			jitter,
			packetLoss,
			_successCount > 0 ? _minimumRoundtripMilliseconds : -1L,
			_successCount > 0 ? _maximumRoundtripMilliseconds : -1L,
			succeeded);
	}

	private void AddHistory(long? roundtripMilliseconds)
	{
		if (_history.Count == HistoryCapacity)
		{
			_ = _history.Dequeue();
		}
		_history.Enqueue(roundtripMilliseconds);
	}

	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}
		_disposed = true;
		_ping.Dispose();
		_history.Clear();
	}
}
