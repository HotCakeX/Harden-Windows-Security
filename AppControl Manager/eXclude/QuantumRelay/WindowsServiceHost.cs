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
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

#pragma warning disable CA1812

namespace QuantumRelay;

internal sealed class WindowsServiceHost(IServiceProvider serviceProvider) : BackgroundService
{
	internal const string EventLogSource = "QuantumRelay";
	private readonly IServiceProvider _serviceProvider = serviceProvider;
	private NamedPipeServer? _pipeServer;

	static WindowsServiceHost()
	{
		// Create the custom event source if it doesn't exist
		try
		{
			if (!EventLog.SourceExists(EventLogSource))
			{
				EventLog.CreateEventSource(EventLogSource, "Application");
			}
		}
		catch
		{
			// Ignore errors during event source creation
			// Will fall back to default behavior
		}
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		try
		{
			_pipeServer = _serviceProvider.GetRequiredService<NamedPipeServer>();
			await _pipeServer.StartAsync(stoppingToken);
		}
		catch (Exception ex)
		{
			try
			{
				EventLog.WriteEntry(EventLogSource,
					$"QuantumRelay Service startup failed: {ex.Message}\n{ex.StackTrace}",
					EventLogEntryType.Error);
			}
			catch { }
			throw;
		}
	}

	public override async Task StopAsync(CancellationToken cancellationToken)
	{
		try
		{
			if (_pipeServer != null)
			{
				await _pipeServer.StopAsync();
			}
		}
		catch (Exception ex)
		{
			try
			{
				EventLog.WriteEntry(EventLogSource,
					$"QuantumRelay Service shutdown error: {ex.Message}",
					EventLogEntryType.Error);
			}
			catch { }
		}
		finally
		{
			await base.StopAsync(cancellationToken);
		}
	}

	public override void Dispose()
	{
		try
		{
			_pipeServer?.Dispose();
		}
		catch (Exception ex)
		{
			try
			{
				EventLog.WriteEntry(EventLogSource,
					$"QuantumRelay Service dispose error: {ex.Message}",
					EventLogEntryType.Error);
			}
			catch { }
		}
		finally
		{
			base.Dispose();
		}
	}
}
