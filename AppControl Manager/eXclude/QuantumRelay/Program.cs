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
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace QuantumRelay;

internal sealed class Program
{
	internal static async Task Main(string[] args)
	{
		try
		{
			HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);

			_ = builder.Services.AddWindowsService(options =>
			{
				options.ServiceName = "QuantumRelay";
			});

			_ = builder.Services.AddSingleton<CommandProcessor>();
			_ = builder.Services.AddSingleton<NamedPipeServer>();
			_ = builder.Services.AddHostedService<WindowsServiceHost>();

			using IHost host = builder.Build();
			await host.RunAsync();
		}
		catch (Exception ex)
		{
			try
			{
				EventLog.WriteEntry(WindowsServiceHost.EventLogSource,
					$"QuantumRelay Fatal error starting service: {ex.Message}\n{ex.StackTrace}",
					EventLogEntryType.Error);
			}
			catch
			{
				// Ignore event log errors
			}
			Environment.Exit(1);
		}
	}
}
