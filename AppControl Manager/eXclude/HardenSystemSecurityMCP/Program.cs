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
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace HardenSystemSecurityMCP;

internal static class Program
{
	private static async Task Main()
	{
		ProcessStartInfo startInfo = new("HSS.exe")
		{
			UseShellExecute = false,
			CreateNoWindow = true,
			RedirectStandardInput = true,
			RedirectStandardOutput = true,
			RedirectStandardError = true
		};
		startInfo.ArgumentList.Add("--mcp");

		using Process host = Process.Start(startInfo) ?? throw new InvalidOperationException("Harden System Security could not be started.");
		using Stream input = Console.OpenStandardInput();
		using Stream output = Console.OpenStandardOutput();
		using Stream error = Console.OpenStandardError();

		await RelayAsync(host, input, output, error).ConfigureAwait(false);
	}

	private static async Task RelayAsync(Process host, Stream input, Stream output, Stream error)
	{
		using CancellationTokenSource inputCancellation = new();
		Task inputRelay = RelayInputAsync(input, host.StandardInput.BaseStream, inputCancellation.Token);
		Task outputRelay = host.StandardOutput.BaseStream.CopyToAsync(output);
		Task errorRelay = host.StandardError.BaseStream.CopyToAsync(error);
		Task hostExit = host.WaitForExitAsync();

		Task completed = await Task.WhenAny(inputRelay, hostExit).ConfigureAwait(false);
		if (ReferenceEquals(completed, hostExit))
		{
			await inputCancellation.CancelAsync();
		}

		try
		{
			await inputRelay.ConfigureAwait(false);
		}
		catch (OperationCanceledException) when (inputCancellation.IsCancellationRequested)
		{
		}

		await hostExit.ConfigureAwait(false);
		await Task.WhenAll(outputRelay, errorRelay).ConfigureAwait(false);
	}

	private static async Task RelayInputAsync(Stream source, Stream destination, CancellationToken cancellationToken)
	{
		try
		{
			await source.CopyToAsync(destination, cancellationToken).ConfigureAwait(false);
		}
		finally
		{
			await destination.DisposeAsync().ConfigureAwait(false);
		}
	}
}
