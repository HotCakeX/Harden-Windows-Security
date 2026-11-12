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

using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace HardenSystemSecurity.DNS;

/// <summary>
/// Owns the single Tor process that every Tor based feature of the DNS page shares:
/// the Tor outbound route of the Smart DNS, the DNS over HTTPS server and the DNS server.
/// </summary>
internal static class TorSessionManager
{
	/// <summary>
	/// The local TCP port of Tor's SOCKS5 proxy.
	/// </summary>
	internal const int SocksPort = 19051;

	/// <summary>
	/// The local UDP port on which Tor resolves A, AAAA and PTR queries.
	/// </summary>
	internal const int DnsPort = 19053;

	private static readonly TimeSpan BootstrapTimeout = TimeSpan.FromMinutes(10);
	private static readonly SemaphoreSlim InitializationLock = new(1, 1);
	private static readonly Lock SessionLock = new();
	private static Action<string>? LogSink;
	private static TorProcessSession? ActiveSession;
	private static int ShutdownGeneration;

	/// <summary>
	/// Whether Tor finished bootstrapping and its process is still running.
	/// </summary>
	internal static bool IsReady
	{
		get
		{
			lock (SessionLock)
			{
				return ActiveSession is not null && !ActiveSession.HasExited;
			}
		}
	}

	/// <summary>
	/// Starts Tor and waits until it is connected to the Tor network. Does nothing when Tor is already ready.
	/// </summary>
	internal static async Task InitializeAsync(Action<string> logSink, string bundlePath, TorConnectionMethod connectionMethod, CancellationToken cancellationToken)
	{
		LogSink = logSink;
		await InitializationLock.WaitAsync(cancellationToken);
		try
		{
			TorProcessSession? previousSession;
			int shutdownGeneration;
			bool isReady;
			lock (SessionLock)
			{
				isReady = ActiveSession is not null && !ActiveSession.HasExited;
				previousSession = isReady ? null : ActiveSession;
				if (!isReady)
				{
					ActiveSession = null;
				}
				shutdownGeneration = ShutdownGeneration;
			}
			if (isReady)
			{
				WriteLine($"TOR ALREADY READY socks=127.0.0.1:{SocksPort} dns=127.0.0.1:{DnsPort}");
				return;
			}
			previousSession?.Dispose();

			// The new session is disposed by the finally block unless it is published as the active session.
			TorProcessSession? newSession = await TorProcessSession.StartAsync(
				bundlePath,
				SocksPort,
				DnsPort,
				"HardenSystemSecurity-Tor",
				BootstrapTimeout,
				WriteLine,
				connectionMethod,
				cancellationToken);
			try
			{
				cancellationToken.ThrowIfCancellationRequested();
				bool sessionPublished;
				lock (SessionLock)
				{
					sessionPublished = shutdownGeneration == ShutdownGeneration;
					if (sessionPublished)
					{
						ActiveSession = newSession;
						newSession = null;
					}
				}
				if (!sessionPublished)
				{
					throw new OperationCanceledException("Tor initialization completed after shutdown was requested.", cancellationToken);
				}
			}
			finally
			{
				newSession?.Dispose();
			}
			WriteLine($"TOR READY socks=127.0.0.1:{SocksPort} dns=127.0.0.1:{DnsPort}");
		}
		finally
		{
			_ = InitializationLock.Release();
		}
	}

	/// <summary>
	/// Stops Tor. An initialization that is still in progress does not publish its session afterwards.
	/// </summary>
	internal static void Shutdown()
	{
		TorProcessSession? session;
		lock (SessionLock)
		{
			ShutdownGeneration++;
			session = ActiveSession;
			ActiveSession = null;
		}
		if (session is null)
		{
			return;
		}
		session.Dispose();
		WriteLine("TOR STOPPED");
	}

	private static void WriteLine(string message) => LogSink?.Invoke($"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz}] {message}");
}

internal sealed partial class TorProcessSession(Process process, string dataDirectory, Action<string> writeLine) : IDisposable
{
	private Process Process => process;
	private string DataDirectory => dataDirectory;
	private Action<string> WriteLine => writeLine;
	private int Disposed;
	internal bool HasExited => Process.HasExited;

	internal static async Task<TorProcessSession> StartAsync(
		string? bundlePath,
		int socksPort,
		int dnsPort,
		string dataDirectoryPrefix,
		TimeSpan bootstrapTimeout,
		Action<string> writeLine,
		TorConnectionMethod torConnectionMethod,
		CancellationToken cancellationToken)
	{
		if (string.IsNullOrWhiteSpace(bundlePath))
		{
			throw new InvalidOperationException("Select the Tor Expert Bundle folder before starting.");
		}
		string root = Path.GetFullPath(bundlePath);
		string executablePath = Path.Join(root, "tor", "tor.exe");
		string geoIpPath = Path.Join(root, "data", "geoip");
		string geoIp6Path = Path.Join(root, "data", "geoip6");
		if (!File.Exists(executablePath) || !File.Exists(geoIpPath) || !File.Exists(geoIp6Path))
		{
			throw new FileNotFoundException("The selected folder is not a complete Tor Expert Bundle.", executablePath);
		}
		string dataDirectory = Path.Join(Path.GetTempPath(), $"{dataDirectoryPrefix}-{Environment.ProcessId}");
		_ = Directory.CreateDirectory(dataDirectory);
		ProcessStartInfo startInfo = new(executablePath)
		{
			UseShellExecute = false,
			CreateNoWindow = true,
			RedirectStandardOutput = true,
			RedirectStandardError = true
		};
		startInfo.ArgumentList.Add("--DataDirectory");
		startInfo.ArgumentList.Add(dataDirectory);
		startInfo.ArgumentList.Add("--SocksPort");
		startInfo.ArgumentList.Add($"127.0.0.1:{socksPort}");

		// Tor answers A, AAAA and PTR queries that arrive on this local UDP port by resolving them through the Tor network.
		startInfo.ArgumentList.Add("--DNSPort");
		startInfo.ArgumentList.Add($"127.0.0.1:{dnsPort}");
		startInfo.ArgumentList.Add("--GeoIPFile");
		startInfo.ArgumentList.Add(geoIpPath);
		startInfo.ArgumentList.Add("--GeoIPv6File");
		startInfo.ArgumentList.Add(geoIp6Path);
		startInfo.ArgumentList.Add("--ClientOnly");
		startInfo.ArgumentList.Add("1");
		startInfo.ArgumentList.Add("--Log");
		startInfo.ArgumentList.Add("notice stdout");
		// Tor periodically checks this process and exits when it's gone, so tor.exe never outlives the app,
		// even when the app crashes or is terminated before the session can be disposed.
		startInfo.ArgumentList.Add("--__OwningControllerProcess");
		startInfo.ArgumentList.Add(Environment.ProcessId.ToString(CultureInfo.InvariantCulture));
		ConfigurePluggableTransport(startInfo, root, torConnectionMethod);
		// The process is owned by the session as soon as it starts, and the session is disposed by the
		// finally block unless bootstrapping completes and it is returned to the caller.
		TorProcessSession? session;
#pragma warning disable CA2000 // Disposed in the catch block below or by the session that takes ownership of it.
		Process process = new() { StartInfo = startInfo, EnableRaisingEvents = true };
#pragma warning restore CA2000
		try
		{
			if (!process.Start())
			{
				throw new InvalidOperationException("Tor could not be started.");
			}
			session = new(process, dataDirectory, writeLine);
		}
		catch
		{
			process.Dispose();
			throw;
		}
		using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
		try
		{
			timeout.CancelAfter(bootstrapTimeout);
			Task errorTask = session.ForwardErrorsAsync();
			while (true)
			{
				string? line = await process.StandardOutput.ReadLineAsync(timeout.Token);
				if (line is null)
				{
					await errorTask;

					// The standard output closes slightly before the process finishes exiting, and reading
					// ExitCode before the exit completes throws, so the exit is awaited first.
					await process.WaitForExitAsync(timeout.Token);
					throw new InvalidOperationException($"Tor exited before bootstrapping completed. Exit code: {process.ExitCode}.");
				}
				writeLine($"TOR {line}");
				if (line.Contains("Bootstrapped 100%", StringComparison.OrdinalIgnoreCase))
				{
					_ = session.ForwardOutputAsync();
					TorProcessSession readySession = session;
					session = null;
					return readySession;
				}
			}
		}
		catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
		{
			// The bootstrap timeout elapsed; it is reported as a timeout instead of a user cancellation.
			throw new TimeoutException($"Tor did not finish bootstrapping within {bootstrapTimeout.TotalMinutes:F0} minutes.");
		}
		finally
		{
			session?.Dispose();
		}
	}

	private static void ConfigurePluggableTransport(ProcessStartInfo startInfo, string root, TorConnectionMethod connectionMethod)
	{
		if (connectionMethod == TorConnectionMethod.Direct)
		{
			return;
		}
		string pluggableTransportsPath = Path.Join(root, "tor", "pluggable_transports");
		string configurationPath = Path.Join(pluggableTransportsPath, "pt_config.json");
		string lyrebirdPath = Path.Join(pluggableTransportsPath, "lyrebird.exe");
		if (!File.Exists(configurationPath) || !File.Exists(lyrebirdPath))
		{
			throw new FileNotFoundException("The selected Tor Expert Bundle does not contain the required Lyrebird files.", configurationPath);
		}
		string bridgeName = connectionMethod switch
		{
			TorConnectionMethod.Obfs4 => "obfs4",
			TorConnectionMethod.Snowflake => "snowflake",
			TorConnectionMethod.Meek => "meek",
			_ => throw new InvalidOperationException("The selected Tor connection method is invalid.")
		};
		using FileStream configurationStream = File.OpenRead(configurationPath);
		using JsonDocument configuration = JsonDocument.Parse(configurationStream);
		JsonElement rootElement = configuration.RootElement;
		if (!rootElement.TryGetProperty("bridges", out JsonElement bridgesElement) ||
			!bridgesElement.TryGetProperty(bridgeName, out JsonElement selectedBridges) ||
			selectedBridges.ValueKind != JsonValueKind.Array ||
			selectedBridges.GetArrayLength() == 0)
		{
			throw new InvalidOperationException($"The selected Tor Expert Bundle does not provide built-in {bridgeName} bridges.");
		}
		string transportName = connectionMethod == TorConnectionMethod.Meek ? "meek_lite" : bridgeName;
		startInfo.ArgumentList.Add("--UseBridges");
		startInfo.ArgumentList.Add("1");
		startInfo.ArgumentList.Add("--ClientTransportPlugin");
		startInfo.ArgumentList.Add($"{transportName} exec {lyrebirdPath}");
		foreach (JsonElement bridgeElement in selectedBridges.EnumerateArray())
		{
			string? bridge = bridgeElement.GetString();
			if (string.IsNullOrWhiteSpace(bridge))
			{
				throw new InvalidDataException($"The built-in {bridgeName} bridge configuration is invalid.");
			}
			startInfo.ArgumentList.Add("--Bridge");
			startInfo.ArgumentList.Add(bridge);
		}
	}
	private async Task ForwardOutputAsync()
	{
		while (await Process.StandardOutput.ReadLineAsync() is string line)
		{
			WriteLine($"TOR {line}");
		}
	}

	private async Task ForwardErrorsAsync()
	{
		while (await Process.StandardError.ReadLineAsync() is string line)
		{
			WriteLine($"TOR ERROR {line}");
		}
	}

	public void Dispose()
	{
		if (Interlocked.Exchange(ref Disposed, 1) != 0)
		{
			return;
		}
		try
		{
			if (!Process.HasExited)
			{
				Process.Kill(true);
				Process.WaitForExit();
			}
		}
		catch (Exception exception) when (exception is InvalidOperationException or Win32Exception)
		{
			// The process exited on its own between the HasExited check and Kill.
		}
		finally
		{
			Process.Dispose();
			try
			{
				Directory.Delete(DataDirectory, true);
			}
			catch { }
		}
	}
}

/// <summary>
/// How Tor connects to the Tor network. The bridge-based methods use the pluggable transports included in the Tor Expert Bundle.
/// </summary>
internal enum TorConnectionMethod
{
	Direct,
	Obfs4,
	Snowflake,
	Meek
}
internal static class Socks5Protocol
{
	private static readonly byte[] NoAuthenticationNegotiationRequest = [5, 1, 0];

	internal static ValueTask WriteNoAuthenticationNegotiationAsync(Stream stream, CancellationToken cancellationToken)
		=> stream.WriteAsync(NoAuthenticationNegotiationRequest, cancellationToken);

	internal static bool TryCreateDomainConnectRequest(string host, int port, out byte[] request)
	{
		int hostByteCount = Encoding.ASCII.GetByteCount(host);
		if (hostByteCount is 0 or > byte.MaxValue)
		{
			request = [];
			return false;
		}
		request = new byte[7 + hostByteCount];
		request[0] = 5;
		request[1] = 1;
		request[2] = 0;
		request[3] = 3;
		request[4] = checked((byte)hostByteCount);
		_ = Encoding.ASCII.GetBytes(host, request.AsSpan(5, hostByteCount));
		BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(5 + hostByteCount, 2), checked((ushort)port));
		return true;
	}
}
