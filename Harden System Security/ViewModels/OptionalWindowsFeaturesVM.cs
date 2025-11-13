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

using System.Collections.Frozen;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using CommonCore.DISM;
using CommunityToolkit.WinUI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class DismServiceClient : IDisposable
{

	/// <summary>
	/// Find all processes with the name "DISMService" and terminates them.
	/// </summary>
	private void ForceKillExistingProcesses()
	{
		try
		{

			Process[] processes = Process.GetProcessesByName("DISMService");

			foreach (Process process in processes)
			{
				try
				{
					LogReceived?.Invoke(string.Format(GlobalVars.GetStr("FoundExistingDISMServiceProcess"), process.Id), LogTypeIntel.Information);

					if (!process.HasExited)
					{
						process.Kill();
						_ = process.WaitForExit(2000);
					}

					LogReceived?.Invoke(string.Format(GlobalVars.GetStr("SuccessfullyTerminatedDISMServiceProcess"), process.Id), LogTypeIntel.Information);
				}
				catch (Exception ex)
				{
					LogReceived?.Invoke(string.Format(GlobalVars.GetStr("FailedToTerminateDISMServiceProcess"), process.Id, ex.Message), LogTypeIntel.Warning);
				}
				finally
				{
					process.Dispose();
				}
			}

			// Give the system a moment to release file handles
			if (processes.Length > 0)
			{
				System.Threading.Thread.Sleep(500);
			}
		}
		catch (Exception ex)
		{
			LogReceived?.Invoke(string.Format(GlobalVars.GetStr("ErrorCheckingExistingDISMServiceProcesses"), ex.Message), LogTypeIntel.Warning);
		}
	}

	private readonly string DISMServiceLocationInPackage = Path.Combine(AppContext.BaseDirectory, "DISMService.exe");

	private string DISMFileHash = string.Empty;

	/// <summary>
	/// The file or directory will not be visible in the file explorer because of file virtualization and we can keep it this way.
	/// https://learn.microsoft.com/windows/msix/desktop/flexible-virtualization
	/// </summary>
	private static readonly string SecureDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
		"HardenSystemSecurity", "DISMService");

	internal static readonly string SecureDISMServicePath = Path.Combine(SecureDirectory, "DISMService.exe");

	/// <summary>
	/// Hash the file and then copy it to the destination.
	/// </summary>
	internal void SecureCopyFile()
	{
		const int bufferSize = 4096 * 1024;

		using (FileStream sourceStreamPrior = new(DISMServiceLocationInPackage, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize))
		{
			using SHA256 sha256 = SHA256.Create();
			byte[] hashBytes = sha256.ComputeHash(sourceStreamPrior);
			DISMFileHash = Convert.ToHexString(hashBytes);
		}

		if (Directory.Exists(SecureDirectory))
		{
			ForceKillExistingProcesses();
			Directory.Delete(SecureDirectory, true);
		}
		_ = Directory.CreateDirectory(SecureDirectory);

		using FileStream sourceStream = new(DISMServiceLocationInPackage, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize);
		using FileStream destinationStream = new(SecureDISMServicePath, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize);

		sourceStream.CopyTo(destinationStream);
		destinationStream.Flush();
	}

	/// <summary>
	/// Verify the integrity of the DISM service executable by comparing its current hash with the stored hash.
	/// </summary>
	/// <returns>True if the file integrity is verified, false if tampered or missing.</returns>
	private async Task<bool> VerifyDISMServiceIntegrity()
	{
		try
		{
			bool isValid = await Task.Run(() =>
			{
				if (!File.Exists(SecureDISMServicePath))
				{
					return false;
				}

				if (string.IsNullOrEmpty(DISMFileHash))
				{
					return false;
				}

				const int bufferSize = 4096 * 1024;

				using FileStream fileStream = new(SecureDISMServicePath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize);
				using SHA256 sha256 = SHA256.Create();
				byte[] currentHashBytes = sha256.ComputeHash(fileStream);
				string currentHash = Convert.ToHexString(currentHashBytes);

				return string.Equals(currentHash, DISMFileHash, StringComparison.OrdinalIgnoreCase);
			});

			if (!isValid)
			{
				LogReceived?.Invoke(GlobalVars.GetStr("DISMServiceFileIntegrityCheckFailed"), LogTypeIntel.Error);
			}

			return isValid;
		}
		catch (Exception ex)
		{
			LogReceived?.Invoke(string.Format(GlobalVars.GetStr("FailedToVerifyDISMServiceIntegrity"), ex.Message), LogTypeIntel.Error);
			return false;
		}
	}

	private IntPtr _processHandle = IntPtr.Zero;
	private NamedPipeClientStream? _pipeClient;
	private BinaryWriter? _writer;
	private BinaryReader? _reader;
	private readonly string _pipeName;
	private bool _disposed;

	internal event Action<string, LogTypeIntel>? LogReceived;
	internal event Action<string, uint, uint>? ItemProgressUpdated;

	// To track the active service for termination
	internal static DismServiceClient? ActiveInstance { get; private set; }

	internal DismServiceClient(string? customPipeName = null)
	{
		_pipeName = customPipeName ?? $"DismService_{Guid.NewGuid():N}";
		ActiveInstance = this;
	}

	private const uint DETACHED_PROCESS = 0x00000008;
	private const uint CREATE_NO_WINDOW = 0x08000000;

	internal async Task<bool> StartServiceAsync(string serviceExecutablePath)
	{
		try
		{
			if (!await VerifyDISMServiceIntegrity())
			{
				LogReceived?.Invoke(GlobalVars.GetStr("DISMServiceFileIntegrityVerificationFailed"), LogTypeIntel.Error);
				return false;
			}


			IntPtr desktopPtr = Marshal.StringToHGlobalUni("");
			IntPtr titlePtr = Marshal.StringToHGlobalUni("");

			try
			{
				return await Task.Run(async () =>
				{

					STARTUPINFO startupInfo = default;

					unsafe
					{
						startupInfo.cb = (uint)sizeof(STARTUPINFO);
					}

					startupInfo.lpReserved = IntPtr.Zero;
					startupInfo.lpDesktop = desktopPtr;
					startupInfo.lpTitle = titlePtr;
					startupInfo.dwFlags = 0;
					startupInfo.wShowWindow = 0;
					startupInfo.cbReserved2 = 0;
					startupInfo.lpReserved2 = IntPtr.Zero;
					startupInfo.hStdInput = IntPtr.Zero;
					startupInfo.hStdOutput = IntPtr.Zero;
					startupInfo.hStdError = IntPtr.Zero;

					string commandLine = $"\"{serviceExecutablePath}\" {_pipeName}";

					bool success = NativeMethods.CreateProcessW(
						null,
						commandLine,
						IntPtr.Zero,
						IntPtr.Zero,
						false,
						CREATE_NO_WINDOW | DETACHED_PROCESS,
						IntPtr.Zero,
						null,
						ref startupInfo,
						out PROCESS_INFORMATION processInfo);

					if (!success)
					{
						int error = Marshal.GetLastPInvokeError();
						LogReceived?.Invoke(string.Format(GlobalVars.GetStr("FailedToCreateProcessWin32Error"), error), LogTypeIntel.Error);
						return false;
					}

					_processHandle = processInfo.hProcess;

					_ = NativeMethods.CloseHandle(processInfo.hThread);

					_pipeClient = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut,
						PipeOptions.Asynchronous, System.Security.Principal.TokenImpersonationLevel.None);
					await _pipeClient.ConnectAsync(10000); // 10 second timeout

					// Set buffer sizes after connection
					_pipeClient.ReadMode = PipeTransmissionMode.Byte;

					_writer = new BinaryWriter(_pipeClient);
					_reader = new BinaryReader(_pipeClient);

					return true;

				});
			}
			finally
			{
				if (desktopPtr != IntPtr.Zero)
					Marshal.FreeHGlobal(desktopPtr);
				if (titlePtr != IntPtr.Zero)
					Marshal.FreeHGlobal(titlePtr);
			}
		}
		catch (Exception ex)
		{
			LogReceived?.Invoke(string.Format(GlobalVars.GetStr("FailedToStartService"), ex.Message), LogTypeIntel.Error);
			return false;
		}
	}

	internal async Task<List<DISMOutput>> GetAllResultsAsync()
	{
		try
		{
			if (!await VerifyDISMServiceIntegrity()) return [];

			return await Task.Run(async () =>
			{
				_writer!.Write((byte)Command.GetAllResults);

				Response response = await WaitForResponse();

				if (response != Response.ResultsData)
					return [];

				return ReadChunkedResultsList();
			});
		}
		catch
		{
			return [];
		}
	}

	internal async Task<List<DISMOutput>> GetSpecificCapabilitiesAsync(string[] capabilityNames)
	{
		try
		{
			if (!await VerifyDISMServiceIntegrity()) return [];

			return await Task.Run(async () =>
			{

				_writer!.Write((byte)Command.GetSpecificCapabilities);
				_writer.Write(capabilityNames.Length);

				foreach (string name in capabilityNames)
				{
					WriteString(name);
				}

				Response response = await WaitForResponse();
				if (response != Response.ResultsData)
					return [];

				return ReadChunkedResultsList();
			});
		}
		catch
		{
			return [];
		}
	}

	internal async Task<List<DISMOutput>> GetSpecificFeaturesAsync(string[] featureNames)
	{
		try
		{
			if (!await VerifyDISMServiceIntegrity()) return [];

			return await Task.Run(async () =>
			{

				_writer!.Write((byte)Command.GetSpecificFeatures);
				_writer.Write(featureNames.Length);

				foreach (string name in featureNames)
				{
					WriteString(name);
				}

				Response response = await WaitForResponse();
				if (response != Response.ResultsData)
					return [];

				return ReadChunkedResultsList();
			});
		}
		catch
		{
			return [];
		}
	}

	internal async Task<bool> AddCapabilityAsync(string capabilityName, bool limitAccess = false, string[]? sourcePaths = null)
	{
		try
		{
			if (!await VerifyDISMServiceIntegrity()) return false;

			_writer!.Write((byte)Command.AddCapability);
			WriteString(capabilityName);
			_writer.Write(limitAccess);

			if (sourcePaths != null)
			{
				_writer.Write(sourcePaths.Length);
				foreach (string path in sourcePaths)
				{
					WriteString(path);
				}
			}
			else
			{
				_writer.Write(0);
			}

			return await WaitForOperationComplete();
		}
		catch
		{
			return false;
		}
	}

	internal async Task<bool> RemoveCapabilityAsync(string capabilityName)
	{
		try
		{
			if (!await VerifyDISMServiceIntegrity()) return false;

			_writer!.Write((byte)Command.RemoveCapability);
			WriteString(capabilityName);

			return await WaitForOperationComplete();
		}
		catch
		{
			return false;
		}
	}

	internal async Task<bool> EnableFeatureAsync(string featureName, string[]? sourcePaths = null)
	{
		try
		{
			if (!await VerifyDISMServiceIntegrity()) return false;

			_writer!.Write((byte)Command.EnableFeature);
			WriteString(featureName);

			if (sourcePaths != null)
			{
				_writer.Write(sourcePaths.Length);
				foreach (string path in sourcePaths)
				{
					WriteString(path);
				}
			}
			else
			{
				_writer.Write(0);
			}

			return await WaitForOperationComplete();
		}
		catch
		{
			return false;
		}
	}

	internal async Task<bool> DisableFeatureAsync(string featureName)
	{
		try
		{
			if (!await VerifyDISMServiceIntegrity()) return false;

			_writer!.Write((byte)Command.DisableFeature);
			WriteString(featureName);

			return await WaitForOperationComplete();
		}
		catch
		{
			return false;
		}
	}

	internal async Task ShutdownAsync()
	{
		try
		{
			if (!await VerifyDISMServiceIntegrity()) return;

			_writer!.Write((byte)Command.Shutdown);
			_ = await WaitForResponse();
		}
		catch { }
	}

	/// <summary>
	/// Terminate the active DISM service from anywhere in the application, used in the App class when app is shutting down.
	/// </summary>
	internal static void TerminateActiveService()
	{
		try
		{
			ActiveInstance?.Dispose();
			ActiveInstance = null;

			if (Directory.Exists(SecureDirectory))
			{
				Directory.Delete(SecureDirectory, true);
			}
		}
		catch { }
	}

	private async Task<Response> WaitForResponse()
	{
		await Task.Yield();

		while (true)
		{
			Response response = (Response)_reader!.ReadByte();

			if (response == Response.Log)
			{
				string message = ReadString();
				LogTypeIntel logType = (LogTypeIntel)_reader.ReadInt32();
				LogReceived?.Invoke(message, logType);
				continue;
			}

			if (response == Response.ItemProgress)
			{
				string itemName = ReadString();
				uint current = _reader.ReadUInt32();
				uint total = _reader.ReadUInt32();
				ItemProgressUpdated?.Invoke(itemName, current, total);
				continue;
			}

			if (response == Response.Error)
			{
				string errorMessage = ReadString();
				LogReceived?.Invoke(string.Format(GlobalVars.GetStr("ServiceError"), errorMessage), LogTypeIntel.Error);
			}

			return response;
		}
	}

	private async Task<bool> WaitForOperationComplete()
	{
		Response response = await WaitForResponse();
		if (response != Response.OperationComplete)
			return false;

		return _reader!.ReadBoolean();
	}

	private List<DISMOutput> ReadChunkedResultsList()
	{
		int totalChunks = _reader!.ReadInt32();
		int totalCount = _reader.ReadInt32();
		List<DISMOutput> results = new(totalCount);

		for (int chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++)
		{
			_ = _reader.ReadInt32();
			int chunkSize = _reader.ReadInt32();

			for (int i = 0; i < chunkSize; i++)
			{
				string name = ReadString();
				DismPackageFeatureState state = (DismPackageFeatureState)_reader.ReadInt32();
				DISMResultType type = (DISMResultType)_reader.ReadInt32();
				string description = ReadString();

				results.Add(new DISMOutput(name, state, type, description));
			}
		}

		return results;
	}

	private void WriteString(string value)
	{
		byte[] bytes = Encoding.UTF8.GetBytes(value);
		_writer!.Write(bytes.Length);
		_writer.Write(bytes);
	}

	private string ReadString()
	{
		int length = _reader!.ReadInt32();
		byte[] bytes = _reader.ReadBytes(length);
		return Encoding.UTF8.GetString(bytes);
	}

	public void Dispose()
	{
		if (_disposed) return;
		_disposed = true;

		try
		{
			if (_writer != null && _pipeClient?.IsConnected == true)
			{
				_writer.Write((byte)Command.Exit);
			}
		}
		catch { }

		_writer?.Dispose();
		_reader?.Dispose();
		_pipeClient?.Dispose();

		try
		{
			if (_processHandle != IntPtr.Zero)
			{
				// Try to terminate the process gracefully first
				uint waitResult = NativeMethods.WaitForSingleObject(_processHandle, 1000); // Wait 1 second
				if (waitResult != 0) // If process is still running
				{
					if (!NativeMethods.TerminateProcess(_processHandle, 0))
					{
						int error = Marshal.GetLastPInvokeError();
						Logger.Write($"Failed terminating DISMService process: {error}", LogTypeIntel.Error);
					}
				}
				_ = NativeMethods.CloseHandle(_processHandle);
				_processHandle = IntPtr.Zero;
			}
		}
		catch { }

		if (ActiveInstance == this)
			ActiveInstance = null;
	}

	private enum Command : byte
	{
		GetAllResults = 1,
		GetSpecificCapabilities = 2,
		GetSpecificFeatures = 3,
		AddCapability = 4,
		RemoveCapability = 5,
		EnableFeature = 6,
		DisableFeature = 7,
		Shutdown = 8,
		Exit = 9
	}

	private enum Response : byte
	{
		ResultsData = 1,
		OperationComplete = 2,
		ShutdownComplete = 4,
		Log = 5,
		ItemProgress = 6,
		Error = 255
	}
}

/// <summary>
/// JSON source generation context for <see cref="DISMOutputEntry"/> serialization
/// </summary>
[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(DISMOutputEntry))]
[JsonSerializable(typeof(List<DISMOutputEntry>))]
internal sealed partial class DISMOutputEntryJsonContext : JsonSerializerContext
{
}

/// <summary>
/// Used as ListView data to display Features and Capabilities to manage.
/// </summary>
internal sealed partial class DISMOutputEntry(DISMOutput dismOutput, OptionalWindowsFeaturesVM parentVM) : ViewModelBase
{
	[JsonInclude]
	internal string Description => dismOutput.Description;

	private static SolidColorBrush GetStateBadgeBrush(DismPackageFeatureState state) => state switch
	{
		DismPackageFeatureState.DismStateInstalled => new SolidColorBrush(Color.FromArgb(255, 16, 137, 62)),         // Green
		DismPackageFeatureState.DismStateInstallPending => new SolidColorBrush(Color.FromArgb(255, 247, 99, 12)),   // Orange
		DismPackageFeatureState.DismStatePartiallyInstalled => new SolidColorBrush(Color.FromArgb(255, 247, 99, 12)),// Orange
		DismPackageFeatureState.DismStateStaged => new SolidColorBrush(Color.FromArgb(255, 0, 120, 215)),           // Blue
		DismPackageFeatureState.DismStateUninstallPending => new SolidColorBrush(Color.FromArgb(255, 247, 99, 12)), // Orange
		DismPackageFeatureState.DismStateSuperseded => new SolidColorBrush(Color.FromArgb(255, 96, 94, 92)),        // Gray
		DismPackageFeatureState.DismStateRemoved => new SolidColorBrush(Color.FromArgb(255, 232, 17, 35)),          // Red
		DismPackageFeatureState.DismStateNotPresent => new SolidColorBrush(Color.FromArgb(255, 96, 94, 92)),        // Gray
		DismPackageFeatureState.NotAvailableOnSystem => new SolidColorBrush(Color.FromArgb(255, 96, 94, 92)),       // Gray
		_ => new SolidColorBrush(Color.FromArgb(255, 96, 94, 92))                                                   // Default Gray
	};

	[JsonIgnore]
	internal SolidColorBrush StateBadgeBrush => GetStateBadgeBrush(State);

	[JsonInclude]
	internal string Name => dismOutput.Name;

	[JsonIgnore]
	internal DISMResultType Type => dismOutput.Type;

	[JsonIgnore]
	internal DismPackageFeatureState State
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(StateDisplayName));
				OnPropertyChanged(nameof(StateBadgeBrush));
			}
		}
	} = dismOutput.State;

	[JsonIgnore]
	internal bool IsProgressIndeterminate => IsProcessing && ProgressTotal == 0;

	[JsonIgnore]
	internal Visibility ProgressTextVisibility => IsProcessing && ProgressTotal > 0 ? Visibility.Visible : Visibility.Collapsed;

	[JsonIgnore]
	internal bool IsProcessing
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(ProgressBarVisibility));
				OnPropertyChanged(nameof(ButtonsEnabled));
				OnPropertyChanged(nameof(BorderBrush));
				OnPropertyChanged(nameof(IsProgressIndeterminate));
				OnPropertyChanged(nameof(ProgressTextVisibility));
			}
		}
	}

	[JsonIgnore]
	internal uint ProgressCurrent
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(ProgressPercentage));
				OnPropertyChanged(nameof(ProgressPercentageFormatted));
			}
		}
	}

	[JsonIgnore]
	internal uint ProgressTotal
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(ProgressPercentage));
				OnPropertyChanged(nameof(ProgressPercentageFormatted));
				// Also update derived progress UI properties
				OnPropertyChanged(nameof(IsProgressIndeterminate));
				OnPropertyChanged(nameof(ProgressTextVisibility));
			}
		}
	}

	[JsonIgnore]
	internal double ProgressPercentage => ProgressTotal > 0 ? ProgressCurrent * 100.0 / ProgressTotal : 0;

	[JsonIgnore]
	internal string ProgressPercentageFormatted => ProgressPercentage.ToString("F1");

	[JsonIgnore]
	internal Visibility ProgressBarVisibility => IsProcessing ? Visibility.Visible : Visibility.Collapsed;

	[JsonIgnore]
	internal bool ButtonsEnabled => !IsProcessing && ParentVM.ElementsAreEnabled;

	[JsonIgnore]
	internal SolidColorBrush BorderBrush => IsProcessing
		? new SolidColorBrush(Color.FromArgb(255, 255, 20, 147)) // Hot pink
		: new SolidColorBrush(Color.FromArgb(0, 0, 0, 0)); // Transparent

	private static string GetStateDisplayName(DismPackageFeatureState state) => state switch
	{
		DismPackageFeatureState.DismStateNotPresent => GlobalVars.GetStr("NotPresentState"),
		DismPackageFeatureState.DismStateUninstallPending => GlobalVars.GetStr("UninstallPendingState"),
		DismPackageFeatureState.DismStateStaged => GlobalVars.GetStr("StagedState"),
		DismPackageFeatureState.DismStateRemoved => GlobalVars.GetStr("RemovedState"),
		DismPackageFeatureState.DismStateInstalled => GlobalVars.GetStr("InstalledState"),
		DismPackageFeatureState.DismStateInstallPending => GlobalVars.GetStr("InstallPendingState"),
		DismPackageFeatureState.DismStateSuperseded => GlobalVars.GetStr("SupersededState"),
		DismPackageFeatureState.DismStatePartiallyInstalled => GlobalVars.GetStr("PartiallyInstalledState"),
		_ => GlobalVars.GetStr("UnknownState")
	};

	[JsonInclude]
	internal string StateDisplayName => GetStateDisplayName(State);

	[JsonInclude]
	internal string TypeDisplayName => Type == DISMResultType.Feature ? GlobalVars.GetStr("FeatureType") : GlobalVars.GetStr("CapabilityType");

	[JsonIgnore]
	internal OptionalWindowsFeaturesVM ParentVM => parentVM;

	internal void UpdateProgress(uint current, uint total)
	{
		ProgressCurrent = current;
		ProgressTotal = total;
	}

	/// <summary>
	/// Trigger property change notification for ButtonsEnabled
	/// </summary>
	internal void NotifyButtonsEnabledChanged() => OnPropertyChanged(nameof(ButtonsEnabled));

	/// <summary>
	/// Enable this specific feature or capability
	/// </summary>
	internal async void EnableItem()
	{
		try
		{
			await ParentVM.EnableItemAsync(this);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// Disable this specific feature or capability
	/// </summary>
	internal async void DisableItem()
	{
		try
		{
			await ParentVM.DisableItemAsync(this);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}
}

internal sealed partial class GroupInfoListForDISMItems(IEnumerable<DISMOutputEntry> items, string key) : List<DISMOutputEntry>(items)
{
	internal string Key => $"{key} ({Count})";
}

internal sealed partial class OptionalWindowsFeaturesVM : ViewModelBase, IDisposable
{
	private DismServiceClient? _dismServiceClient;

	/// <summary>
	/// Track current operation type for progress logging
	/// </summary>
	private string? _currentOperationType;

	internal OptionalWindowsFeaturesVM()
	{
		// Initialize the animated cancellable buttons
		ApplyCancellableButton = new AnimatedCancellableButtonInitializer(GlobalVars.GetStr("ApplyRecommendedConfigurations"));
		VerifyCancellableButton = new AnimatedCancellableButtonInitializer(GlobalVars.GetStr("VerifyRecommendedConfigurations"));
		RemoveCancellableButton = new AnimatedCancellableButtonInitializer(GlobalVars.GetStr("RemoveRecommendedConfigurations"));

		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		UpdateFilteredItems();

		UpdateCancellableButtonsEnabledStates();
	}

	/// <summary>
	/// Initialization details for the Apply Security Hardening button
	/// </summary>
	internal AnimatedCancellableButtonInitializer ApplyCancellableButton { get; }

	/// <summary>
	/// Initialization details for the Verify Security Hardening button
	/// </summary>
	internal AnimatedCancellableButtonInitializer VerifyCancellableButton { get; }

	/// <summary>
	/// Initialization details for the Remove Security Hardening button
	/// </summary>
	internal AnimatedCancellableButtonInitializer RemoveCancellableButton { get; }

	/// <summary>
	/// The main InfoBar for this VM.
	/// </summary>
	internal readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	internal Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal List<DISMOutputEntry> AllItems = [];

	/// <summary>
	/// Selected Items list in the ListView.
	/// </summary>
	internal List<DISMOutputEntry> ItemsSourceSelectedItems = [];

	/// <summary>
	/// ListView reference of the UI.
	/// </summary>
	internal volatile ListViewBase? UIListView;

	internal string? SearchQuery
	{
		get; set
		{
			if (SP(ref field, value))
			{
				UpdateFilteredItems();
			}
		}
	}

	internal bool ElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ProgressBarVisibility = field ? Visibility.Collapsed : Visibility.Visible;

				// Update all entry button states
				foreach (DISMOutputEntry entry in AllItems)
				{
					entry.NotifyButtonsEnabledChanged();
				}

				UpdateCancellableButtonsEnabledStates();
			}
		}
	} = true;

	// Computed properties to control IsEnabled state of the three AnimatedCancellableButton controls
	internal bool IsApplyButtonEnabled => ComputeCancellableButtonEnabled(ApplyCancellableButton);
	internal bool IsVerifyButtonEnabled => ComputeCancellableButtonEnabled(VerifyCancellableButton);
	internal bool IsRemoveButtonEnabled => ComputeCancellableButtonEnabled(RemoveCancellableButton);

	// Re-evaluate and notify bindings for the three buttons' IsEnabled
	private void UpdateCancellableButtonsEnabledStates()
	{
		OnPropertyChanged(nameof(IsApplyButtonEnabled));
		OnPropertyChanged(nameof(IsVerifyButtonEnabled));
		OnPropertyChanged(nameof(IsRemoveButtonEnabled));
	}

	/// <summary>
	/// Core logic for enabling/disabling the animated cancellable buttons
	/// </summary>
	private bool ComputeCancellableButtonEnabled(AnimatedCancellableButtonInitializer candidate)
	{
		bool anyInProgress =
			ApplyCancellableButton.IsOperationInProgress ||
			VerifyCancellableButton.IsOperationInProgress ||
			RemoveCancellableButton.IsOperationInProgress;

		// If other UI activity is in progress (ElementsAreEnabled == false)
		// then disable all three unless this button is the one running (so user can cancel).
		if (!ElementsAreEnabled)
		{
			return anyInProgress && candidate.IsOperationInProgress;
		}

		// If no one is running and UI is enabled -> enable all
		if (!anyInProgress)
		{
			return true;
		}

		// If someone is running and UI is enabled -> enable only the running one
		return candidate.IsOperationInProgress;
	}

	/// <summary>
	/// Total number of items loaded (all features and capabilities)
	/// </summary>
	internal int TotalItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of items currently displayed after filtering
	/// </summary>
	internal int FilteredItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of currently selected items
	/// </summary>
	internal int SelectedItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Flag to prevent recursive selection sync
	/// </summary>
	private volatile bool _isUpdatingSelection;

	/// <summary>
	/// Items source bound to the ListView.
	/// </summary>
	internal readonly ObservableCollection<GroupInfoListForDISMItems> GroupedFilteredDISMItems = [];

	private void UpdateFilteredItems()
	{
		// Choose the source items based on search query
		IEnumerable<DISMOutputEntry> filtered;

		if (string.IsNullOrEmpty(SearchQuery))
		{
			filtered = AllItems;
		}
		else
		{
			filtered = AllItems.Where(x =>
				x.Name.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ||
				x.TypeDisplayName.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ||
				x.Description.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ||
				x.StateDisplayName.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase));
		}

		// Update total counts
		TotalItemsCount = AllItems.Count;

		HashSet<string> recommendedNames = SecurityHardeningConfigs
			.Select(config => config.Name)
			.ToHashSet(StringComparer.OrdinalIgnoreCase);

		List<DISMOutputEntry> RecommendedItems = [];
		List<DISMOutputEntry> NetworkAdapterItems = [];
		List<DISMOutputEntry> OtherItems = [];

		foreach (DISMOutputEntry item in filtered)
		{
			if (recommendedNames.Contains(item.Name))
			{
				RecommendedItems.Add(item);
			}
			else
			{
				// Classify as "Network adapters" if it matches any of the vendor patterns
				string? vendor = GetNetworkVendor(item.Name);
				if (!string.IsNullOrEmpty(vendor))
				{
					NetworkAdapterItems.Add(item);
				}
				else
				{
					OtherItems.Add(item);
				}
			}
		}

		// Publish grouped collection for the XAML CollectionViewSource
		GroupedFilteredDISMItems.Clear();
		GroupedFilteredDISMItems.Add(new GroupInfoListForDISMItems(RecommendedItems, GlobalVars.GetStr("RecommendedProtectionPresetComboBoxItemText")));
		GroupedFilteredDISMItems.Add(new GroupInfoListForDISMItems(NetworkAdapterItems, GlobalVars.GetStr("NetworkAdapters/Text")));
		GroupedFilteredDISMItems.Add(new GroupInfoListForDISMItems(OtherItems, "Others"));

		// Update filtered counts
		FilteredItemsCount = RecommendedItems.Count + NetworkAdapterItems.Count + OtherItems.Count;

		// Sync ListView selection with our selection list after filtering
		SyncListViewSelection();
	}

	/// <summary>
	/// For the button event handler.
	/// </summary>
	internal async void EnsureRecommendedItemsRetrievedAndGroupAsync_Click()
	{
		try
		{
			await EnsureRecommendedItemsRetrievedAndGroupAsync();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Retrieve only the recommended items (features and capabilities) and ensure grouping is up-to-date.
	/// </summary>
	internal async Task EnsureRecommendedItemsRetrievedAndGroupAsync()
	{
		try
		{
			ElementsAreEnabled = false;

			// Initialize DISM service
			if (!await InitializeDismServiceAsync())
			{
				return;
			}

			// Build unique, case-insensitive name lists for recommended capabilities and features
			string[] capabilityNames = SecurityHardeningConfigs
				.Where(config => config.Type == DISMResultType.Capability)
				.Select(config => config.Name)
				.Distinct(StringComparer.OrdinalIgnoreCase)
				.ToArray();

			string[] featureNames = SecurityHardeningConfigs
				.Where(config => config.Type == DISMResultType.Feature)
				.Select(config => config.Name)
				.Distinct(StringComparer.OrdinalIgnoreCase)
				.ToArray();

			List<DISMOutput> results = new(featureNames.Length + capabilityNames.Length);

			// Retrieve only the recommended features and capabilities
			if (featureNames.Length > 0)
			{
				List<DISMOutput> featureResults = await _dismServiceClient!.GetSpecificFeaturesAsync(featureNames);
				results.AddRange(featureResults);
			}

			if (capabilityNames.Length > 0)
			{
				List<DISMOutput> capabilityResults = await _dismServiceClient!.GetSpecificCapabilitiesAsync(capabilityNames);
				results.AddRange(capabilityResults);
			}

			// Filter out items that are not available on this system, so they won't appear in the ListView
			// This applies to features that were marked as NotAvailableOnSystem by the service.
			List<DISMOutput> filteredResults = results
				.Where(r => r.State is not DismPackageFeatureState.NotAvailableOnSystem)
				.ToList();

			// Populate list
			AllItems.Clear();
			foreach (DISMOutput item in filteredResults)
			{
				AllItems.Add(new DISMOutputEntry(item, this));
			}
		}
		finally
		{
			ElementsAreEnabled = true;
		}

		// Rebuild filtered and grouped views to reflect current content and search (if any)
		UpdateFilteredItems();
	}

	/// <summary>
	/// Synchronize ListView selection with our internal selection list
	/// </summary>
	private void SyncListViewSelection()
	{
		if (UIListView == null || _isUpdatingSelection)
			return;

		_isUpdatingSelection = true;

		try
		{
			// Clear current ListView selection
			UIListView.SelectedItems.Clear();

			// Re-select items that are in our selection list and currently visible in grouped view
			foreach (DISMOutputEntry selectedItem in ItemsSourceSelectedItems)
			{
				bool isVisible = false;
				for (int g = 0; g < GroupedFilteredDISMItems.Count && !isVisible; g++)
				{
					if (GroupedFilteredDISMItems[g].Contains(selectedItem))
					{
						isVisible = true;
					}
				}

				if (isVisible)
				{
					UIListView.SelectedItems.Add(selectedItem);
				}
			}
		}
		finally
		{
			_isUpdatingSelection = false;
		}
	}

	/// <summary>
	/// Initialize the DISM service client
	/// </summary>
	private async Task<bool> InitializeDismServiceAsync()
	{
		try
		{
			if (_dismServiceClient == null)
			{
				_dismServiceClient = new DismServiceClient();

				// Subscribe to item-specific progress updates
				_dismServiceClient.ItemProgressUpdated += async (itemName, current, total) =>
				{
					await Dispatcher.EnqueueAsync(() =>
					{
						// Update the item's progress
						DISMOutputEntry? entry = AllItems.FirstOrDefault(x => string.Equals(x.Name, itemName, StringComparison.OrdinalIgnoreCase));
						entry?.UpdateProgress(current, total);
					});
				};

				// Subscribe to log messages
				_dismServiceClient.LogReceived += (message, logType) =>
				{
					switch (logType)
					{
						case LogTypeIntel.Information:
						case LogTypeIntel.InformationInteractionRequired:
							Logger.Write(message, LogTypeIntel.Information);
							break;
						case LogTypeIntel.Warning:
						case LogTypeIntel.WarningInteractionRequired:
							MainInfoBar.WriteWarning(message);
							Logger.Write(message, LogTypeIntel.Warning);
							break;
						case LogTypeIntel.Error:
						case LogTypeIntel.ErrorInteractionRequired:
							MainInfoBar.WriteWarning(message);
							Logger.Write(message, LogTypeIntel.Error);
							break;
						default:
							break;
					}
				};

				_dismServiceClient.SecureCopyFile();

				// Start the service
				if (!await _dismServiceClient.StartServiceAsync(DismServiceClient.SecureDISMServicePath))
				{
					MainInfoBar.WriteWarning(GlobalVars.GetStr("FailedToStartDISMServiceAdministrator"));
					return false;
				}
			}

			return true;
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("FailedToInitializeDISMService"));
			Logger.Write(string.Format(GlobalVars.GetStr("FailedToInitializeDISMService"), ex.Message), LogTypeIntel.Error);
			return false;
		}
	}

	/// <summary>
	/// Event handler for the Load All button - loads all Windows features and capabilities
	/// </summary>
	internal async void LoadAll()
	{
		// Prevent the RefreshContainer to trigger a load when activity is in progress.
		if (!ElementsAreEnabled)
			return;

		try
		{
			ElementsAreEnabled = false;

			// Clear existing items and reset their processing state
			AllItems.Clear();
			ItemsSourceSelectedItems.Clear();

			// Initialize DISM service
			if (!await InitializeDismServiceAsync())
			{
				return;
			}

			// Retrieve all features and capabilities from the service
			List<DISMOutput> results = await _dismServiceClient!.GetAllResultsAsync();

			// Add results to the master list
			foreach (DISMOutput result in results)
			{
				AllItems.Add(new DISMOutputEntry(result, this));
			}

			// Update grouped view and counts
			UpdateFilteredItems();
			SelectedItemsCount = ItemsSourceSelectedItems.Count;

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyLoadedWindowsFeaturesCapabilities"), results.Count));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Enable a specific feature or capability
	/// </summary>
	/// <param name="entry">The entry to enable</param>
	internal async Task EnableItemAsync(DISMOutputEntry entry)
	{
		try
		{
			// Set operation type for progress logging
			_currentOperationType = "Enabling";

			// Disable buttons and search, but set processing state for the specific item
			await Dispatcher.EnqueueAsync(() =>
			{
				ElementsAreEnabled = false;
				entry.IsProcessing = true;
				entry.ProgressCurrent = 0;
				entry.ProgressTotal = 0;
			});

			MainInfoBar.WriteInfo($"{_currentOperationType} {entry.TypeDisplayName.ToLowerInvariant()}: {entry.Name}");

			// Initialize DISM service if not already done
			if (!await InitializeDismServiceAsync())
			{
				return;
			}

			bool result = false;

			// Run the actual DISM operation on a background thread
			await Task.Run(async () =>
			{
				if (entry.Type == DISMResultType.Feature)
				{
					result = await _dismServiceClient!.EnableFeatureAsync(entry.Name);
				}
				else if (entry.Type == DISMResultType.Capability)
				{
					result = await _dismServiceClient!.AddCapabilityAsync(entry.Name);
				}
			});

			// After the operation, get the current state to verify the change.
			if (result)
			{
				List<DISMOutput> updatedResults;
				if (entry.Type == DISMResultType.Feature)
				{
					updatedResults = await _dismServiceClient!.GetSpecificFeaturesAsync([entry.Name]);
				}
				else
				{
					updatedResults = await _dismServiceClient!.GetSpecificCapabilitiesAsync([entry.Name]);
				}

				await Dispatcher.EnqueueAsync(() =>
				{
					if (updatedResults.Count > 0)
					{
						// Update the state based on the actual current state from DISM
						entry.State = updatedResults[0].State;
						MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyEnabledItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name));
					}
					else
					{
						MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("CouldNotVerifyStateAfterEnabling"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name));
					}
				});
			}
			else
			{
				MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("FailedToEnableItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name));
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, string.Format(GlobalVars.GetStr("ErrorEnablingItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name));
		}
		finally
		{
			// Always reset processing state and re-enable buttons and search
			await Dispatcher.EnqueueAsync(() =>
			{
				entry.IsProcessing = false;
				entry.ProgressCurrent = 0;
				entry.ProgressTotal = 0;
				ElementsAreEnabled = true;
				_currentOperationType = null;
			});
		}
	}

	/// <summary>
	/// Disable a specific feature or capability
	/// </summary>
	/// <param name="entry">The entry to disable</param>
	internal async Task DisableItemAsync(DISMOutputEntry entry)
	{
		try
		{
			// Set operation type for progress logging
			_currentOperationType = "Disabling";

			// Disable buttons and search, but set processing state for the specific item
			await Dispatcher.EnqueueAsync(() =>
			{
				ElementsAreEnabled = false;
				entry.IsProcessing = true;
				entry.ProgressCurrent = 0;
				entry.ProgressTotal = 0;
			});

			MainInfoBar.WriteInfo($"{_currentOperationType} {entry.TypeDisplayName.ToLowerInvariant()}: {entry.Name}");

			// Initialize DISM service if not already done
			if (!await InitializeDismServiceAsync())
			{
				return;
			}

			bool result = false;

			// Run the actual DISM operation on a background thread
			await Task.Run(async () =>
			{
				if (entry.Type == DISMResultType.Feature)
				{
					result = await _dismServiceClient!.DisableFeatureAsync(entry.Name);
				}
				else if (entry.Type == DISMResultType.Capability)
				{
					result = await _dismServiceClient!.RemoveCapabilityAsync(entry.Name);
				}
			});

			// After the operation, get the current state to verify the change
			if (result)
			{
				List<DISMOutput> updatedResults;
				if (entry.Type == DISMResultType.Feature)
				{
					updatedResults = await _dismServiceClient!.GetSpecificFeaturesAsync([entry.Name]);
				}
				else
				{
					updatedResults = await _dismServiceClient!.GetSpecificCapabilitiesAsync([entry.Name]);
				}

				await Dispatcher.EnqueueAsync(() =>
				{
					if (updatedResults.Count > 0)
					{
						// Update the state based on the actual current state from DISM
						entry.State = updatedResults[0].State;
						MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyDisabledItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name));
					}
					else
					{
						MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("CouldNotVerifyStateAfterDisabling"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name));
					}
				});
			}
			else
			{
				MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("FailedToDisableItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name));
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, string.Format(GlobalVars.GetStr("ErrorDisablingItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name));
		}
		finally
		{
			// Always reset processing state and re-enable buttons and search
			await Dispatcher.EnqueueAsync(() =>
			{
				entry.IsProcessing = false;
				entry.ProgressCurrent = 0;
				entry.ProgressTotal = 0;
				ElementsAreEnabled = true;
				_currentOperationType = null;
			});
		}
	}

	/// <summary>
	/// Enable all selected items in bulk
	/// </summary>
	internal async void EnableSelected_Click(object sender, RoutedEventArgs e)
	{
		if (ItemsSourceSelectedItems.Count == 0)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("NoItemsSelectedForEnable"));
			return;
		}

		try
		{
			// Set operation type for progress logging
			_currentOperationType = "Enabling Selected Item";

			ElementsAreEnabled = false;

			// Initialize DISM service if not already done
			if (!await InitializeDismServiceAsync())
			{
				return;
			}

			int successCount = 0;
			int failureCount = 0;
			List<string> failedItems = [];

			MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("StartingBulkEnableOperation"), ItemsSourceSelectedItems.Count));

			await Task.Run(async () =>
			{
				foreach (DISMOutputEntry entry in ItemsSourceSelectedItems.ToList()) // ToList to avoid collection modification issues
				{
					try
					{
						await Dispatcher.EnqueueAsync(() =>
						{
							entry.IsProcessing = true;
							entry.ProgressCurrent = 0;
							entry.ProgressTotal = 0;

							// Scroll the ListView to the currently active item
							UIListView?.ScrollIntoView(entry, ScrollIntoViewAlignment.Leading);
						});

						bool result = false;

						if (entry.Type == DISMResultType.Feature)
						{
							result = await _dismServiceClient!.EnableFeatureAsync(entry.Name);
						}
						else if (entry.Type == DISMResultType.Capability)
						{
							result = await _dismServiceClient!.AddCapabilityAsync(entry.Name);
						}

						if (result)
						{
							// Get updated state
							List<DISMOutput> updatedResults;
							if (entry.Type == DISMResultType.Feature)
							{
								updatedResults = await _dismServiceClient!.GetSpecificFeaturesAsync([entry.Name]);
							}
							else
							{
								updatedResults = await _dismServiceClient!.GetSpecificCapabilitiesAsync([entry.Name]);
							}

							await Dispatcher.EnqueueAsync(() =>
							{
								if (updatedResults.Count > 0)
								{
									entry.State = updatedResults[0].State;
								}
							});

							successCount++;
							MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("SuccessfullyEnabledItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name));
						}
						else
						{
							failureCount++;
							failedItems.Add($"{entry.TypeDisplayName}: {entry.Name}");
							MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("FailedToEnableItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name));
						}
					}
					catch (Exception ex)
					{
						failureCount++;
						failedItems.Add($"{entry.TypeDisplayName}: {entry.Name}");
						MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("ErrorEnablingItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name) + $": {ex.Message}");
					}
					finally
					{
						await Dispatcher.EnqueueAsync(() =>
						{
							entry.IsProcessing = false;
							entry.ProgressCurrent = 0;
							entry.ProgressTotal = 0;
						});
					}
				}
			});

			// Show final results
			await Dispatcher.EnqueueAsync(() =>
			{
				if (failureCount == 0)
				{
					MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyEnabledAllSelectedItems"), successCount));
				}
				else if (successCount == 0)
				{
					MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("FailedToEnableAllSelectedItems"), failureCount));
				}
				else
				{
					MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("BulkEnableCompleted"), successCount, failureCount));
				}

				if (failedItems.Count > 0)
				{
					string failedItemsList = string.Join(", ", failedItems.Take(5));
					if (failedItems.Count > 5)
					{
						failedItemsList += $" and {failedItems.Count - 5} more...";
					}
					MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("FailedItems"), failedItemsList));
				}
			});
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorDuringBulkEnableOperation"));
		}
		finally
		{
			ElementsAreEnabled = true;
			_currentOperationType = null;
		}
	}

	/// <summary>
	/// Disable all selected items in bulk
	/// </summary>
	internal async void DisableSelected_Click(object sender, RoutedEventArgs e)
	{
		if (ItemsSourceSelectedItems.Count == 0)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("NoItemsSelectedForDisable"));
			return;
		}

		try
		{
			// Set operation type for progress logging
			_currentOperationType = "Disabling Selected Item";

			ElementsAreEnabled = false;

			// Initialize DISM service if not already done
			if (!await InitializeDismServiceAsync())
			{
				return;
			}

			int successCount = 0;
			int failureCount = 0;
			List<string> failedItems = [];

			MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("StartingBulkDisableOperation"), ItemsSourceSelectedItems.Count));

			await Task.Run(async () =>
			{
				foreach (DISMOutputEntry entry in ItemsSourceSelectedItems.ToList()) // ToList to avoid collection modification issues
				{
					try
					{
						await Dispatcher.EnqueueAsync(() =>
						{
							entry.IsProcessing = true;
							entry.ProgressCurrent = 0;
							entry.ProgressTotal = 0;

							// Scroll the ListView to the currently active item
							UIListView?.ScrollIntoView(entry, ScrollIntoViewAlignment.Leading);
						});

						bool result = false;

						if (entry.Type == DISMResultType.Feature)
						{
							result = await _dismServiceClient!.DisableFeatureAsync(entry.Name);
						}
						else if (entry.Type == DISMResultType.Capability)
						{
							result = await _dismServiceClient!.RemoveCapabilityAsync(entry.Name);
						}

						if (result)
						{
							// Get updated state
							List<DISMOutput> updatedResults;
							if (entry.Type == DISMResultType.Feature)
							{
								updatedResults = await _dismServiceClient!.GetSpecificFeaturesAsync([entry.Name]);
							}
							else
							{
								updatedResults = await _dismServiceClient!.GetSpecificCapabilitiesAsync([entry.Name]);
							}

							await Dispatcher.EnqueueAsync(() =>
							{
								if (updatedResults.Count > 0)
								{
									entry.State = updatedResults[0].State;
								}
							});

							successCount++;
							MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("SuccessfullyDisabledItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name));
						}
						else
						{
							failureCount++;
							failedItems.Add($"{entry.TypeDisplayName}: {entry.Name}");
							MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("FailedToDisableItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name));
						}
					}
					catch (Exception ex)
					{
						failureCount++;
						failedItems.Add($"{entry.TypeDisplayName}: {entry.Name}");
						MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("ErrorDisablingItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name) + $": {ex.Message}");
					}
					finally
					{
						await Dispatcher.EnqueueAsync(() =>
						{
							entry.IsProcessing = false;
							entry.ProgressCurrent = 0;
							entry.ProgressTotal = 0;
						});
					}
				}
			});

			// Show final results
			await Dispatcher.EnqueueAsync(() =>
			{
				if (failureCount == 0)
				{
					MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyDisabledAllSelectedItems"), successCount));
				}
				else if (successCount == 0)
				{
					MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("FailedToDisableAllSelectedItems"), failureCount));
				}
				else
				{
					MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("BulkDisableCompleted"), successCount, failureCount));
				}

				if (failedItems.Count > 0)
				{
					string failedItemsList = string.Join(", ", failedItems.Take(5));
					if (failedItems.Count > 5)
					{
						failedItemsList += $" and {failedItems.Count - 5} more...";
					}
					MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("FailedItems"), failedItemsList));
				}
			});
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorDuringBulkDisableOperation"));
		}
		finally
		{
			ElementsAreEnabled = true;
			_currentOperationType = null;
		}
	}

	#region Item Selections

	/// <summary>
	/// For selecting all items on the UI. Will automatically trigger <see cref="MainListView_SelectionChanged"/> method as well,
	/// Adding the items to <see cref="ItemsSourceSelectedItems"/>.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void SelectAll_Click(object sender, RoutedEventArgs e)
	{
		if (_isUpdatingSelection) return;

		foreach (GroupInfoListForDISMItems group in GroupedFilteredDISMItems)
		{
			for (int i = 0; i < group.Count; i++)
			{
				UIListView?.SelectedItems.Add(group[i]);
			}
		}
	}

	/// <summary>
	/// For De-selecting all items on the UI. Will automatically trigger <see cref="MainListView_SelectionChanged"/> method as well,
	/// Removing the items from <see cref="ItemsSourceSelectedItems"/>.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void RemoveSelections_Click(object sender, RoutedEventArgs e)
	{
		if (_isUpdatingSelection) return;

		UIListView?.SelectedItems.Clear();
	}

	/// <summary>
	/// Event handler for when the ListView is loaded - store reference and sync selection
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void MainListView_Loaded(object sender, RoutedEventArgs e)
	{
		UIListView = sender as ListViewBase;
		SyncListViewSelection();
	}

	/// <summary>
	/// Event handler for the SelectionChanged event of the ListView.
	/// Triggered by <see cref="SelectAll_Click(object, RoutedEventArgs)"/> and <see cref="RemoveSelections_Click(object, RoutedEventArgs)"/> to keep things consistent.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void MainListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		if (_isUpdatingSelection) return;

		// Add newly selected items to our internal list
		foreach (DISMOutputEntry item in e.AddedItems.Cast<DISMOutputEntry>())
		{
			if (!ItemsSourceSelectedItems.Contains(item))
			{
				ItemsSourceSelectedItems.Add(item);
			}
		}

		// Remove deselected items from our internal list
		foreach (DISMOutputEntry item in e.RemovedItems.Cast<DISMOutputEntry>())
		{
			_ = ItemsSourceSelectedItems.Remove(item);
		}

		// Update the selected count display
		SelectedItemsCount = ItemsSourceSelectedItems.Count;
	}

	#endregion

	#region Bulk Operations for Protect Tab and Recommended States application

	/// <summary>
	/// Defines the operation to perform during Apply for each feature/capability
	/// </summary>
	internal enum ApplyOperation
	{
		Enable,  // For features: EnableFeature, For capabilities: AddCapability
		Disable  // For features: DisableFeature, For capabilities: RemoveCapability
	}

	/// <summary>
	/// Configurations for each feature/capability defining apply strategy, remove strategy, and valid verification states.
	/// </summary>
	internal sealed class OptionalFeatureConfig(
		string name,
		DISMResultType type,
		ApplyOperation applyStrategy,
		ApplyOperation removeStrategy,
		List<DismPackageFeatureState> validVerificationStates)
	{
		internal string Name => name;
		internal DISMResultType Type => type;
		internal ApplyOperation ApplyStrategy => applyStrategy;
		internal ApplyOperation RemoveStrategy => removeStrategy;
		internal List<DismPackageFeatureState> ValidVerificationStates => validVerificationStates;
	}

	/// <summary>
	/// Acceptable states of a feature or capability that should be disabled/removed from the system.
	/// </summary>
	private static readonly List<DismPackageFeatureState> ValidStatesForRemoval = [
					DismPackageFeatureState.DismStateRemoved,
					DismPackageFeatureState.DismStateNotPresent,
					DismPackageFeatureState.NotAvailableOnSystem,
					DismPackageFeatureState.DismStateStaged // DISM.exe also shows staged as "Disabled" when we query a feature state. This means the payload of the package exists on the system but isn't turned on in the running image.
					];

	/// <summary>
	/// Acceptable states of a feature or capability that should be enabled on the system.
	/// </summary>
	private static readonly List<DismPackageFeatureState> ValidStatesForEnablement = [
					DismPackageFeatureState.DismStateInstalled,
					DismPackageFeatureState.DismStateInstallPending,
					DismPackageFeatureState.NotAvailableOnSystem
					];

	/// <summary>
	/// Predefined configurations for this hardening category that needs to run to provide a secure system state.
	/// </summary>
	private static readonly List<OptionalFeatureConfig> SecurityHardeningConfigs = [

			#region FEATURES

			new OptionalFeatureConfig(
				name:                   "MicrosoftWindowsPowerShellV2",
				type:                   DISMResultType.Feature,
				applyStrategy:          ApplyOperation.Disable,  // Apply = Disable
				removeStrategy:         ApplyOperation.Enable,   // Remove = Enable (restore)
				validVerificationStates: ValidStatesForRemoval
			),
			new OptionalFeatureConfig(
				name:                   "MicrosoftWindowsPowerShellV2Root",
				type:                   DISMResultType.Feature,
				applyStrategy:          ApplyOperation.Disable,
				removeStrategy:         ApplyOperation.Enable,
				validVerificationStates:ValidStatesForRemoval
			),
			new OptionalFeatureConfig(
				name:                   "WorkFolders-Client",
				type:                   DISMResultType.Feature,
				applyStrategy:          ApplyOperation.Disable,
				removeStrategy:         ApplyOperation.Enable,
				validVerificationStates:ValidStatesForRemoval
			),
			new OptionalFeatureConfig(
				name:                   "Printing-Foundation-InternetPrinting-Client",
				type:                   DISMResultType.Feature,
				applyStrategy:          ApplyOperation.Disable,
				removeStrategy:         ApplyOperation.Enable,
				validVerificationStates:ValidStatesForRemoval
			),
			new OptionalFeatureConfig(
				name:                   "Containers-DisposableClientVM",
				type:                   DISMResultType.Feature,
				applyStrategy:          ApplyOperation.Enable,   // Apply = Enable
				removeStrategy:         ApplyOperation.Disable,  // Remove = Disable (undo)
				validVerificationStates:ValidStatesForEnablement
			),
			new OptionalFeatureConfig(
				name:                   "Microsoft-Hyper-V-All",
				type:                   DISMResultType.Feature,
				applyStrategy:          ApplyOperation.Enable,
				removeStrategy:         ApplyOperation.Disable,
				validVerificationStates:ValidStatesForEnablement
			),

			#endregion

			#region CAPABILITIES

			new OptionalFeatureConfig(
				name:                   "Media.WindowsMediaPlayer~~~~0.0.12.0",
				type:                   DISMResultType.Capability,
				applyStrategy:          ApplyOperation.Disable,  // Apply = Remove (disable for capabilities)
				removeStrategy:         ApplyOperation.Enable,   // Remove = Add (restore)
				validVerificationStates:ValidStatesForRemoval
			),
			new OptionalFeatureConfig(
				name:                   "WMIC~~~~",
				type:                   DISMResultType.Capability,
				applyStrategy:          ApplyOperation.Disable,
				removeStrategy:         ApplyOperation.Enable,
				validVerificationStates:ValidStatesForRemoval
			),
			new OptionalFeatureConfig(
				name:                   "Microsoft.Windows.Notepad.System~~~~0.0.1.0",
				type:                   DISMResultType.Capability,
				applyStrategy:          ApplyOperation.Disable,
				removeStrategy:         ApplyOperation.Enable,
				validVerificationStates:ValidStatesForRemoval
			),
			new OptionalFeatureConfig(
				name:                   "Microsoft.Windows.WordPad~~~~0.0.1.0",
				type:                   DISMResultType.Capability,
				applyStrategy:          ApplyOperation.Disable,
				removeStrategy:         ApplyOperation.Enable,
				validVerificationStates:ValidStatesForRemoval
			),
			new OptionalFeatureConfig(
				name:                   "Microsoft.Windows.PowerShell.ISE~~~~0.0.1.0",
				type:                   DISMResultType.Capability,
				applyStrategy:          ApplyOperation.Disable,
				removeStrategy:         ApplyOperation.Enable,
				validVerificationStates:ValidStatesForRemoval
			),
			new OptionalFeatureConfig(
				name:                   "App.StepsRecorder~~~~0.0.1.0",
				type:                   DISMResultType.Capability,
				applyStrategy:          ApplyOperation.Disable,
				removeStrategy:         ApplyOperation.Enable,
				validVerificationStates:ValidStatesForRemoval
			),
			new OptionalFeatureConfig(
				name:                   "VBSCRIPT~~~~",
				type:                   DISMResultType.Capability,
				applyStrategy:          ApplyOperation.Disable,
				removeStrategy:         ApplyOperation.Enable,
				validVerificationStates:ValidStatesForRemoval
			),
			new OptionalFeatureConfig(
				name:                   "Browser.InternetExplorer~~~~0.0.11.0",
				type:                   DISMResultType.Capability,
				applyStrategy:          ApplyOperation.Disable,
				removeStrategy:         ApplyOperation.Enable,
				validVerificationStates:ValidStatesForRemoval
			),

			#endregion
		];

	/// <summary>
	/// Execute the specified operation on a feature or capability
	/// </summary>
	/// <param name="config">Configuration for the item</param>
	/// <param name="operation">Operation to perform</param>
	/// <returns>True if successful</returns>
	private async Task<bool> ExecuteOperationAsync(OptionalFeatureConfig config, ApplyOperation operation)
	{
		if (config.Type == DISMResultType.Feature)
		{
			return operation switch
			{
				ApplyOperation.Enable => await _dismServiceClient!.EnableFeatureAsync(config.Name),
				ApplyOperation.Disable => await _dismServiceClient!.DisableFeatureAsync(config.Name),
				_ => false
			};
		}
		else if (config.Type == DISMResultType.Capability)
		{
			return operation switch
			{
				ApplyOperation.Enable => await _dismServiceClient!.AddCapabilityAsync(config.Name),
				ApplyOperation.Disable => await _dismServiceClient!.RemoveCapabilityAsync(config.Name),
				_ => false
			};
		}

		return false;
	}

	/// <summary>
	/// Apply the recommended configs by processing predefined features and capabilities according to their configurations we defined earlier.
	/// Called from the Protect tab when Optional Windows Features category is applied and from the UI buttons.
	/// </summary>
	internal async Task ApplySecurityHardening()
	{
		bool errorsOccurred = false;

		try
		{
			ElementsAreEnabled = false;

			// Initialize DISM service if not already done
			if (!await InitializeDismServiceAsync())
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("FailedToInitializeDISMServiceForSecurityHardening"));
				return;
			}

			ApplyCancellableButton.Begin();

			await Dispatcher.EnqueueAsync(UpdateCancellableButtonsEnabledStates);

			// Set operation type for progress logging
			_currentOperationType = "Applying Recommended Configurations";

			int successCount = 0;
			int failureCount = 0;
			List<string> failedItems = [];

			MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("StartingWithOptionalWindowsFeatures"), SecurityHardeningConfigs.Count));

			await Task.Run(async () =>
			{
				foreach (OptionalFeatureConfig config in SecurityHardeningConfigs)
				{
					ApplyCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

					// Display a per-item "currently doing" message
					string actionText = config.ApplyStrategy == ApplyOperation.Enable ? "Enabling" : "Disabling";
					MainInfoBar.WriteInfo($"{actionText} {config.Type.ToString().ToLowerInvariant()}: {config.Name}");

					// Try to find the corresponding list item (if present) and show its progress (initially indeterminate)
					DISMOutputEntry? entry = null;
					await Dispatcher.EnqueueAsync(() =>
					{
						entry = AllItems.FirstOrDefault(x => string.Equals(x.Name, config.Name, StringComparison.OrdinalIgnoreCase));
						if (entry != null)
						{
							// Mark active and scroll it into view at the top
							entry.IsProcessing = true;
							entry.ProgressCurrent = 0;
							entry.ProgressTotal = 0; // Unknown total => indeterminate bar shows

							// Scroll to currently active item on the ListView
							UIListView?.ScrollIntoView(entry, ScrollIntoViewAlignment.Leading);
						}
					});

					try
					{
						bool result = await ExecuteOperationAsync(config, config.ApplyStrategy);

						if (result)
						{
							successCount++;
							string operationName = config.ApplyStrategy == ApplyOperation.Enable ? "enabled" : "disabled";
							MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("SuccessfullyEnabledItem"), config.Type.ToString().ToLowerInvariant(), config.Name));
						}
						else
						{
							failureCount++;
							string operationName = config.ApplyStrategy == ApplyOperation.Enable ? "enable" : "disable";
							failedItems.Add($"{config.Type}: {config.Name}");
							MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("FailedToEnableItem"), config.Type.ToString().ToLowerInvariant(), config.Name));
						}
					}
					catch (Exception ex)
					{
						failureCount++;
						string operationName = config.ApplyStrategy == ApplyOperation.Enable ? "enabling" : "disabling";
						failedItems.Add($"{config.Type}: {config.Name}");
						MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("ErrorEnablingItem"), config.Type.ToString().ToLowerInvariant(), config.Name) + $": {ex.Message}");
					}
					finally
					{
						// Always collapse the item's progress once this config is done
						if (entry != null)
						{
							await Dispatcher.EnqueueAsync(() =>
							{
								entry.IsProcessing = false;
								entry.ProgressCurrent = 0;
								entry.ProgressTotal = 0;
							});
						}
					}
				}
			});

			ApplyCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

			await Dispatcher.EnqueueAsync(() =>
			{
				if (failureCount == 0)
				{
					MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyAppliedSecurityHardening"), successCount));
				}
				else if (successCount == 0)
				{
					MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("FailedToApplySecurityHardening"), failureCount));
				}
				else
				{
					MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("SecurityHardeningCompleted"), successCount, failureCount));
				}

				if (failedItems.Count > 0)
				{
					string failedItemsList = string.Join(", ", failedItems.Take(5));
					if (failedItems.Count > 5)
					{
						failedItemsList += $" and {failedItems.Count - 5} more...";
					}
					MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("FailedItems"), failedItemsList));
				}
			});
		}
		catch (Exception ex)
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				HandleExceptions(ex, ref errorsOccurred, ref ApplyCancellableButton.wasCancelled, MainInfoBar);
			});
		}
		finally
		{
			if (ApplyCancellableButton.wasCancelled)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("ApplyOperationCancelledByUser"));
			}
			await Dispatcher.EnqueueAsync(() =>
			{
				ElementsAreEnabled = true;
				ApplyCancellableButton.End();
				UpdateCancellableButtonsEnabledStates();
				_currentOperationType = null;
			});
		}
	}

	/// <summary>
	/// Verify that security hardening has been applied correctly by checking if items are in their valid states
	/// Called from the Protect tab when Optional Windows Features category is verified and from the UI buttons
	/// </summary>
	internal async Task<bool> VerifySecurityHardening()
	{
		bool errorsOccurred = false;

		VerifyCancellableButton.Begin();
		await Dispatcher.EnqueueAsync(UpdateCancellableButtonsEnabledStates);

		// Track which UI entries we mark as "processing" so we can reliably unmark them
		HashSet<string> targetNames = SecurityHardeningConfigs
			.Select(c => c.Name)
			.ToHashSet(StringComparer.OrdinalIgnoreCase);

		try
		{
			ElementsAreEnabled = false;

			// Initialize DISM service if not already done
			if (!await InitializeDismServiceAsync())
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("FailedToInitializeDISMServiceForVerification"));
				return false;
			}

			// Set operation type for progress logging
			_currentOperationType = "Verifying Recommended Configurations";

			int correctCount = 0;
			int incorrectCount = 0;
			List<string> incorrectItems = [];

			MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("VerifyingSecurityHardeningState"), SecurityHardeningConfigs.Count));

			// Mark all recommended items present in the ListView as "in progress" with indeterminate bars
			await Dispatcher.EnqueueAsync(() =>
			{
				foreach (DISMOutputEntry entry in AllItems)
				{
					if (targetNames.Contains(entry.Name))
					{
						entry.IsProcessing = true;
						entry.ProgressCurrent = 0;
						entry.ProgressTotal = 0; // Unknown total => indeterminate
					}
				}
			});

			Dictionary<string, DismPackageFeatureState> actualStates = [];

			VerifyCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

			await Task.Run(async () =>
			{
				// Get current states for all targets
				string[] capabilityNames = SecurityHardeningConfigs
					.Where(config => config.Type == DISMResultType.Capability)
					.Select(config => config.Name)
					.ToArray();

				string[] featureNames = SecurityHardeningConfigs
					.Where(config => config.Type == DISMResultType.Feature)
					.Select(config => config.Name)
					.ToArray();

				if (capabilityNames.Length > 0)
				{
					List<DISMOutput> capabilityResults = await _dismServiceClient!.GetSpecificCapabilitiesAsync(capabilityNames);
					foreach (DISMOutput result in capabilityResults)
					{
						actualStates[result.Name] = result.State;
					}
				}

				VerifyCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

				if (featureNames.Length > 0)
				{
					List<DISMOutput> featureResults = await _dismServiceClient!.GetSpecificFeaturesAsync(featureNames);
					foreach (DISMOutput result in featureResults)
					{
						actualStates[result.Name] = result.State;
					}
				}

				// Compare with valid verification states for each item
				foreach (OptionalFeatureConfig config in SecurityHardeningConfigs)
				{
					VerifyCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

					MainInfoBar.WriteInfo($"Verifying {config.Type.ToString().ToLowerInvariant()}: {config.Name}");

					if (actualStates.TryGetValue(config.Name, out DismPackageFeatureState actualState))
					{
						if (config.ValidVerificationStates.Contains(actualState))
						{
							correctCount++;
							MainInfoBar.WriteInfo($"Correct state for {config.Name}: {actualState}");
						}
						else
						{
							incorrectCount++;
							string validStates = string.Join(", ", config.ValidVerificationStates);
							incorrectItems.Add($"{config.Name} (Expected: {validStates}, Actual: {actualState})");
							MainInfoBar.WriteWarning($"Incorrect state for {config.Name}: Expected one of [{validStates}], Actual {actualState}");
						}
					}
					else
					{
						// Item not found - check if "Not Present" is a valid state
						if (config.ValidVerificationStates.Contains(DismPackageFeatureState.DismStateNotPresent))
						{
							correctCount++;
							MainInfoBar.WriteInfo($"Correct state for {config.Name}: Not Present (as expected)");
						}
						else
						{
							incorrectCount++;
							string validStates = string.Join(", ", config.ValidVerificationStates);
							incorrectItems.Add($"{config.Name} (Expected: {validStates}, Actual: Not Found)");
							MainInfoBar.WriteWarning($"Item not found during verification: {config.Name}");
						}
					}
				}
			});

			VerifyCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

			// Show verification results
			bool allCorrect = incorrectCount == 0;
			await Dispatcher.EnqueueAsync(() =>
			{
				if (allCorrect)
				{
					MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SecurityHardeningVerificationPassed"), correctCount));
				}
				else
				{
					MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("SecurityHardeningVerificationCompleted"), correctCount, incorrectCount));

					if (incorrectItems.Count > 0)
					{
						string incorrectItemsList = string.Join(", ", incorrectItems.Take(3));
						if (incorrectItems.Count > 3)
						{
							incorrectItemsList += $" and {incorrectItems.Count - 3} more...";
						}
						MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("IncorrectItems"), incorrectItemsList));
					}
				}
			});

			return allCorrect;
		}
		catch (Exception ex)
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				HandleExceptions(ex, ref errorsOccurred, ref VerifyCancellableButton.wasCancelled, MainInfoBar);
			});
			return false;
		}
		finally
		{
			// Unmark all recommended items as "processing"
			await Dispatcher.EnqueueAsync(() =>
			{
				foreach (DISMOutputEntry entry in AllItems)
				{
					if (targetNames.Contains(entry.Name))
					{
						entry.IsProcessing = false;
						entry.ProgressCurrent = 0;
						entry.ProgressTotal = 0;
					}
				}
			});

			if (VerifyCancellableButton.wasCancelled)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("VerifyOperationCancelledByUser"));
			}
			await Dispatcher.EnqueueAsync(() =>
			{
				ElementsAreEnabled = true;
				VerifyCancellableButton.End();
				UpdateCancellableButtonsEnabledStates();
				_currentOperationType = null;
			});
		}
	}

	/// <summary>
	/// Remove security hardening by executing the remove strategy for each item
	/// Called from the Protect tab when Optional Windows Features category is removed and from the UI buttons
	/// </summary>
	internal async Task RemoveSecurityHardening()
	{
		bool errorsOccurred = false;

		RemoveCancellableButton.Begin();
		await Dispatcher.EnqueueAsync(UpdateCancellableButtonsEnabledStates);

		try
		{
			ElementsAreEnabled = false;

			// Initialize DISM service if not already done
			if (!await InitializeDismServiceAsync())
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("FailedToInitializeDISMServiceForRemovingSecurityHardening"));
				return;
			}

			// Set operation type for progress logging
			_currentOperationType = "Removing Recommended Configurations";

			int successCount = 0;
			int failureCount = 0;
			List<string> failedItems = [];

			MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("RemovingSecurityHardening"), SecurityHardeningConfigs.Count));

			await Task.Run(async () =>
			{
				foreach (OptionalFeatureConfig config in SecurityHardeningConfigs)
				{
					RemoveCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

					// Display a per-item "currently doing" message for removal phase
					string actionText = config.RemoveStrategy == ApplyOperation.Enable ? "Enabling" : "Disabling";
					MainInfoBar.WriteInfo($"{actionText} {config.Type.ToString().ToLowerInvariant()}: {config.Name}");

					// Try to find the corresponding list item (if present) and show its progress (initially indeterminate)
					DISMOutputEntry? entry = null;
					await Dispatcher.EnqueueAsync(() =>
					{
						entry = AllItems.FirstOrDefault(x => string.Equals(x.Name, config.Name, StringComparison.OrdinalIgnoreCase));
						if (entry != null)
						{
							// Mark active and scroll it into view at the top
							entry.IsProcessing = true;
							entry.ProgressCurrent = 0;
							entry.ProgressTotal = 0; // Unknown total => indeterminate bar shows

							// Scroll to currently active item on the ListView
							UIListView?.ScrollIntoView(entry, ScrollIntoViewAlignment.Leading);
						}
					});

					try
					{
						bool result = await ExecuteOperationAsync(config, config.RemoveStrategy);

						if (result)
						{
							successCount++;
							string operationName = config.RemoveStrategy == ApplyOperation.Enable ? "restored" : "removed";
							MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("SuccessfullyEnabledItem"), config.Type.ToString().ToLowerInvariant(), config.Name));
						}
						else
						{
							failureCount++;
							string operationName = config.RemoveStrategy == ApplyOperation.Enable ? "restore" : "remove";
							failedItems.Add($"{config.Type}: {config.Name}");
							MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("FailedToEnableItem"), config.Type.ToString().ToLowerInvariant(), config.Name));
						}
					}
					catch (Exception ex)
					{
						failureCount++;
						string operationName = config.RemoveStrategy == ApplyOperation.Enable ? "restoring" : "removing";
						failedItems.Add($"{config.Type}: {config.Name}");
						MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("ErrorEnablingItem"), config.Type.ToString().ToLowerInvariant(), config.Name) + $": {ex.Message}");
					}
					finally
					{
						// Always collapse the item's progress once this config is done
						if (entry != null)
						{
							await Dispatcher.EnqueueAsync(() =>
							{
								entry.IsProcessing = false;
								entry.ProgressCurrent = 0;
								entry.ProgressTotal = 0;
							});
						}
					}
				}
			});

			RemoveCancellableButton.Cts?.Token.ThrowIfCancellationRequested();

			// Show final results
			await Dispatcher.EnqueueAsync(() =>
			{
				if (failureCount == 0)
				{
					MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyRemovedSecurityHardening"), successCount));
				}
				else if (successCount == 0)
				{
					MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("FailedToRemoveSecurityHardening"), failureCount));
				}
				else
				{
					MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("SecurityHardeningRemovalCompleted"), successCount, failureCount));
				}

				if (failedItems.Count > 0)
				{
					string failedItemsList = string.Join(", ", failedItems.Take(5));
					if (failedItems.Count > 5)
					{
						failedItemsList += $" and {failedItems.Count - 5} more...";
					}
					MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("FailedItems"), failedItemsList));
				}
			});
		}
		catch (Exception ex)
		{
			HandleExceptions(ex, ref errorsOccurred, ref RemoveCancellableButton.wasCancelled, MainInfoBar);
		}
		finally
		{
			if (RemoveCancellableButton.wasCancelled)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("RemoveOperationCancelledByUser"));
			}
			await Dispatcher.EnqueueAsync(() =>
			{
				ElementsAreEnabled = true;
				RemoveCancellableButton.End();
				UpdateCancellableButtonsEnabledStates();
				_currentOperationType = null;
			});
		}
	}

	/// <summary>
	/// UI wrapper for ApplySecurityHardening - calls the async Task method
	/// </summary>
	internal async void ApplySecurityHardeningUI()
	{
		// Ensure only recommended items are retrieved and grouped before applying
		await EnsureRecommendedItemsRetrievedAndGroupAsync();
		await ApplySecurityHardening();
	}

	/// <summary>
	/// UI wrapper for VerifySecurityHardening - calls the async Task<bool> method
	/// </summary>
	internal async void VerifySecurityHardeningUI()
	{
		// Ensure only recommended items are retrieved and grouped before removing
		await EnsureRecommendedItemsRetrievedAndGroupAsync();
		_ = await VerifySecurityHardening();
	}

	/// <summary>
	/// UI wrapper for RemoveSecurityHardening - calls the async Task method
	/// </summary>
	internal async void RemoveSecurityHardeningUI()
	{
		// Ensure only recommended items are retrieved and grouped before removing
		await EnsureRecommendedItemsRetrievedAndGroupAsync();
		await RemoveSecurityHardening();
	}

	#endregion

	/// <summary>
	/// Clean up resources when the ViewModel is disposed
	/// </summary>
	public void Dispose()
	{
		try
		{
			_dismServiceClient?.Dispose();
		}
		catch (Exception ex)
		{
			Logger.Write(string.Format(GlobalVars.GetStr("ErrorDisposingDISMServiceClient"), ex.Message), LogTypeIntel.Error);
		}
	}

	/// <summary>
	/// Wildcard-based patterns for network adapter vendors
	/// </summary>
	private static readonly FrozenDictionary<string, string> NetworkVendorPatterns = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
	{
		{ "Intel",     "Microsoft.Windows.*.Client.Intel*"     },
		{ "Broadcom",  "Microsoft.Windows.Wifi.Client.Broadcom*" },
		{ "Marvel",    "Microsoft.Windows.Wifi.Client.Marvel*"   },
		{ "Qualcomm",  "Microsoft.Windows.Wifi.Client.Qualcomm*" },
		{ "Ralink",    "Microsoft.Windows.Wifi.Client.Ralink*"   },
		{ "Realtek",   "Microsoft.Windows.*.Client.Realtek*"     }
	}.ToFrozenDictionary<string, string>();

	/// <summary>
	/// Simple wildcard matcher supporting '*' anywhere in the pattern (case-insensitive).
	/// '*' matches zero or more of any characters.
	/// </summary>
	private static bool WildcardMatch(string text, string pattern)
	{
		if (text == null) return false;
		if (pattern == null) return false;

		string[] parts = pattern.Split('*');
		int index = 0;

		// If pattern does not start with '*', the first part must be at the beginning
		bool mustStart = !pattern.StartsWith('*');
		// If pattern does not end with '*', the last part must be at the end
		bool mustEnd = !pattern.EndsWith('*');

		for (int i = 0; i < parts.Length; i++)
		{
			string part = parts[i];
			if (part.Length == 0)
			{
				continue;
			}

			int pos = text.IndexOf(part, index, StringComparison.OrdinalIgnoreCase);
			if (pos < 0)
			{
				return false;
			}

			if (i == 0 && mustStart && pos != 0)
			{
				return false;
			}

			index = pos + part.Length;

			if (i == parts.Length - 1 && mustEnd)
			{
				// If the last part must align to the end, ensure we ended exactly at the end
				return index == text.Length;
			}
		}

		// If mustEnd is true but last non-empty part ended before text end, fail
		if (mustEnd)
		{
			return index == text.Length;
		}

		return true;
	}

	/// <summary>
	/// Returns the vendor name ("Intel", "Broadcom", etc.) if the item name matches any of the network vendor patterns; otherwise null.
	/// </summary>
	private static string? GetNetworkVendor(string itemName)
	{
		foreach (KeyValuePair<string, string> kvp in NetworkVendorPatterns)
		{
			if (WildcardMatch(itemName, kvp.Value))
			{
				return kvp.Key;
			}
		}
		return null;
	}

	/// <summary>
	/// Select or unselect items of a specific network adapter vendor in the current (filtered) view.
	/// This works via the ListView <see cref="UIListView"/> so SelectionChanged keeps <see cref="ItemsSourceSelectedItems"/> in sync.
	/// </summary>
	internal void SetVendorSelection(string vendor, bool select)
	{
		if (_isUpdatingSelection) return;
		if (UIListView == null) return;

		// Operate only on the items currently visible in the grouped, filtered view
		if (select)
		{
			for (int g = 0; g < GroupedFilteredDISMItems.Count; g++)
			{
				GroupInfoListForDISMItems group = GroupedFilteredDISMItems[g];
				for (int i = 0; i < group.Count; i++)
				{
					DISMOutputEntry entry = group[i];
					string? matchVendor = GetNetworkVendor(entry.Name);
					if (string.Equals(vendor, matchVendor, StringComparison.OrdinalIgnoreCase))
					{
						UIListView.SelectedItems.Add(entry);
					}
				}
			}
		}
		else
		{
			// Remove from current selection those entries that match the vendor
			List<object> toRemove = [];
			for (int s = 0; s < UIListView.SelectedItems.Count; s++)
			{
				if (UIListView.SelectedItems[s] is DISMOutputEntry entry)
				{
					string? matchVendor = GetNetworkVendor(entry.Name);
					if (string.Equals(vendor, matchVendor, StringComparison.OrdinalIgnoreCase))
					{
						toRemove.Add(entry);
					}
				}
			}
			for (int r = 0; r < toRemove.Count; r++)
			{
				_ = UIListView.SelectedItems.Remove(toRemove[r]);
			}
		}
	}

	/// <summary>
	/// Event handler for "Select" vendor menu items (sender.Tag must be the vendor string)
	/// </summary>
	internal void SelectVendor_Click(object sender, RoutedEventArgs e)
	{
		MenuFlyoutItem? mi = sender as MenuFlyoutItem;
		string? vendor = mi?.Tag as string;
		if (string.IsNullOrEmpty(vendor)) return;

		SetVendorSelection(vendor, true);
	}

	/// <summary>
	/// Event handler for "Unselect" vendor menu items (sender.Tag must be the vendor string)
	/// </summary>
	internal void UnselectVendor_Click(object sender, RoutedEventArgs e)
	{
		MenuFlyoutItem? mi = sender as MenuFlyoutItem;
		string? vendor = mi?.Tag as string;
		if (string.IsNullOrEmpty(vendor)) return;

		SetVendorSelection(vendor, false);
	}

	/// <summary>
	/// Exports the optional features and capabilities to a JSON file
	/// </summary>
	internal async void ExportToJson_Click()
	{
		try
		{
			if (AllItems.Count == 0)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("NoOptionalFeaturesAvailableForExport"));
				return;
			}

			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			string? saveLocation = FileDialogHelper.ShowSaveFileDialog(
					"OSFeaturesAndCapabilities|*.JSON",
					"OSFeaturesAndCapabilities.JSON");

			if (saveLocation is null)
				return;

			await Task.Run(() =>
			{
				string jsonString = JsonSerializer.Serialize(AllItems, DISMOutputEntryJsonContext.Default.ListDISMOutputEntry);

				File.WriteAllText(saveLocation, jsonString, Encoding.UTF8);
			});

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyExportedOptionalFeatures"), AllItems.Count, saveLocation));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}
}
