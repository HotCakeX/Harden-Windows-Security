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
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AppControlManager;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using CommunityToolkit.WinUI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace HardenWindowsSecurity.ViewModels;

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
					LogReceived?.Invoke($"Found existing DISMService process (PID: {process.Id}), terminating...", LogTypeIntel.Information);

					if (!process.HasExited)
					{
						process.Kill();
						_ = process.WaitForExit(2000);
					}

					LogReceived?.Invoke($"Successfully terminated DISMService process (PID: {process.Id})", LogTypeIntel.Information);
				}
				catch (Exception ex)
				{
					LogReceived?.Invoke($"Failed to terminate DISMService process (PID: {process.Id}): {ex.Message}", LogTypeIntel.Warning);
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
			LogReceived?.Invoke($"Error while checking for existing DISMService processes: {ex.Message}", LogTypeIntel.Warning);
		}
	}

	private readonly string DISMServiceLocationInPackage = Path.Combine(AppContext.BaseDirectory, "DISMService.exe");

	private string DISMFileHash = string.Empty;

	private static readonly string SecureDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
		"HardenWindowsSecurity", "DISMService");

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
				LogReceived?.Invoke("DISM service file integrity check failed", LogTypeIntel.Error);
			}

			return isValid;
		}
		catch (Exception ex)
		{
			LogReceived?.Invoke($"Failed to verify DISM service integrity: {ex.Message}", LogTypeIntel.Error);
			return false;
		}
	}

	private IntPtr _processHandle = IntPtr.Zero;
	private NamedPipeClientStream? _pipeClient;
	private BinaryWriter? _writer;
	private BinaryReader? _reader;
	private readonly string _pipeName;
	private bool _disposed;

	internal event Action<uint, uint>? ProgressUpdated;
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
				LogReceived?.Invoke("DISM service file integrity verification failed. Cannot start service.", LogTypeIntel.Error);
				return false;
			}


			IntPtr desktopPtr = Marshal.StringToHGlobalUni("");
			IntPtr titlePtr = Marshal.StringToHGlobalUni("");

			try
			{
				return await Task.Run(async () =>
				{

					NativeMethods.STARTUPINFO startupInfo = new()
					{
						cb = (uint)Marshal.SizeOf<NativeMethods.STARTUPINFO>(),
						lpReserved = IntPtr.Zero,
						lpDesktop = desktopPtr,
						lpTitle = titlePtr,
						dwFlags = 0,
						wShowWindow = 0,
						cbReserved2 = 0,
						lpReserved2 = IntPtr.Zero,
						hStdInput = IntPtr.Zero,
						hStdOutput = IntPtr.Zero,
						hStdError = IntPtr.Zero
					};

					string commandLine = $"\"{serviceExecutablePath}\" {_pipeName}";

					bool success = NativeMethods.CreateProcess(
						null,
						commandLine,
						IntPtr.Zero,
						IntPtr.Zero,
						false,
						CREATE_NO_WINDOW | DETACHED_PROCESS,
						IntPtr.Zero,
						null,
						ref startupInfo,
						out NativeMethods.PROCESS_INFORMATION processInfo);

					if (!success)
					{
						int error = Marshal.GetLastWin32Error();
						LogReceived?.Invoke($"Failed to create process. Win32 Error: {error}", LogTypeIntel.Error);
						return false;
					}

					_processHandle = processInfo.hProcess;

					_ = NativeMethods.CloseHandle(processInfo.hThread);

					// Wait a bit for the service to start
					await Task.Delay(2000);

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
			LogReceived?.Invoke($"Failed to start service: {ex.Message}", LogTypeIntel.Error);
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

			if (response == Response.Progress)
			{
				uint current = _reader.ReadUInt32();
				uint total = _reader.ReadUInt32();
				ProgressUpdated?.Invoke(current, total);
				continue;
			}

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
				LogReceived?.Invoke($"Service error: {errorMessage}", LogTypeIntel.Error);
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

				results.Add(new DISMOutput(name, state, type));
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
					_ = NativeMethods.TerminateProcess(_processHandle, 0);
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
		Progress = 3,
		ShutdownComplete = 4,
		Log = 5,
		ItemProgress = 6,
		Error = 255
	}
}


/// <summary>
/// Used as ListView data to display Features and Capabilities to manage.
/// </summary>
internal sealed partial class DISMOutputEntry : ViewModelBase
{
	internal string Name { get; }
	internal DISMResultType Type { get; }
	internal DismPackageFeatureState State
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(StateDisplayName));
			}
		}
	}

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
			}
		}
	}

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

	internal uint ProgressTotal
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

	internal double ProgressPercentage => ProgressTotal > 0 ? (ProgressCurrent * 100.0) / ProgressTotal : 0;

	internal string ProgressPercentageFormatted => ProgressPercentage.ToString("F1");

	internal Visibility ProgressBarVisibility => IsProcessing ? Visibility.Visible : Visibility.Collapsed;

	internal bool ButtonsEnabled => !IsProcessing && ParentVM.ButtonsEnabled;

	internal SolidColorBrush BorderBrush => IsProcessing
		? new SolidColorBrush(Color.FromArgb(255, 255, 20, 147)) // Hot pink
		: new SolidColorBrush(Color.FromArgb(0, 0, 0, 0)); // Transparent

	internal string StateDisplayName => State switch
	{
		DismPackageFeatureState.DismStateNotPresent => "Not Present",
		DismPackageFeatureState.DismStateUninstallPending => "Uninstall Pending",
		DismPackageFeatureState.DismStateStaged => "Staged",
		DismPackageFeatureState.DismStateRemoved => "Removed",
		DismPackageFeatureState.DismStateInstalled => "Installed",
		DismPackageFeatureState.DismStateInstallPending => "Install Pending",
		DismPackageFeatureState.DismStateSuperseded => "Superseded",
		DismPackageFeatureState.DismStatePartiallyInstalled => "Partially Installed",
		_ => "Unknown"
	};

	internal string TypeDisplayName => Type == DISMResultType.Feature ? "Feature" : "Capability";

	internal SolidColorBrush TypeColor => Type == DISMResultType.Feature
		? new SolidColorBrush(Color.FromArgb(255, 0, 120, 215))    // Blue for Features
		: new SolidColorBrush(Color.FromArgb(255, 16, 137, 62));   // Green for Capabilities

	internal OptionalWindowsFeaturesVM ParentVM { get; }

	internal DISMOutputEntry(DISMOutput dismOutput, OptionalWindowsFeaturesVM parentVM)
	{
		Name = dismOutput.Name;
		Type = dismOutput.Type;
		State = dismOutput.State;
		ParentVM = parentVM;
		IsProcessing = false;
		ProgressCurrent = 0;
		ProgressTotal = 0;
	}

	internal void UpdateProgress(uint current, uint total)
	{
		ProgressCurrent = current;
		ProgressTotal = total;
	}

	/// <summary>
	/// Trigger property change notification for ButtonsEnabled
	/// </summary>
	internal void NotifyButtonsEnabledChanged()
	{
		OnPropertyChanged(nameof(ButtonsEnabled));
	}

	/// <summary>
	/// Enable this specific feature or capability
	/// </summary>
	internal async void EnableItem()
	{
		await ParentVM.EnableItemAsync(this);
	}

	/// <summary>
	/// Disable this specific feature or capability
	/// </summary>
	internal async void DisableItem()
	{
		await ParentVM.DisableItemAsync(this);
	}
}

internal sealed partial class OptionalWindowsFeaturesVM : ViewModelBase, IDisposable
{
	private DismServiceClient? _dismServiceClient;

	internal OptionalWindowsFeaturesVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			null, null);

		UpdateFilteredItems();
	}

	/// <summary>
	/// The main InfoBar for the Settings VM.
	/// </summary>
	internal readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	internal Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal ObservableCollection<DISMOutputEntry> DISMItemsLVBound = [];
	internal ObservableCollection<DISMOutputEntry> FilteredDISMItems = [];

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

	// For buttons and search box
	internal bool ButtonsEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ProgressBarVisibility = field ? Visibility.Collapsed : Visibility.Visible;
				// Update all entry button states
				foreach (DISMOutputEntry entry in DISMItemsLVBound)
				{
					entry.NotifyButtonsEnabledChanged();
				}
			}
		}
	} = true;

	internal bool SearchEnabled { get; set => SP(ref field, value); } = true;

	private void UpdateFilteredItems()
	{
		FilteredDISMItems.Clear();

		if (string.IsNullOrWhiteSpace(SearchQuery))
		{
			foreach (DISMOutputEntry item in DISMItemsLVBound)
			{
				FilteredDISMItems.Add(item);
			}
		}
		else
		{
			string? query = SearchQuery.ToLowerInvariant();
			foreach (DISMOutputEntry item in DISMItemsLVBound.Where(x =>
				x.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
				x.TypeDisplayName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
				x.StateDisplayName.Contains(query, StringComparison.OrdinalIgnoreCase)))
			{
				FilteredDISMItems.Add(item);
			}
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

				// Subscribe to progress updates
				_dismServiceClient.ProgressUpdated += async (current, total) =>
				{
					// Update UI with progress information
					await Dispatcher.EnqueueAsync(() =>
					{
						if (total > 0)
						{
							double percentage = (current * 100.0) / total;
							MainInfoBar.WriteInfo($"Progress: {current}/{total} ({percentage:F1}%)");
						}
						else
						{
							MainInfoBar.WriteInfo($"Progress: {current}/unknown");
						}
					});
				};

				// Subscribe to item-specific progress updates
				_dismServiceClient.ItemProgressUpdated += async (itemName, current, total) =>
				{
					// Update UI with item progress
					await Dispatcher.EnqueueAsync(() =>
					{
						DISMOutputEntry? entry = DISMItemsLVBound.FirstOrDefault(x => x.Name == itemName);
						entry?.UpdateProgress(current, total);
					});
				};

				// Subscribe to log messages
				_dismServiceClient.LogReceived += async (message, logType) =>
				{
					await Dispatcher.EnqueueAsync(() =>
					{
						switch (logType)
						{
							case LogTypeIntel.Information:
								Logger.Write(message, LogTypeIntel.Information);
								break;
							case LogTypeIntel.Warning:
								MainInfoBar.WriteWarning(message);
								Logger.Write(message, LogTypeIntel.Warning);
								break;
							case LogTypeIntel.Error:
								MainInfoBar.WriteWarning(message);
								Logger.Write(message, LogTypeIntel.Error);
								break;
							case LogTypeIntel.InformationInteractionRequired:
								break;
							case LogTypeIntel.WarningInteractionRequired:
								break;
							case LogTypeIntel.ErrorInteractionRequired:
								break;
							default:
								break;
						}
					});
				};

				_dismServiceClient.SecureCopyFile();

				// Start the service
				if (!await _dismServiceClient.StartServiceAsync(DismServiceClient.SecureDISMServicePath))
				{
					await Dispatcher.EnqueueAsync(() =>
					{
						MainInfoBar.WriteWarning("Failed to start DISM service. Make sure DismService.exe is in the application directory and you're running as Administrator.");
					});
					return false;
				}
			}

			return true;
		}
		catch (Exception ex)
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				MainInfoBar.WriteError(ex, "Failed to initialize DISM service");
				Logger.Write($"Failed to initialize DISM service: {ex.Message}", LogTypeIntel.Error);
			});
			return false;
		}
	}

	/// <summary>
	/// Event handler for the Load All button - loads all Windows features and capabilities
	/// </summary>
	internal async void LoadAll()
	{
		try
		{
			ButtonsEnabled = false;
			SearchEnabled = false;

			// Clear existing items and reset their processing state
			DISMItemsLVBound.Clear();
			FilteredDISMItems.Clear();

			// Initialize DISM service
			if (!await InitializeDismServiceAsync())
			{
				return;
			}

			// Retrieve all features and capabilities from the service
			List<DISMOutput> results = await _dismServiceClient!.GetAllResultsAsync();

			// Add results to the ListView
			foreach (DISMOutput result in results)
			{
				DISMItemsLVBound.Add(new DISMOutputEntry(result, this));
			}

			// Update filtered items
			UpdateFilteredItems();

			MainInfoBar.WriteSuccess($"Successfully loaded {results.Count} Windows features and capabilities.");
			Logger.Write($"Successfully loaded {results.Count} Windows features and capabilities.", LogTypeIntel.Information);
		}
		catch (Exception ex)
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				MainInfoBar.WriteError(ex, "Failed to load Windows features and capabilities");
				Logger.Write($"Failed to load Windows features and capabilities: {ex.Message}", LogTypeIntel.Error);
			});
		}
		finally
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				ButtonsEnabled = true;
				SearchEnabled = true;
			});
		}
	}

	/// <summary>
	/// Enable a specific feature or capability (async version)
	/// </summary>
	/// <param name="entry">The entry to enable</param>
	internal async Task EnableItemAsync(DISMOutputEntry entry)
	{
		try
		{
			// Disable buttons and search, but set processing state for the specific item
			await Dispatcher.EnqueueAsync(() =>
			{
				ButtonsEnabled = false;
				SearchEnabled = false;
				entry.IsProcessing = true;
				entry.ProgressCurrent = 0;
				entry.ProgressTotal = 0;
			});

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
						MainInfoBar.WriteSuccess($"Successfully enabled {entry.TypeDisplayName.ToLower()}: {entry.Name}");
					}
					else
					{
						MainInfoBar.WriteWarning($"Could not verify state after enabling {entry.TypeDisplayName.ToLower()}: {entry.Name}");
					}
				});
			}
			else
			{
				await Dispatcher.EnqueueAsync(() =>
				{
					MainInfoBar.WriteWarning($"Failed to enable {entry.TypeDisplayName.ToLower()}: {entry.Name}");
				});
			}
		}
		catch (Exception ex)
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				MainInfoBar.WriteError(ex, $"Error enabling {entry.TypeDisplayName.ToLower()}: {entry.Name}");
				Logger.Write($"Error enabling {entry.TypeDisplayName.ToLower()} '{entry.Name}': {ex.Message}", LogTypeIntel.Error);
			});
		}
		finally
		{
			// Always reset processing state and re-enable buttons and search
			await Dispatcher.EnqueueAsync(() =>
			{
				entry.IsProcessing = false;
				entry.ProgressCurrent = 0;
				entry.ProgressTotal = 0;
				ButtonsEnabled = true;
				SearchEnabled = true;
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
			// Disable buttons and search, but set processing state for the specific item
			await Dispatcher.EnqueueAsync(() =>
			{
				ButtonsEnabled = false;
				SearchEnabled = false;
				entry.IsProcessing = true;
				entry.ProgressCurrent = 0;
				entry.ProgressTotal = 0;
			});

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
						MainInfoBar.WriteSuccess($"Successfully disabled {entry.TypeDisplayName.ToLower()}: {entry.Name}");
					}
					else
					{
						MainInfoBar.WriteWarning($"Could not verify state after disabling {entry.TypeDisplayName.ToLower()}: {entry.Name}");
					}
				});
			}
			else
			{
				await Dispatcher.EnqueueAsync(() =>
				{
					MainInfoBar.WriteWarning($"Failed to disable {entry.TypeDisplayName.ToLower()}: {entry.Name}");
				});
			}
		}
		catch (Exception ex)
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				MainInfoBar.WriteError(ex, $"Error disabling {entry.TypeDisplayName.ToLower()}: {entry.Name}");
				Logger.Write($"Error disabling {entry.TypeDisplayName.ToLower()} '{entry.Name}': {ex.Message}", LogTypeIntel.Error);
			});
		}
		finally
		{
			// Always reset processing state and re-enable buttons and search
			await Dispatcher.EnqueueAsync(() =>
			{
				entry.IsProcessing = false;
				entry.ProgressCurrent = 0;
				entry.ProgressTotal = 0;
				ButtonsEnabled = true;
				SearchEnabled = true;
			});
		}
	}

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
			Logger.Write($"Error disposing DISM service client: {ex.Message}", LogTypeIntel.Error);
		}
	}
}

internal sealed class DISMOutput
{
	internal string Name { get; }
	internal DismPackageFeatureState State { get; }
	internal DISMResultType Type { get; }

	internal DISMOutput(string name, DismPackageFeatureState state, DISMResultType type)
	{
		Name = name;
		State = state;
		Type = type;
	}
}

internal enum DismPackageFeatureState
{
	DismStateNotPresent = 0,
	DismStateUninstallPending = 1,
	DismStateStaged = 2,
	DismStateRemoved = 3,
	DismStateInstalled = 4,
	DismStateInstallPending = 5,
	DismStateSuperseded = 6,
	DismStatePartiallyInstalled = 7
}

internal enum DISMResultType
{
	Capability,
	Feature
}
