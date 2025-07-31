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
				LogReceived?.Invoke(GlobalVars.GetStr("DISMServiceFileIntegrityVerificationFailed"), LogTypeIntel.Error);
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
						LogReceived?.Invoke(string.Format(GlobalVars.GetStr("FailedToCreateProcessWin32Error"), error), LogTypeIntel.Error);
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

	internal bool ButtonsEnabled => !IsProcessing && ParentVM.ElementsAreEnabled;

	internal SolidColorBrush BorderBrush => IsProcessing
		? new SolidColorBrush(Color.FromArgb(255, 255, 20, 147)) // Hot pink
		: new SolidColorBrush(Color.FromArgb(0, 0, 0, 0)); // Transparent

	internal string StateDisplayName => State switch
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

	internal string TypeDisplayName => Type == DISMResultType.Feature ? GlobalVars.GetStr("FeatureType") : GlobalVars.GetStr("CapabilityType");

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
		try
		{
			await ParentVM.EnableItemAsync(this);
		}
		catch (Exception ex)
		{
			Logger.Write(ErrorWriter.FormatException(ex));
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
			Logger.Write(ErrorWriter.FormatException(ex));
		}
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
	/// The main InfoBar for this VM.
	/// </summary>
	internal readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	internal Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal ObservableCollection<DISMOutputEntry> DISMItemsLVBound = [];
	internal ObservableCollection<DISMOutputEntry> FilteredDISMItems = [];

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
				foreach (DISMOutputEntry entry in DISMItemsLVBound)
				{
					entry.NotifyButtonsEnabledChanged();
				}
			}
		}
	} = true;

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

		// Update counts
		TotalItemsCount = DISMItemsLVBound.Count;
		FilteredItemsCount = FilteredDISMItems.Count;

		// Sync ListView selection with our selection list after filtering
		SyncListViewSelection();
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

			// Re-select items that are in our selection list and currently visible in filtered items
			foreach (DISMOutputEntry selectedItem in ItemsSourceSelectedItems)
			{
				if (FilteredDISMItems.Contains(selectedItem))
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
	/// Update the selected items count display
	/// </summary>
	private void UpdateSelectedItemsCount()
	{
		SelectedItemsCount = ItemsSourceSelectedItems.Count;
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
							MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("ProgressInfo"), current, total, percentage.ToString("F1")));
						}
						else
						{
							MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("ProgressUnknownInfo"), current));
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
						MainInfoBar.WriteWarning(GlobalVars.GetStr("FailedToStartDISMServiceAdministrator"));
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
				MainInfoBar.WriteError(ex, GlobalVars.GetStr("FailedToInitializeDISMService"));
				Logger.Write(string.Format(GlobalVars.GetStr("FailedToInitializeDISMService"), ex.Message), LogTypeIntel.Error);
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
			ElementsAreEnabled = false;

			// Clear existing items and reset their processing state
			DISMItemsLVBound.Clear();
			FilteredDISMItems.Clear();
			ItemsSourceSelectedItems.Clear();

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

			// Update filtered items and counts
			UpdateFilteredItems();
			UpdateSelectedItemsCount();

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
			// Disable buttons and search, but set processing state for the specific item
			await Dispatcher.EnqueueAsync(() =>
			{
				ElementsAreEnabled = false;
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
				await Dispatcher.EnqueueAsync(() =>
				{
					MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("FailedToEnableItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name));
				});
			}
		}
		catch (Exception ex)
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				MainInfoBar.WriteError(ex, string.Format(GlobalVars.GetStr("ErrorEnablingItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name));
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
				ElementsAreEnabled = true;
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
				ElementsAreEnabled = false;
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
				await Dispatcher.EnqueueAsync(() =>
				{
					MainInfoBar.WriteWarning(string.Format(GlobalVars.GetStr("FailedToDisableItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name));
				});
			}
		}
		catch (Exception ex)
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				MainInfoBar.WriteError(ex, string.Format(GlobalVars.GetStr("ErrorDisablingItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name));
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
				ElementsAreEnabled = true;
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
							Logger.Write(string.Format(GlobalVars.GetStr("SuccessfullyEnabledItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name), LogTypeIntel.Information);
						}
						else
						{
							failureCount++;
							failedItems.Add($"{entry.TypeDisplayName}: {entry.Name}");
							Logger.Write(string.Format(GlobalVars.GetStr("FailedToEnableItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name), LogTypeIntel.Warning);
						}
					}
					catch (Exception ex)
					{
						failureCount++;
						failedItems.Add($"{entry.TypeDisplayName}: {entry.Name}");
						Logger.Write(string.Format(GlobalVars.GetStr("ErrorEnablingItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name) + $": {ex.Message}", LogTypeIntel.Error);
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
					Logger.Write(string.Format(GlobalVars.GetStr("FailedItems"), failedItemsList), LogTypeIntel.Warning);
				}
			});
		}
		catch (Exception ex)
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				MainInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorDuringBulkEnableOperation"));
			});
		}
		finally
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				ElementsAreEnabled = true;
			});
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
							Logger.Write(string.Format(GlobalVars.GetStr("SuccessfullyDisabledItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name), LogTypeIntel.Information);
						}
						else
						{
							failureCount++;
							failedItems.Add($"{entry.TypeDisplayName}: {entry.Name}");
							Logger.Write(string.Format(GlobalVars.GetStr("FailedToDisableItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name), LogTypeIntel.Warning);
						}
					}
					catch (Exception ex)
					{
						failureCount++;
						failedItems.Add($"{entry.TypeDisplayName}: {entry.Name}");
						Logger.Write(string.Format(GlobalVars.GetStr("ErrorDisablingItem"), entry.TypeDisplayName.ToLowerInvariant(), entry.Name) + $": {ex.Message}", LogTypeIntel.Error);
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
					Logger.Write(string.Format(GlobalVars.GetStr("FailedItems"), failedItemsList), LogTypeIntel.Warning);
				}
			});
		}
		catch (Exception ex)
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				MainInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorDuringBulkDisableOperation"));
			});
		}
		finally
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				ElementsAreEnabled = true;
			});
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

		foreach (DISMOutputEntry item in FilteredDISMItems)
		{
			UIListView?.SelectedItems.Add(item);
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
		UpdateSelectedItemsCount();
	}

	#endregion

	#region Bulk Operations for Protect Tab

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
		HashSet<DismPackageFeatureState> validVerificationStates)
	{
		internal string Name => name;
		internal DISMResultType Type => type;
		internal ApplyOperation ApplyStrategy => applyStrategy;
		internal ApplyOperation RemoveStrategy => removeStrategy;
		internal HashSet<DismPackageFeatureState> ValidVerificationStates => validVerificationStates;
	}

	/// <summary>
	/// Predefined configurations for this hardening category that needs to run to provide a secure system state.
	/// </summary>
	private static readonly FrozenDictionary<string, OptionalFeatureConfig> SecurityHardeningConfigs = new Dictionary<string, OptionalFeatureConfig>(StringComparer.OrdinalIgnoreCase)
{

#region FEATURES

	{
	"MicrosoftWindowsPowerShellV2",
	new OptionalFeatureConfig(
		name:                   "MicrosoftWindowsPowerShellV2",
		type:                   DISMResultType.Feature,
		applyStrategy:          ApplyOperation.Disable,  // Apply = Disable
		removeStrategy:         ApplyOperation.Enable,   // Remove = Enable (restore)
		validVerificationStates:[DismPackageFeatureState.DismStateRemoved,
		 DismPackageFeatureState.DismStateNotPresent]
	)
},
{
	"MicrosoftWindowsPowerShellV2Root",
	new OptionalFeatureConfig(
		name:                   "MicrosoftWindowsPowerShellV2Root",
		type:                   DISMResultType.Feature,
		applyStrategy:          ApplyOperation.Disable,
		removeStrategy:         ApplyOperation.Enable,
		validVerificationStates:[DismPackageFeatureState.DismStateRemoved,
		DismPackageFeatureState.DismStateNotPresent]
	)
},
{
	"WorkFolders-Client",
	new OptionalFeatureConfig(
		name:                   "WorkFolders-Client",
		type:                   DISMResultType.Feature,
		applyStrategy:          ApplyOperation.Disable,
		removeStrategy:         ApplyOperation.Enable,
		validVerificationStates:[DismPackageFeatureState.DismStateRemoved,
		DismPackageFeatureState.DismStateNotPresent]
	)
},
{
	"Printing-Foundation-InternetPrinting-Client",
	new OptionalFeatureConfig(
		name:                   "Printing-Foundation-InternetPrinting-Client",
		type:                   DISMResultType.Feature,
		applyStrategy:          ApplyOperation.Disable,
		removeStrategy:         ApplyOperation.Enable,
		validVerificationStates:[DismPackageFeatureState.DismStateRemoved,
		DismPackageFeatureState.DismStateNotPresent]
	)
},
{
	"Windows-Defender-ApplicationGuard",
	new OptionalFeatureConfig(
		name:                   "Windows-Defender-ApplicationGuard",
		type:                   DISMResultType.Feature,
		applyStrategy:          ApplyOperation.Disable,
		removeStrategy:         ApplyOperation.Enable,
		validVerificationStates:[DismPackageFeatureState.DismStateRemoved,
		DismPackageFeatureState.DismStateNotPresent]
	)
},
{
	"Containers-DisposableClientVM",
	new OptionalFeatureConfig(
		name:                   "Containers-DisposableClientVM",
		type:                   DISMResultType.Feature,
		applyStrategy:          ApplyOperation.Enable,   // Apply = Enable
		removeStrategy:         ApplyOperation.Disable,  // Remove = Disable (undo)
		validVerificationStates:[DismPackageFeatureState.DismStateInstalled,
		DismPackageFeatureState.DismStateInstallPending]
	)
},
{
	"Microsoft-Hyper-V-All",
	new OptionalFeatureConfig(
		name:                   "Microsoft-Hyper-V-All",
		type:                   DISMResultType.Feature,
		applyStrategy:          ApplyOperation.Enable,
		removeStrategy:         ApplyOperation.Disable,
		validVerificationStates:[DismPackageFeatureState.DismStateInstalled,
		DismPackageFeatureState.DismStateInstallPending]
	)
},

#endregion

#region CAPABILITIES

	{
	"Media.WindowsMediaPlayer~~~~0.0.12.0",
	new OptionalFeatureConfig(
		name:                   "Media.WindowsMediaPlayer~~~~0.0.12.0",
		type:                   DISMResultType.Capability,
		applyStrategy:          ApplyOperation.Disable,  // Apply = Remove (disable for capabilities)
		removeStrategy:         ApplyOperation.Enable,   // Remove = Add (restore)
		validVerificationStates:[DismPackageFeatureState.DismStateNotPresent,
		DismPackageFeatureState.DismStateRemoved]
	)
},
{
	"WMIC~~~~",
	new OptionalFeatureConfig(
		name:                   "WMIC~~~~",
		type:                   DISMResultType.Capability,
		applyStrategy:          ApplyOperation.Disable,
		removeStrategy:         ApplyOperation.Enable,
		validVerificationStates:[DismPackageFeatureState.DismStateNotPresent,
		DismPackageFeatureState.DismStateRemoved]
	)
},
{
	"Microsoft.Windows.Notepad.System~~~~0.0.1.0",
	new OptionalFeatureConfig(
		name:                   "Microsoft.Windows.Notepad.System~~~~0.0.1.0",
		type:                   DISMResultType.Capability,
		applyStrategy:          ApplyOperation.Disable,
		removeStrategy:         ApplyOperation.Enable,
		validVerificationStates:[DismPackageFeatureState.DismStateNotPresent,
		DismPackageFeatureState.DismStateRemoved]
	)
},
{
	"Microsoft.Windows.WordPad~~~~0.0.1.0",
	new OptionalFeatureConfig(
		name:                   "Microsoft.Windows.WordPad~~~~0.0.1.0",
		type:                   DISMResultType.Capability,
		applyStrategy:          ApplyOperation.Disable,
		removeStrategy:         ApplyOperation.Enable,
		validVerificationStates:[DismPackageFeatureState.DismStateNotPresent,
		DismPackageFeatureState.DismStateRemoved]
	)
},
{
	"Microsoft.Windows.PowerShell.ISE~~~~0.0.1.0",
	new OptionalFeatureConfig(
		name:                   "Microsoft.Windows.PowerShell.ISE~~~~0.0.1.0",
		type:                   DISMResultType.Capability,
		applyStrategy:          ApplyOperation.Disable,
		removeStrategy:         ApplyOperation.Enable,
		validVerificationStates:[DismPackageFeatureState.DismStateNotPresent,
		DismPackageFeatureState.DismStateRemoved]
	)
},
{
	"App.StepsRecorder~~~~0.0.1.0",
	new OptionalFeatureConfig(
		name:                   "App.StepsRecorder~~~~0.0.1.0",
		type:                   DISMResultType.Capability,
		applyStrategy:          ApplyOperation.Disable,
		removeStrategy:         ApplyOperation.Enable,
		validVerificationStates:[DismPackageFeatureState.DismStateNotPresent,
		DismPackageFeatureState.DismStateRemoved]
	)
},
{
	"VBSCRIPT~~~~",
	new OptionalFeatureConfig(
		name:                   "VBSCRIPT~~~~",
		type:                   DISMResultType.Capability,
		applyStrategy:          ApplyOperation.Disable,
		removeStrategy:         ApplyOperation.Enable,
		validVerificationStates:[DismPackageFeatureState.DismStateNotPresent,
		DismPackageFeatureState.DismStateRemoved]
	)
},
{
	"Browser.InternetExplorer~~~~0.0.11.0",
	new OptionalFeatureConfig(
		name:                   "Browser.InternetExplorer~~~~0.0.11.0",
		type:                   DISMResultType.Capability,
		applyStrategy:          ApplyOperation.Disable,
		removeStrategy:         ApplyOperation.Enable,
		validVerificationStates:[DismPackageFeatureState.DismStateNotPresent,
		DismPackageFeatureState.DismStateRemoved]
	)
}

#endregion

}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

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
	/// Called from the Protect tab when Optional Windows Features category is applied.
	/// </summary>
	internal async Task ApplySecurityHardening()
	{
		try
		{
			ElementsAreEnabled = false;

			// Initialize DISM service if not already done
			if (!await InitializeDismServiceAsync())
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("FailedToInitializeDISMServiceForSecurityHardening"));
				return;
			}

			int successCount = 0;
			int failureCount = 0;
			List<string> failedItems = [];

			MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("StartingWithOptionalWindowsFeatures"), SecurityHardeningConfigs.Count));

			await Task.Run(async () =>
			{
				foreach (OptionalFeatureConfig config in SecurityHardeningConfigs.Values)
				{
					try
					{
						bool result = await ExecuteOperationAsync(config, config.ApplyStrategy);

						if (result)
						{
							successCount++;
							string operationName = config.ApplyStrategy == ApplyOperation.Enable ? "enabled" : "disabled";
							Logger.Write(string.Format(GlobalVars.GetStr("SuccessfullyEnabledItem"), config.Type.ToString().ToLowerInvariant(), config.Name), LogTypeIntel.Information);
						}
						else
						{
							failureCount++;
							string operationName = config.ApplyStrategy == ApplyOperation.Enable ? "enable" : "disable";
							failedItems.Add($"{config.Type}: {config.Name}");
							Logger.Write(string.Format(GlobalVars.GetStr("FailedToEnableItem"), config.Type.ToString().ToLowerInvariant(), config.Name), LogTypeIntel.Warning);
						}
					}
					catch (Exception ex)
					{
						failureCount++;
						string operationName = config.ApplyStrategy == ApplyOperation.Enable ? "enabling" : "disabling";
						failedItems.Add($"{config.Type}: {config.Name}");
						Logger.Write(string.Format(GlobalVars.GetStr("ErrorEnablingItem"), config.Type.ToString().ToLowerInvariant(), config.Name) + $": {ex.Message}", LogTypeIntel.Error);
					}
				}
			});

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
					Logger.Write(string.Format(GlobalVars.GetStr("FailedItems"), failedItemsList), LogTypeIntel.Warning);
				}
			});
		}
		catch (Exception ex)
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				MainInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorDuringSecurityHardeningOperation"));
			});
		}
		finally
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				ElementsAreEnabled = true;
			});
		}
	}

	/// <summary>
	/// Verify that security hardening has been applied correctly by checking if items are in their valid states
	/// Called from the Protect tab when Optional Windows Features category is verified
	/// </summary>
	internal async Task<bool> VerifySecurityHardening()
	{
		try
		{
			ElementsAreEnabled = false;

			// Initialize DISM service if not already done
			if (!await InitializeDismServiceAsync())
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("FailedToInitializeDISMServiceForVerification"));
				return false;
			}

			int correctCount = 0;
			int incorrectCount = 0;
			List<string> incorrectItems = [];

			MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("VerifyingSecurityHardeningState"), SecurityHardeningConfigs.Count));

			Dictionary<string, DismPackageFeatureState> actualStates = [];

			await Task.Run(async () =>
			{
				// Get current states for all targets
				string[] capabilityNames = SecurityHardeningConfigs.Values
					.Where(config => config.Type == DISMResultType.Capability)
					.Select(config => config.Name)
					.ToArray();

				string[] featureNames = SecurityHardeningConfigs.Values
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

				if (featureNames.Length > 0)
				{
					List<DISMOutput> featureResults = await _dismServiceClient!.GetSpecificFeaturesAsync(featureNames);
					foreach (DISMOutput result in featureResults)
					{
						actualStates[result.Name] = result.State;
					}
				}

				// Compare with valid verification states for each item
				foreach (OptionalFeatureConfig config in SecurityHardeningConfigs.Values)
				{
					if (actualStates.TryGetValue(config.Name, out DismPackageFeatureState actualState))
					{
						if (config.ValidVerificationStates.Contains(actualState))
						{
							correctCount++;
							Logger.Write($"Correct state for {config.Name}: {actualState}", LogTypeIntel.Information);
						}
						else
						{
							incorrectCount++;
							string validStates = string.Join(", ", config.ValidVerificationStates);
							incorrectItems.Add($"{config.Name} (Expected: {validStates}, Actual: {actualState})");
							Logger.Write($"Incorrect state for {config.Name}: Expected one of [{validStates}], Actual {actualState}", LogTypeIntel.Warning);
						}
					}
					else
					{
						// Item not found - check if "Not Present" is a valid state
						if (config.ValidVerificationStates.Contains(DismPackageFeatureState.DismStateNotPresent))
						{
							correctCount++;
							Logger.Write($"Correct state for {config.Name}: Not Present (as expected)", LogTypeIntel.Information);
						}
						else
						{
							incorrectCount++;
							string validStates = string.Join(", ", config.ValidVerificationStates);
							incorrectItems.Add($"{config.Name} (Expected: {validStates}, Actual: Not Found)");
							Logger.Write($"Item not found during verification: {config.Name}", LogTypeIntel.Warning);
						}
					}
				}
			});

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
						Logger.Write(string.Format(GlobalVars.GetStr("IncorrectItems"), incorrectItemsList), LogTypeIntel.Warning);
					}
				}
			});

			return allCorrect;
		}
		catch (Exception ex)
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				MainInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorDuringSecurityHardeningVerification"));
			});
			return false;
		}
		finally
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				ElementsAreEnabled = true;
			});
		}
	}

	/// <summary>
	/// Remove security hardening by executing the remove strategy for each item
	/// Called from the Protect tab when Optional Windows Features category is removed
	/// </summary>
	internal async Task RemoveSecurityHardening()
	{
		try
		{
			ElementsAreEnabled = false;

			// Initialize DISM service if not already done
			if (!await InitializeDismServiceAsync())
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("FailedToInitializeDISMServiceForRemovingSecurityHardening"));
				return;
			}

			int successCount = 0;
			int failureCount = 0;
			List<string> failedItems = [];

			MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("RemovingSecurityHardening"), SecurityHardeningConfigs.Count));

			await Task.Run(async () =>
			{
				foreach (OptionalFeatureConfig config in SecurityHardeningConfigs.Values)
				{
					try
					{
						bool result = await ExecuteOperationAsync(config, config.RemoveStrategy);

						if (result)
						{
							successCount++;
							string operationName = config.RemoveStrategy == ApplyOperation.Enable ? "restored" : "removed";
							Logger.Write(string.Format(GlobalVars.GetStr("SuccessfullyEnabledItem"), config.Type.ToString().ToLowerInvariant(), config.Name), LogTypeIntel.Information);
						}
						else
						{
							failureCount++;
							string operationName = config.RemoveStrategy == ApplyOperation.Enable ? "restore" : "remove";
							failedItems.Add($"{config.Type}: {config.Name}");
							Logger.Write(string.Format(GlobalVars.GetStr("FailedToEnableItem"), config.Type.ToString().ToLowerInvariant(), config.Name), LogTypeIntel.Warning);
						}
					}
					catch (Exception ex)
					{
						failureCount++;
						string operationName = config.RemoveStrategy == ApplyOperation.Enable ? "restoring" : "removing";
						failedItems.Add($"{config.Type}: {config.Name}");
						Logger.Write(string.Format(GlobalVars.GetStr("ErrorEnablingItem"), config.Type.ToString().ToLowerInvariant(), config.Name) + $": {ex.Message}", LogTypeIntel.Error);
					}
				}
			});

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
					Logger.Write(string.Format(GlobalVars.GetStr("FailedItems"), failedItemsList), LogTypeIntel.Warning);
				}
			});
		}
		catch (Exception ex)
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				MainInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorDuringSecurityHardeningRemovalOperation"));
			});
		}
		finally
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				ElementsAreEnabled = true;
			});
		}
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
