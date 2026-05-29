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
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml.Linq;
using AppControlManager.CustomUIElements;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class SandboxMakerVM : ViewModelBase
{
	private const string DefinitionsFileName = "SandboxMakerDefinitions.json";
	private const string SandboxStorageFolderName = "SandboxMaker";
	internal const double MinimumAllowedSelectedRAMValue = 2000D;
	private const double DefaultMaximumAllowedSelectedRAM = 4000D;
	private const double HostReservedMemoryInMb = 4000D;

	private static readonly Encoding Utf8WithoutBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

	private static readonly string SandboxConfigurationDirectory =
		Directory.CreateDirectory(Path.Combine(Microsoft.Windows.Storage.ApplicationData.GetDefault().LocalCachePath, SandboxStorageFolderName)).FullName;

	private static readonly string DefinitionsFilePath = Path.Combine(SandboxConfigurationDirectory, DefinitionsFileName);


	internal static readonly List<WindowsSandboxTimeZoneOption> TimeZoneOptions =
	[
		new("Sandbox default time zone", "Same as host", null),
		.. new WindowsSandboxTimeZoneOption[]
		{
			new("Afghanistan", "UTC+04:30", "Afghanistan Standard Time"),
			new("Alaska, Gambier Islands (French Polynesia)", "UTC-09:00", "Alaskan Standard Time"),
			new("American Samoa, Niue (New Zealand)", "UTC-11:00", "UTC-11"),
			new("Argentina, Brazil (Eastern), Greenland (Eastern), Uruguay", "UTC-03:00", "SA Eastern Standard Time"),
			new("Armenia, Azerbaijan, Georgia, Oman, United Arab Emirates, Russia (Astrakhan), etc", "UTC+04:00", "Arabian Standard Time"),
			new("Atlantic Time (Canada), Bolivia, Brazil (Western), Chile, Paraguay", "UTC-04:00", "Atlantic Standard Time"),
			new("Australia (Central)", "UTC+09:30", "Cen. Australia Standard Time"),
			new("Australia (Eastern)", "UTC+10:00", "AUS Eastern Standard Time"),
			new("Baker Island, Howland Island (USA)", "UTC-12:00", "Dateline Standard Time"),
			new("Bangladesh, Kazakhstan, Kyrgyzstan, Russia (Omsk), etc", "UTC+06:00", "Central Asia Standard Time"),
			new("Cabo Verde, Azores (Portugal), Ittoqqortoormiit (Greenland)", "UTC-01:00", "Cape Verde Standard Time"),
			new("Central Time (USA and Canada), Central America, Mexico", "UTC-06:00", "Central America Standard Time"),
			new("Chatham Islands (New Zealand)", "UTC+12:45", "Chatham Islands Standard Time"),
			new("China, Mongolia, Malaysia, Singapore, Philippines, Indonesia (Central), Russia (Irkutsk), etc", "UTC+08:00", "China Standard Time"),
			new("Eastern Time (USA and Canada), Colombia, Peru, Ecuador", "UTC-05:00", "Eastern Standard Time"),
			new("Eucla (Australia)", "UTC+08:45", "Aus Central W. Standard Time"),
			new("France, Germany, Spain, Italy, Poland, Nigeria, Algeria, etc", "UTC+01:00", "W. Europe Standard Time"),
			new("Greece, Turkey, Romania, Bulgaria, Ukraine, Egypt, South Africa, etc", "UTC+02:00", "E. Europe Standard Time"),
			new("Hawaii, Cook Islands (New Zealand)", "UTC-10:00", "Hawaiian Standard Time"),
			new("India, Sri Lanka", "UTC+05:30", "India Standard Time"),
			new("Israel/Jerusalem", "UTC+02:00", "Israel Standard Time"),
			new("Iran", "UTC+03:30", "Iran Standard Time"),
			new("Japan, Korea (North and South), Indonesia (Eastern), Russia (Yakutsk), etc", "UTC+09:00", "Tokyo Standard Time"),
			new("Kenya, Ethiopia, Saudi Arabia, Iraq, Russia (Kaliningrad), etc", "UTC+03:00", "Arab Standard Time"),
			new("Lord Howe Island (Australia)", "UTC+10:30", "Lord Howe Standard Time"),
			new("Marquesas Islands (French Polynesia)", "UTC-09:30", "Marquesas Standard Time"),
			new("Mountain Time (USA and Canada), Baja California (Mexico)", "UTC-07:00", "Mountain Standard Time"),
			new("Myanmar, Cocos (Keeling) Islands", "UTC+06:30", "Myanmar Standard Time"),
			new("New Zealand, Fiji", "UTC+12:00", "New Zealand Standard Time"),
			new("Newfoundland (Canada)", "UTC-03:30", "Newfoundland Standard Time"),
			new("Norfolk Island (Australia), Solomon Islands", "UTC+11:00", "UTC+11"),
			new("Pacific Time (USA and Canada), Pitcairn Islands (UK)", "UTC-08:00", "Pacific Standard Time"),
			new("Pakistan, Uzbekistan, Turkmenistan, Tajikistan, Russia (Samara), etc", "UTC+05:00", "West Asia Standard Time"),
			new("South Georgia and the South Sandwich Islands (UK)", "UTC-02:00", "UTC-02"),
			new("Thailand, Vietnam, Cambodia, Laos, Indonesia (Western), Russia (Krasnoyarsk), etc", "UTC+07:00", "SE Asia Standard Time"),
			new("United Kingdom, Ireland, Portugal, Senegal, Ghana, etc", "UTC+00:00", "GMT Standard Time"),
			new("Venezuela", "UTC-04:30", "Venezuela Standard Time")
		}
		.OrderBy(static option => option.OffsetMinutes)
		.ThenBy(static option => option.RegionName, StringComparer.Ordinal)
	];

	internal static readonly List<WindowsSandboxCustomPowerShellTimingOption> CustomPowerShellLaunchTimingOptions =
	[
		new("Before mapped program launch", WindowsSandboxCustomPowerShellLaunchTiming.BeforeMappedProgramLaunch),
		new("After mapped program launch", WindowsSandboxCustomPowerShellLaunchTiming.AfterMappedProgramLaunch)
	];

	internal readonly InfoBarSettings MainInfoBar = new();
	internal readonly ObservableCollection<WindowsSandboxProgramOption> AvailableProgramExecutables = [];
	internal readonly ObservableCollection<WindowsSandboxSavedDefinition> SavedSandboxes = [];

	internal string? SandboxName
	{
		get; set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(SandboxConfigurationPath));
			}
		}
	} = "My Sandbox";

	internal string SandboxConfigurationPath => string.IsNullOrWhiteSpace(SandboxName) ? string.Empty : GetSandboxConfigurationPath(SandboxName);

	internal WindowsSandboxTimeZoneOption SelectedTimeZone { get; set => SP(ref field, value); } = TimeZoneOptions[0];
	internal WindowsSandboxProgramOption? SelectedProgramExecutable { get; set => SP(ref field, value); }
	internal WindowsSandboxCustomPowerShellTimingOption SelectedCustomPowerShellLaunchTiming { get; set => SP(ref field, value); } = CustomPowerShellLaunchTimingOptions[0];
	internal string? SelectedProgramFolderPath { get; private set => SP(ref field, value); }
	internal string? CustomPowerShellCode { get; set => SP(ref field, value); }

	internal bool HasProgramFolderSelection { get; private set => SP(ref field, value); }
	internal bool HasProgramExecutableChoices { get; private set => SP(ref field, value); }
	internal bool HasSavedSandboxes { get; private set => SP(ref field, value); }
	internal Visibility SavedSandboxesVisibility { get; private set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility SavedSandboxesEmptyVisibility { get; private set => SP(ref field, value); } = Visibility.Visible;

	internal double MemoryInMb
	{
		get; set
		{
			double validatedValue = ValidateRAM(value);
			_ = SP(ref field, validatedValue);
		}
	} = 4000D;
	internal bool DisableNetworking { get; set => SP(ref field, value); }
	internal bool EnableVGpu { get; set => SP(ref field, value); }
	internal bool EnableClipboardRedirection { get; set => SP(ref field, value); }
	internal bool EnableAudioInput { get; set => SP(ref field, value); }
	internal bool EnableVideoInput { get; set => SP(ref field, value); }
	internal bool EnablePrinterRedirection { get; set => SP(ref field, value); }
	internal bool EnableProtectedClient { get; set => SP(ref field, value); } = true;
	internal bool IsProgramFolderReadOnly { get; set => SP(ref field, value); } = true;
	internal bool RunMappedProgramOnStartup { get; set => SP(ref field, value); }
	internal bool RunCustomPowerShellOnStartup { get; set => SP(ref field, value); }

	internal readonly double MaxAllowedSelectedRAM = DefaultMaximumAllowedSelectedRAM;

	internal SandboxMakerVM()
	{
		LoadSavedSandboxes();

		// Let user only select RAM size between 2 GB and (Max RAM - 4 GB reserved for the host).
		bool ok = NativeMethods.GetPhysicallyInstalledSystemMemory(out ulong totalKilobytes);

		if (ok && totalKilobytes > 0)
		{
			try
			{
				double installedMemoryInMb = totalKilobytes / 1024D; // KB -> MB
				double computedMaximum = installedMemoryInMb - HostReservedMemoryInMb;
				MaxAllowedSelectedRAM = computedMaximum >= MinimumAllowedSelectedRAMValue
					? computedMaximum
					: MinimumAllowedSelectedRAMValue;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}
		}

		MemoryInMb = ValidateRAM(MemoryInMb);
	}

	private double ValidateRAM(double value)
	{
		if (!double.IsFinite(value))
		{
			return MinimumAllowedSelectedRAMValue;
		}

		if (value < MinimumAllowedSelectedRAMValue)
		{
			return MinimumAllowedSelectedRAMValue;
		}

		if (value > MaxAllowedSelectedRAM)
		{
			return MaxAllowedSelectedRAM;
		}

		return value;
	}

	internal void BrowseProgramFolder_Click()
	{
		try
		{
			string? selectedFolderPath = FileDialogHelper.ShowDirectoryPickerDialog();
			if (string.IsNullOrWhiteSpace(selectedFolderPath))
			{
				return;
			}

			SelectedProgramFolderPath = selectedFolderPath;
			RefreshProgramExecutables(null);
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	internal void ClearProgramFolder_Click()
	{
		SelectedProgramFolderPath = null;
		SelectedProgramExecutable = null;
		HasProgramFolderSelection = false;
		HasProgramExecutableChoices = false;
		RunMappedProgramOnStartup = false;
		AvailableProgramExecutables.Clear();
	}

	internal void SaveSandbox_Click()
	{
		try
		{
			WindowsSandboxSavedDefinition definition = SaveCurrentSandbox();
			MainInfoBar.WriteSuccess($"Saved sandbox \"{definition.Name}\".");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	internal void StartSandbox_Click()
	{
		try
		{
			WindowsSandboxSavedDefinition definition = SaveCurrentSandbox();
			string sandboxConfigurationPath = GetSandboxConfigurationPath(definition.Name);
			LaunchSandbox(sandboxConfigurationPath);
			MainInfoBar.WriteSuccess($"Started sandbox \"{definition.Name}\".");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	internal void LaunchSavedSandbox_Click(object sender, RoutedEventArgs e)
	{
		if ((sender as FrameworkElement)?.Tag is not WindowsSandboxSavedDefinition definition)
		{
			return;
		}

		try
		{
			ValidateDefinition(definition);
			string sandboxConfigurationPath = CreateSandboxConfigurationFile(definition);
			LaunchSandbox(sandboxConfigurationPath);
			MainInfoBar.WriteSuccess($"Started sandbox \"{definition.Name}\".");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	internal void OpenSavedSandboxFileLocation_Click(object sender, RoutedEventArgs e)
	{
		if ((sender as FrameworkElement)?.Tag is not WindowsSandboxSavedDefinition definition)
		{
			return;
		}

		try
		{
			OpenPathInExplorer(GetSandboxConfigurationPath(definition.Name));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	internal async void DeleteSavedSandbox_Click(object sender, RoutedEventArgs e)
	{
		if ((sender as FrameworkElement)?.Tag is not WindowsSandboxSavedDefinition definition)
		{
			return;
		}

		using ContentDialogV2 deleteDialog = new()
		{
			Title = "Delete saved sandbox?",
			Content = new TextBlock
			{
				Text = $"This will remove \"{definition.Name}\" from the saved sandboxes list and delete its .wsb file if it exists.",
				TextWrapping = TextWrapping.Wrap
			},
			PrimaryButtonText = "Delete",
			CloseButtonText = "Cancel",
			DefaultButton = ContentDialogButton.Close
		};

		ContentDialogResult result = await deleteDialog.ShowAsync();
		if (result is not ContentDialogResult.Primary)
		{
			return;
		}

		try
		{
			string sandboxConfigurationPath = GetSandboxConfigurationPath(definition.Name);
			if (File.Exists(sandboxConfigurationPath))
			{
				File.Delete(sandboxConfigurationPath);
			}

			int removedCount = SavedSandboxes.Remove(definition) ? 1 : 0;
			if (removedCount == 0)
			{
				return;
			}

			PersistSavedSandboxes();
			UpdateSavedSandboxesState();
			MainInfoBar.WriteSuccess($"Deleted saved sandbox \"{definition.Name}\".");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	internal async void DeleteAllSavedSandboxes_Click()
	{
		if (SavedSandboxes.Count == 0)
		{
			MainInfoBar.WriteWarning("There are no saved sandboxes to delete.");
			return;
		}

		using ContentDialogV2 deleteDialog = new()
		{
			Title = "Delete all saved sandboxes?",
			Content = new TextBlock
			{
				Text = "This will remove every saved sandbox from the list and delete each generated .wsb file if it exists.",
				TextWrapping = TextWrapping.Wrap
			},
			PrimaryButtonText = "Delete all",
			CloseButtonText = "Cancel",
			DefaultButton = ContentDialogButton.Close
		};

		ContentDialogResult result = await deleteDialog.ShowAsync();
		if (result is not ContentDialogResult.Primary)
		{
			return;
		}

		try
		{
			List<WindowsSandboxSavedDefinition> savedDefinitions = [.. SavedSandboxes];

			foreach (WindowsSandboxSavedDefinition definition in CollectionsMarshal.AsSpan(savedDefinitions))
			{
				string sandboxConfigurationPath = GetSandboxConfigurationPath(definition.Name);
				if (File.Exists(sandboxConfigurationPath))
				{
					File.Delete(sandboxConfigurationPath);
				}
			}

			SavedSandboxes.Clear();
			PersistSavedSandboxes();
			UpdateSavedSandboxesState();
			MainInfoBar.WriteSuccess("Deleted all saved sandboxes.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	internal void LoadSavedSandboxIntoEditor_Click(object sender, RoutedEventArgs e)
	{
		if ((sender as FrameworkElement)?.Tag is not WindowsSandboxSavedDefinition definition)
		{
			return;
		}

		try
		{
			ApplyDefinitionToEditor(definition);
			MainInfoBar.WriteSuccess($"Loaded \"{definition.Name}\" into the editor.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	internal static string GetSandboxConfigurationPath(string sandboxName)
	{
		string normalizedName = GetValidatedSandboxName(sandboxName);
		return GetSandboxConfigurationPathCore(normalizedName);
	}

	private static string GetSandboxConfigurationPathCore(string sandboxName)
	{
		string safeFileName = GetSafeFileName(sandboxName);
		return Path.Combine(SandboxConfigurationDirectory, safeFileName + ".wsb");
	}

	internal static string GetTimeZoneDisplayLabel(string? timeZoneId)
	{
		if (string.IsNullOrWhiteSpace(timeZoneId))
		{
			return TimeZoneOptions[0].OffsetLabel;
		}

		WindowsSandboxTimeZoneOption? timeZoneOption = TimeZoneOptions.FirstOrDefault(option =>
			string.Equals(option.TimeZoneId, timeZoneId, StringComparison.Ordinal));

		return timeZoneOption?.OffsetLabel ?? timeZoneId;
	}

	internal static string GetCustomPowerShellLaunchTimingDisplayLabel(WindowsSandboxCustomPowerShellLaunchTiming customPowerShellLaunchTiming)
	{
		WindowsSandboxCustomPowerShellTimingOption? launchTimingOption = CustomPowerShellLaunchTimingOptions.FirstOrDefault(option =>
			option.LaunchTiming == customPowerShellLaunchTiming);

		return launchTimingOption?.DisplayName ?? CustomPowerShellLaunchTimingOptions[0].DisplayName;
	}

	private void ApplyDefinitionToEditor(WindowsSandboxSavedDefinition definition)
	{
		SandboxName = definition.Name;
		MemoryInMb = definition.MemoryInMb;
		DisableNetworking = definition.DisableNetworking;
		EnableVGpu = definition.EnableVGpu;
		EnableClipboardRedirection = definition.EnableClipboardRedirection;
		EnableAudioInput = definition.EnableAudioInput;
		EnableVideoInput = definition.EnableVideoInput;
		EnablePrinterRedirection = definition.EnablePrinterRedirection;
		EnableProtectedClient = definition.EnableProtectedClient;
		IsProgramFolderReadOnly = definition.IsProgramFolderReadOnly;
		RunMappedProgramOnStartup = definition.RunMappedProgramOnStartup;
		RunCustomPowerShellOnStartup = definition.RunCustomPowerShellOnStartup;
		CustomPowerShellCode = DecodeCustomPowerShellCodeFromStorage(definition.CustomPowerShellCode);
		SelectedTimeZone = TimeZoneOptions.FirstOrDefault(option =>
			string.Equals(option.TimeZoneId, definition.TimeZoneId, StringComparison.Ordinal)) ?? TimeZoneOptions[0];
		SelectedCustomPowerShellLaunchTiming = CustomPowerShellLaunchTimingOptions.FirstOrDefault(option =>
			option.LaunchTiming == definition.CustomPowerShellLaunchTiming) ?? CustomPowerShellLaunchTimingOptions[0];

		SelectedProgramFolderPath = definition.ProgramFolderPath;
		RefreshProgramExecutables(definition.ProgramExecutableRelativePath);
	}

	private void LoadSavedSandboxes()
	{
		try
		{
			if (!File.Exists(DefinitionsFilePath))
			{
				UpdateSavedSandboxesState();
				return;
			}

			List<WindowsSandboxSavedDefinition> savedDefinitions = ReadSavedDefinitionsFromDisk();
			ReplaceSavedSandboxes(savedDefinitions);
			PersistSavedSandboxes();
		}
		catch (Exception ex)
		{
			SavedSandboxes.Clear();
			UpdateSavedSandboxesState();
			MainInfoBar.WriteWarning("Saved sandboxes could not be loaded. The list has been reset for this session.");
			Logger.Write($"Failed to load saved sandboxes: {ex}");
		}
	}

	private void PersistSavedSandboxes()
	{
		List<WindowsSandboxSavedDefinition> savedDefinitions = [.. SavedSandboxes.OrderBy(static definition => definition.Name, StringComparer.OrdinalIgnoreCase)];
		string json = JsonSerializer.Serialize(savedDefinitions, SandboxMakerDefinitionsJsonContext.Default.ListWindowsSandboxSavedDefinition);
		File.WriteAllText(DefinitionsFilePath, json, Utf8WithoutBom);
	}

	private void ReplaceSavedSandboxes(IEnumerable<WindowsSandboxSavedDefinition> definitions)
	{
		SavedSandboxes.Clear();

		foreach (WindowsSandboxSavedDefinition definition in definitions
			.OrderBy(static item => item.Name, StringComparer.OrdinalIgnoreCase))
		{
			SavedSandboxes.Add(definition);
		}

		UpdateSavedSandboxesState();
	}

	private void UpdateSavedSandboxesState()
	{
		bool hasSavedSandboxes = SavedSandboxes.Count > 0;
		HasSavedSandboxes = hasSavedSandboxes;
		SavedSandboxesVisibility = hasSavedSandboxes ? Visibility.Visible : Visibility.Collapsed;
		SavedSandboxesEmptyVisibility = hasSavedSandboxes ? Visibility.Collapsed : Visibility.Visible;
	}

	private void UpsertSavedSandbox(WindowsSandboxSavedDefinition definition)
	{
		WindowsSandboxSavedDefinition? existingDefinition = SavedSandboxes.FirstOrDefault(savedDefinition =>
			string.Equals(savedDefinition.Name, definition.Name, StringComparison.OrdinalIgnoreCase));

		if (existingDefinition is not null)
		{
			int existingIndex = SavedSandboxes.IndexOf(existingDefinition);
			SavedSandboxes[existingIndex] = definition;
		}
		else
		{
			SavedSandboxes.Add(definition);
		}

		List<WindowsSandboxSavedDefinition> updatedDefinitions = [.. SavedSandboxes];
		ReplaceSavedSandboxes(updatedDefinitions);
		PersistSavedSandboxes();
	}

	private WindowsSandboxSavedDefinition SaveCurrentSandbox()
	{
		WindowsSandboxSavedDefinition definition = CreateDefinitionFromCurrentState();
		_ = CreateSandboxConfigurationFile(definition);
		UpsertSavedSandbox(definition);
		return definition;
	}

	private static List<WindowsSandboxSavedDefinition> ReadSavedDefinitionsFromDisk()
	{
		string json = File.ReadAllText(DefinitionsFilePath);
		if (string.IsNullOrWhiteSpace(json))
		{
			return [];
		}

		List<WindowsSandboxSavedDefinition>? savedDefinitions = JsonSerializer.Deserialize(
			json,
			SandboxMakerDefinitionsJsonContext.Default.ListWindowsSandboxSavedDefinition);

		return savedDefinitions ?? [];
	}

	private WindowsSandboxSavedDefinition CreateDefinitionFromCurrentState()
	{
		string normalizedSandboxName = GetValidatedSandboxName(SandboxName);
		ValidateCurrentSelection();

		return new WindowsSandboxSavedDefinition
		{
			Name = normalizedSandboxName,
			TimeZoneId = SelectedTimeZone?.TimeZoneId,
			MemoryInMb = MemoryInMb,
			DisableNetworking = DisableNetworking,
			EnableVGpu = EnableVGpu,
			EnableClipboardRedirection = EnableClipboardRedirection,
			EnableAudioInput = EnableAudioInput,
			EnableVideoInput = EnableVideoInput,
			EnablePrinterRedirection = EnablePrinterRedirection,
			EnableProtectedClient = EnableProtectedClient,
			ProgramFolderPath = SelectedProgramFolderPath,
			ProgramExecutableRelativePath = SelectedProgramExecutable?.RelativePath,
			IsProgramFolderReadOnly = IsProgramFolderReadOnly,
			RunMappedProgramOnStartup = RunMappedProgramOnStartup,
			RunCustomPowerShellOnStartup = RunCustomPowerShellOnStartup,
			CustomPowerShellCode = EncodeCustomPowerShellCodeForStorage(CustomPowerShellCode),
			CustomPowerShellLaunchTiming = SelectedCustomPowerShellLaunchTiming.LaunchTiming,
			SavedAtUtc = DateTimeOffset.UtcNow
		};
	}

	private void RefreshProgramExecutables(string? selectedRelativePath)
	{
		AvailableProgramExecutables.Clear();
		SelectedProgramExecutable = null;
		HasProgramFolderSelection = !string.IsNullOrWhiteSpace(SelectedProgramFolderPath);
		HasProgramExecutableChoices = false;

		if (!HasProgramFolderSelection || SelectedProgramFolderPath is null)
		{
			return;
		}

		if (!Directory.Exists(SelectedProgramFolderPath))
		{
			throw new DirectoryNotFoundException($"The selected program folder does not exist: {SelectedProgramFolderPath}");
		}

		EnumerationOptions enumerationOptions = new()
		{
			RecurseSubdirectories = true,
			IgnoreInaccessible = true,
			ReturnSpecialDirectories = false,
			AttributesToSkip = FileAttributes.Hidden | FileAttributes.System
		};

		List<string> executablePaths = [.. Directory.EnumerateFiles(SelectedProgramFolderPath, "*.exe", enumerationOptions)];
		executablePaths.Sort(StringComparer.OrdinalIgnoreCase);

		string sandboxMappedProgramRoot = GetSandboxMappedProgramRoot(SelectedProgramFolderPath);

		foreach (string executablePath in executablePaths)
		{
			string relativePath = NormalizeWindowsPath(Path.GetRelativePath(SelectedProgramFolderPath, executablePath));
			string sandboxExecutablePath = CombineWindowsPath(sandboxMappedProgramRoot, relativePath);
			string displayName = Path.GetFileNameWithoutExtension(executablePath);

			AvailableProgramExecutables.Add(new WindowsSandboxProgramOption(displayName, relativePath));
		}

		HasProgramExecutableChoices = AvailableProgramExecutables.Count > 0;

		if (!string.IsNullOrWhiteSpace(selectedRelativePath))
		{
			SelectedProgramExecutable = AvailableProgramExecutables.FirstOrDefault(program =>
				string.Equals(program.RelativePath, NormalizeWindowsPath(selectedRelativePath), StringComparison.OrdinalIgnoreCase));
		}

		SelectedProgramExecutable ??= AvailableProgramExecutables.FirstOrDefault();

		if (!HasProgramExecutableChoices)
		{
			MainInfoBar.WriteWarning("No executable files were found inside the selected folder.");
		}
	}

	private void ValidateCurrentSelection()
	{
		MemoryInMb = ValidateRAM(MemoryInMb);

		if (!string.IsNullOrWhiteSpace(SelectedProgramFolderPath))
		{
			if (!Directory.Exists(SelectedProgramFolderPath))
			{
				throw new DirectoryNotFoundException($"The selected program folder does not exist: {SelectedProgramFolderPath}");
			}

			if (SelectedProgramExecutable is null)
			{
				throw new InvalidOperationException("Choose the main executable for the selected folder, or clear the program selection.");
			}

			string hostExecutablePath = Path.Combine(
				SelectedProgramFolderPath,
				SelectedProgramExecutable.RelativePath.Replace('\\', Path.DirectorySeparatorChar));

			if (!File.Exists(hostExecutablePath))
			{
				throw new FileNotFoundException($"The selected executable does not exist: {hostExecutablePath}", hostExecutablePath);
			}
		}

		if (RunCustomPowerShellOnStartup && string.IsNullOrWhiteSpace(CustomPowerShellCode))
		{
			throw new InvalidOperationException("Enter custom PowerShell code to run at sandbox startup, or turn off custom PowerShell startup code.");
		}
	}

	private void ValidateDefinition(WindowsSandboxSavedDefinition definition)
	{
		definition.MemoryInMb = ValidateRAM(definition.MemoryInMb);

		if (!string.IsNullOrWhiteSpace(definition.ProgramFolderPath))
		{
			if (!Directory.Exists(definition.ProgramFolderPath))
			{
				throw new DirectoryNotFoundException($"The selected program folder does not exist: {definition.ProgramFolderPath}");
			}

			if (string.IsNullOrWhiteSpace(definition.ProgramExecutableRelativePath))
			{
				throw new InvalidOperationException("The saved sandbox is missing its selected executable.");
			}

			string hostExecutablePath = Path.Combine(
				definition.ProgramFolderPath,
				definition.ProgramExecutableRelativePath.Replace('\\', Path.DirectorySeparatorChar));

			if (!File.Exists(hostExecutablePath))
			{
				throw new FileNotFoundException($"The selected executable does not exist: {hostExecutablePath}", hostExecutablePath);
			}
		}

		string? decodedCustomPowerShellCode = DecodeCustomPowerShellCodeFromStorage(definition.CustomPowerShellCode);

		if (definition.RunCustomPowerShellOnStartup && string.IsNullOrWhiteSpace(decodedCustomPowerShellCode))
		{
			throw new InvalidOperationException("The saved sandbox has custom PowerShell startup enabled, but no PowerShell code is configured.");
		}
	}

	private string CreateSandboxConfigurationFile(WindowsSandboxSavedDefinition definition)
	{
		ValidateDefinition(definition);
		XDocument sandboxConfiguration = BuildSandboxConfigurationDocument(definition);
		string sandboxConfigurationPath = GetSandboxConfigurationPath(definition.Name);
		sandboxConfiguration.Save(sandboxConfigurationPath);

		Logger.Write($"Windows Sandbox configuration generated at {sandboxConfigurationPath}");
		return sandboxConfigurationPath;
	}

	private XDocument BuildSandboxConfigurationDocument(WindowsSandboxSavedDefinition definition)
	{
		XElement configurationElement = new("Configuration",
			new XElement("Networking", definition.DisableNetworking ? "disable" : "enable"),
			new XElement("MemoryInMB", Convert.ToInt32(Math.Round(definition.MemoryInMb, MidpointRounding.AwayFromZero))),
			new XElement("vGPU", definition.EnableVGpu ? "enable" : "disable"),
			new XElement("AudioInput", definition.EnableAudioInput ? "enable" : "disable"),
			new XElement("VideoInput", definition.EnableVideoInput ? "enable" : "disable"),
			new XElement("PrinterRedirection", definition.EnablePrinterRedirection ? "enable" : "disable"),
			new XElement("ClipboardRedirection", definition.EnableClipboardRedirection ? "enable" : "disable"),
			new XElement("ProtectedClient", definition.EnableProtectedClient ? "enable" : "disable"));

		if (!string.IsNullOrWhiteSpace(definition.ProgramFolderPath) &&
			!string.IsNullOrWhiteSpace(definition.ProgramExecutableRelativePath))
		{
			string sandboxMappedProgramRoot = GetSandboxMappedProgramRoot(definition.ProgramFolderPath);
			configurationElement.Add(
				new XElement("MappedFolders",
					new XElement("MappedFolder",
						new XElement("HostFolder", definition.ProgramFolderPath),
						new XElement("SandboxFolder", sandboxMappedProgramRoot),
						new XElement("ReadOnly", definition.IsProgramFolderReadOnly ? "true" : "false"))));
		}

		string? logonCommand = BuildLogonCommand(definition);
		if (!string.IsNullOrWhiteSpace(logonCommand))
		{
			configurationElement.Add(
				new XElement("LogonCommand",
					new XElement("Command", logonCommand)));
		}

		return new XDocument(configurationElement);
	}

	private string? BuildLogonCommand(WindowsSandboxSavedDefinition definition)
	{
		List<string> startupCommands = [];

		if (!string.IsNullOrWhiteSpace(definition.TimeZoneId))
		{
			startupCommands.Add($"Set-TimeZone -Id {ToPowerShellLiteral(definition.TimeZoneId)}");
		}

		string? mappedProgramLaunchCommand = null;

		if (!string.IsNullOrWhiteSpace(definition.ProgramFolderPath) &&
			!string.IsNullOrWhiteSpace(definition.ProgramExecutableRelativePath))
		{
			string sandboxMappedProgramRoot = GetSandboxMappedProgramRoot(definition.ProgramFolderPath);
			string sandboxExecutablePath = CombineWindowsPath(
				sandboxMappedProgramRoot,
				NormalizeWindowsPath(definition.ProgramExecutableRelativePath));

			string shortcutFileName = Path.GetFileNameWithoutExtension(sandboxExecutablePath) + ".lnk";
			string sandboxWorkingDirectory = GetWindowsDirectoryName(sandboxExecutablePath);

			startupCommands.Add("$DesktopPath = [Environment]::GetFolderPath('Desktop')");
			startupCommands.Add("$WshShell = New-Object -ComObject WScript.Shell");
			startupCommands.Add($"$Shortcut = $WshShell.CreateShortcut((Join-Path $DesktopPath {ToPowerShellLiteral(shortcutFileName)}))");
			startupCommands.Add($"$Shortcut.TargetPath = {ToPowerShellLiteral(sandboxExecutablePath)}");
			startupCommands.Add($"$Shortcut.WorkingDirectory = {ToPowerShellLiteral(sandboxWorkingDirectory)}");
			startupCommands.Add($"$Shortcut.IconLocation = {ToPowerShellLiteral(sandboxExecutablePath)}");
			startupCommands.Add("$Shortcut.Save()");

			if (definition.RunMappedProgramOnStartup)
			{
				mappedProgramLaunchCommand = $"Start-Process -FilePath {ToPowerShellLiteral(sandboxExecutablePath)} -WorkingDirectory {ToPowerShellLiteral(sandboxWorkingDirectory)}";
			}
		}

		string? customPowerShellCode = DecodeCustomPowerShellCodeFromStorage(definition.CustomPowerShellCode);

		if (definition.RunCustomPowerShellOnStartup &&
			!string.IsNullOrWhiteSpace(customPowerShellCode) &&
			definition.CustomPowerShellLaunchTiming == WindowsSandboxCustomPowerShellLaunchTiming.BeforeMappedProgramLaunch)
		{
			// The custom script is appended as-is because the final startup script is encoded for PowerShell.
			startupCommands.Add(customPowerShellCode);
		}

		if (!string.IsNullOrWhiteSpace(mappedProgramLaunchCommand))
		{
			startupCommands.Add(mappedProgramLaunchCommand);
		}

		if (definition.RunCustomPowerShellOnStartup &&
			!string.IsNullOrWhiteSpace(customPowerShellCode) &&
			definition.CustomPowerShellLaunchTiming == WindowsSandboxCustomPowerShellLaunchTiming.AfterMappedProgramLaunch)
		{
			// When no mapped program is launched, this still runs during sandbox startup after the built-in setup commands.
			startupCommands.Add(customPowerShellCode);
		}

		if (startupCommands.Count == 0)
		{
			return null;
		}

		StringBuilder startupScriptBuilder = new();
		_ = startupScriptBuilder.AppendLine("$ErrorActionPreference = 'Stop'");

		foreach (string startupCommand in CollectionsMarshal.AsSpan(startupCommands))
		{
			_ = startupScriptBuilder.AppendLine(startupCommand);
		}

		byte[] encodedScriptBytes = Encoding.Unicode.GetBytes(startupScriptBuilder.ToString());
		string encodedScript = Convert.ToBase64String(encodedScriptBytes);

		return $"powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encodedScript}";
	}

	private void OpenPathInExplorer(string? sandboxConfigurationPath)
	{
		ProcessStartInfo processStartInfo = new()
		{
			FileName = "explorer.exe",
			Arguments = !string.IsNullOrWhiteSpace(sandboxConfigurationPath) && File.Exists(sandboxConfigurationPath)
				? $"/select,\"{sandboxConfigurationPath}\""
				: $"\"{SandboxConfigurationDirectory}\"",
			UseShellExecute = true
		};

		using Process? process = Process.Start(processStartInfo) ?? throw new InvalidOperationException("The sandbox file location could not be opened.");
	}

	private static void LaunchSandbox(string sandboxConfigurationPath)
	{
		ProcessStartInfo processStartInfo = new()
		{
			FileName = sandboxConfigurationPath,
			UseShellExecute = true
		};

		using Process? process = Process.Start(processStartInfo) ?? throw new InvalidOperationException("Windows Sandbox could not be started from the generated configuration file.");
	}

	private static string? EncodeCustomPowerShellCodeForStorage(string? customPowerShellCode)
	{
		if (string.IsNullOrWhiteSpace(customPowerShellCode))
		{
			return null;
		}

		byte[] customPowerShellCodeBytes = Utf8WithoutBom.GetBytes(customPowerShellCode);
		return Convert.ToBase64String(customPowerShellCodeBytes);
	}

	internal static string? DecodeCustomPowerShellCodeFromStorage(string? storedCustomPowerShellCode)
	{
		if (string.IsNullOrWhiteSpace(storedCustomPowerShellCode))
		{
			return null;
		}

		try
		{
			byte[] customPowerShellCodeBytes = Convert.FromBase64String(storedCustomPowerShellCode);
			return Utf8WithoutBom.GetString(customPowerShellCodeBytes);
		}
		catch (FormatException ex)
		{
			Logger.Write($"Saved custom PowerShell code could not be decoded from Base64: {ex}");
			return null;
		}
	}

	private static string ToPowerShellLiteral(string value) => $"'{value.Replace("'", "''", StringComparison.Ordinal)}'";

	private static string NormalizeWindowsPath(string path) =>
		path.Replace(Path.DirectorySeparatorChar, '\\').Replace(Path.AltDirectorySeparatorChar, '\\');

	private static string CombineWindowsPath(string rootPath, string relativePath) =>
		$"{rootPath.TrimEnd('\\')}\\{relativePath.TrimStart('\\')}";

	private static string GetSandboxMappedProgramRoot(string selectedProgramFolderPath) =>
		CombineWindowsPath(@"C:\", GetWindowsFolderName(selectedProgramFolderPath));

	private static string GetWindowsFolderName(string path)
	{
		string trimmedPath = Path.TrimEndingDirectorySeparator(path);
		string folderName = Path.GetFileName(trimmedPath);
		if (!string.IsNullOrWhiteSpace(folderName))
		{
			return folderName;
		}

		string? rootPath = Path.GetPathRoot(trimmedPath);
		if (!string.IsNullOrWhiteSpace(rootPath))
		{
			string rootFolderName = rootPath.TrimEnd('\\').Replace(":", string.Empty, StringComparison.Ordinal);
			if (!string.IsNullOrWhiteSpace(rootFolderName))
			{
				return rootFolderName;
			}
		}

		throw new InvalidOperationException($"A sandbox folder name could not be derived from the selected path: {path}");
	}

	private static string GetWindowsDirectoryName(string path)
	{
		int lastSeparatorIndex = path.LastIndexOf('\\');
		return lastSeparatorIndex > 0 ? path[..lastSeparatorIndex] : @"C:\";
	}

	private static string GetValidatedSandboxName(string? sandboxName)
	{
		string normalizedName = sandboxName?.Trim() ?? string.Empty;
		if (string.IsNullOrWhiteSpace(normalizedName))
		{
			throw new InvalidOperationException("Enter a sandbox name before creating or launching it.");
		}

		if (string.IsNullOrWhiteSpace(GetSafeFileName(normalizedName)))
		{
			throw new InvalidOperationException("The sandbox name must contain at least one valid file-name character.");
		}

		return normalizedName;
	}

	private static string GetSafeFileName(string sandboxName)
	{
		StringBuilder fileNameBuilder = new(sandboxName.Length);
		HashSet<char> invalidCharacters = [.. Atlas.InvalidFileNameChars.Value];

		foreach (char character in sandboxName.Trim())
		{
			_ = fileNameBuilder.Append(invalidCharacters.Contains(character) ? '_' : character);
		}

		return fileNameBuilder.ToString().Trim().Trim('.');
	}
}

internal sealed class WindowsSandboxTimeZoneOption(string regionName, string offsetLabel, string? timeZoneId)
{
	internal string RegionName => regionName;
	internal string OffsetLabel => offsetLabel;
	internal string? TimeZoneId => timeZoneId;
	internal int OffsetMinutes => GetOffsetMinutes(offsetLabel);

	private static int GetOffsetMinutes(string offsetLabel)
	{
		if (!offsetLabel.StartsWith("UTC", StringComparison.Ordinal))
		{
			return int.MinValue;
		}

		string offsetValue = offsetLabel["UTC".Length..];
		int sign = offsetValue[0] == '-' ? -1 : 1;
		TimeSpan offset = TimeSpan.ParseExact(offsetValue[1..], @"hh\:mm", CultureInfo.InvariantCulture);
		return sign * (int)offset.TotalMinutes;
	}
}

internal sealed class WindowsSandboxProgramOption(string displayName, string relativePath)
{
	internal string DisplayName => displayName;
	internal string RelativePath => relativePath;
}

internal sealed class WindowsSandboxCustomPowerShellTimingOption(string displayName, WindowsSandboxCustomPowerShellLaunchTiming launchTiming)
{
	internal string DisplayName => displayName;
	internal WindowsSandboxCustomPowerShellLaunchTiming LaunchTiming => launchTiming;
}

internal enum WindowsSandboxCustomPowerShellLaunchTiming
{
	BeforeMappedProgramLaunch,
	AfterMappedProgramLaunch
}

internal sealed class WindowsSandboxSavedDefinition
{
	public string Name { get; set; } = string.Empty;
	public string? TimeZoneId { get; set; }
	public double MemoryInMb { get; set; } = 4000D;
	public bool DisableNetworking { get; set; }
	public bool EnableVGpu { get; set; }
	public bool EnableClipboardRedirection { get; set; }
	public bool EnableAudioInput { get; set; }
	public bool EnableVideoInput { get; set; }
	public bool EnablePrinterRedirection { get; set; }
	public bool EnableProtectedClient { get; set; } = true;
	public string? ProgramFolderPath { get; set; }
	public string? ProgramExecutableRelativePath { get; set; }
	public bool IsProgramFolderReadOnly { get; set; } = true;
	public bool RunMappedProgramOnStartup { get; set; }
	public bool RunCustomPowerShellOnStartup { get; set; }
	public string? CustomPowerShellCode { get; set; }
	public WindowsSandboxCustomPowerShellLaunchTiming CustomPowerShellLaunchTiming { get; set; }
	public DateTimeOffset SavedAtUtc { get; set; }

	[JsonIgnore]
	internal string TimeZoneDisplayText => SandboxMakerVM.GetTimeZoneDisplayLabel(TimeZoneId);

	[JsonIgnore]
	internal string ProgramDisplayText
	{
		get
		{
			if (string.IsNullOrWhiteSpace(ProgramExecutableRelativePath))
			{
				return "Not configured";
			}

			string programDisplayText = ProgramExecutableRelativePath;
			return RunMappedProgramOnStartup
				? $"{programDisplayText} (runs on startup)"
				: programDisplayText;
		}
	}

	[JsonIgnore]
	internal string CustomPowerShellDisplayText
	{
		get
		{
			string? decodedCustomPowerShellCode = SandboxMakerVM.DecodeCustomPowerShellCodeFromStorage(CustomPowerShellCode);

			if (!RunCustomPowerShellOnStartup || string.IsNullOrWhiteSpace(decodedCustomPowerShellCode))
			{
				return "Not configured";
			}

			return SandboxMakerVM.GetCustomPowerShellLaunchTimingDisplayLabel(CustomPowerShellLaunchTiming);
		}
	}

	[JsonIgnore]
	internal string MemoryDisplayText => MemoryInMb >= 1024D && Math.Abs(MemoryInMb % 1024D) < 0.01D
		? (MemoryInMb / 1024D).ToString("0.#", CultureInfo.CurrentCulture) + " GB"
		: MemoryInMb.ToString("0", CultureInfo.CurrentCulture) + " MB";

	[JsonIgnore]
	internal string SavedAtDisplayText => SavedAtUtc == default ? "Not saved yet" : SavedAtUtc.ToLocalTime().ToString("g", CultureInfo.CurrentCulture);
}

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(WindowsSandboxCustomPowerShellLaunchTiming))]
[JsonSerializable(typeof(WindowsSandboxSavedDefinition))]
[JsonSerializable(typeof(List<WindowsSandboxSavedDefinition>))]
internal sealed partial class SandboxMakerDefinitionsJsonContext : JsonSerializerContext
{
}
