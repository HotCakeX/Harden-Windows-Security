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
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using CommonCore.GroupPolicy;
using CommonCore.Interop;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Win32;
using WinRT;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class TweaksVM : ViewModelBase
{
	#region Page Sections

	// The SelectorBar chooses which section of the page is shown.
	internal Microsoft.UI.Xaml.Visibility CleanupSectionVisibility { get; set => SP(ref field, value); } = Microsoft.UI.Xaml.Visibility.Visible;

	internal Microsoft.UI.Xaml.Visibility DiagnosticsSectionVisibility { get; set => SP(ref field, value); } = Microsoft.UI.Xaml.Visibility.Collapsed;

	internal async void SectionSelectorBar_SelectionChanged(SelectorBar sender, SelectorBarSelectionChangedEventArgs args)
	{
		int selectedIndex = sender.SelectedItem is null ? 0 : sender.Items.IndexOf(sender.SelectedItem);
		CleanupSectionVisibility = selectedIndex == 0 ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;
		DiagnosticsSectionVisibility = selectedIndex == 1 ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;

		// Keep the toggle statuses up to date whenever user switched to this tab
		if (selectedIndex == 1)
		{
			DiskHealthModelUpdatesIsOn = IsDiskHealthModelUpdatesEnabled();
			await RefreshWindowsReConfiguration();
		}
	}

	#endregion

	#region Cleanup

	#region NuGet Cleaner

	internal readonly InfoBarSettings NuGetCleanerInfoBar = new();
	internal bool NuGetCleanerIsEnabled { get; set => SP(ref field, value); } = true;
	internal bool NuGetCleanerCanRemove { get; set => SP(ref field, value); }
	internal bool NuGetCleanerReviewExpanded { get; set => SP(ref field, value); }
	internal string? NuGetCleanerResults { get; set => SP(ref field, value); }
	private readonly List<string> NuGetCleanerDirectoriesToDelete = [];

	internal async void CheckNuGetCleaner_Click()
	{
		try
		{
			NuGetCleanerIsEnabled = false;
			NuGetCleanerCanRemove = false;
			NuGetCleanerInfoBar.IsClosable = false;
			NuGetCleanerInfoBar.WriteInfo("Checking the NuGet package cache...");
			NuGetCleanerCheckResult result = await Task.Run(CheckNuGetCleaner);
			NuGetCleanerDirectoriesToDelete.Clear();
			NuGetCleanerDirectoriesToDelete.AddRange(result.Paths);
			// Put each path on a new line to be displayed on the UI TextBox
			NuGetCleanerResults = string.Join(Environment.NewLine, result.Paths);
			NuGetCleanerCanRemove = result.Paths.Count > 0;
			if (NuGetCleanerCanRemove)
			{
				NuGetCleanerInfoBar.WriteSuccess($"Found {result.Paths.Count} older version folder(s), totaling {result.TotalSizeInMB:N2} MB.");
			}
			else
			{
				NuGetCleanerInfoBar.WriteInfo("Nothing to clean up. Every package already has a single version.");
			}
		}
		catch (Exception ex)
		{
			NuGetCleanerDirectoriesToDelete.Clear();
			NuGetCleanerCanRemove = false;
			NuGetCleanerResults = null;
			NuGetCleanerInfoBar.WriteError(ex);
		}
		finally
		{
			NuGetCleanerIsEnabled = true;
			NuGetCleanerInfoBar.IsClosable = true;
		}
	}

	internal async void RemoveNuGetCleaner_Click()
	{
		if (NuGetCleanerDirectoriesToDelete.Count == 0)
		{
			NuGetCleanerCanRemove = false;
			NuGetCleanerInfoBar.WriteWarning("There is no NuGet package data to remove.");
			return;
		}
		try
		{
			NuGetCleanerIsEnabled = false;
			NuGetCleanerCanRemove = false;
			NuGetCleanerInfoBar.IsClosable = false;
			List<string> paths = new(NuGetCleanerDirectoriesToDelete);
			NuGetCleanerDeleteResult result = await Task.Run(() => DeleteNuGetCleanerDirectories(paths));
			NuGetCleanerDirectoriesToDelete.Clear();
			NuGetCleanerDirectoriesToDelete.AddRange(result.FailedPaths);
			NuGetCleanerCanRemove = result.FailedPaths.Count > 0;
			// Put each path on a new line to be displayed on the UI TextBox
			NuGetCleanerResults = string.Join(Environment.NewLine, result.FailedPaths);
			if (result.FailedPaths.Count == 0)
			{
				NuGetCleanerReviewExpanded = false;
				NuGetCleanerInfoBar.WriteSuccess($"Done. Deleted {result.DeletedCount} of {paths.Count} older version folder(s).");
			}
			else
			{
				NuGetCleanerInfoBar.WriteWarning($"Deleted {result.DeletedCount} of {paths.Count} older version folder(s). Review the remaining paths.");
			}
		}
		catch (Exception ex)
		{
			NuGetCleanerInfoBar.WriteError(ex);
		}
		finally
		{
			NuGetCleanerIsEnabled = true;
			NuGetCleanerInfoBar.IsClosable = true;
		}
	}

	private static NuGetCleanerCheckResult CheckNuGetCleaner()
	{
		string? configuredPackagesRoot = Environment.GetEnvironmentVariable("NUGET_PACKAGES");
		string packagesRoot = !string.IsNullOrWhiteSpace(configuredPackagesRoot) ? configuredPackagesRoot : Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".nuget", "packages");
		if (!Directory.Exists(packagesRoot))
		{
			return new([], 0);
		}
		List<string> toDelete = [];
		foreach (string packageDir in Directory.EnumerateDirectories(packagesRoot))
		{
			string[] versionDirs = Directory.GetDirectories(packageDir);
			List<KeyValuePair<string, NuGetVersion>> parsed = new(versionDirs.Length);
			foreach (string versionDir in versionDirs)
			{
				// Only consider subfolders whose name is a valid version.
				if (NuGetVersion.TryParse(Path.GetFileName(versionDir), out NuGetVersion? version))
				{
					parsed.Add(new(versionDir, version));
				}
			}
			// Nothing to trim when a package has zero or one recognizable version.
			if (parsed.Count <= 1)
			{
				continue;
			}
			// Ascending order, so the highest version ends up last and is kept.
			parsed.Sort(static (a, b) => a.Value.CompareTo(b.Value));
			for (int i = 0; i < parsed.Count - 1; i++)
			{
				toDelete.Add(parsed[i].Key);
			}
		}
		if (toDelete.Count == 0)
		{
			return new(toDelete, 0);
		}
		long totalBytes = 0;
		foreach (string path in toDelete)
		{
			foreach (string filePath in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
			{
				totalBytes += new FileInfo(filePath).Length;
			}
		}
		return new(toDelete, totalBytes / (1024d * 1024d));
	}

	private static NuGetCleanerDeleteResult DeleteNuGetCleanerDirectories(List<string> paths)
	{
		int deleted = 0;
		List<string> failedPaths = [];
		foreach (string path in paths)
		{
			try
			{
				Directory.Delete(path, true);
				deleted++;
			}
			catch
			{
				failedPaths.Add(path);
			}
		}
		return new(deleted, failedPaths);
	}

	private sealed record NuGetCleanerCheckResult(List<string> Paths, double TotalSizeInMB);

	private sealed record NuGetCleanerDeleteResult(int DeletedCount, List<string> FailedPaths);

	// Minimal SemVer 2.0.0 style version parser and comparer. Prerelease identifiers are compared
	// case-insensitively to match NuGet folder naming, which deviates from the case-sensitive
	// ordering that the specification itself mandates.
	private sealed class NuGetVersion : IComparable<NuGetVersion>
	{
		private readonly int[] _release;
		private readonly string[] _prerelease;

		private NuGetVersion(int[] release, string[] prerelease)
		{
			_release = release;
			_prerelease = prerelease;
		}

		internal static bool TryParse(string text, [NotNullWhen(true)] out NuGetVersion? version)
		{
			version = null;
			if (string.IsNullOrWhiteSpace(text))
			{
				return false;
			}

			// Build metadata (everything after '+') is ignored for precedence.
			int plusIndex = text.IndexOf('+');
			if (plusIndex >= 0)
			{
				text = text[..plusIndex];
			}

			// Split the release part from the optional prerelease part.
			string releasePart;
			string[] prerelease;
			int dashIndex = text.IndexOf('-');
			if (dashIndex >= 0)
			{
				releasePart = text[..dashIndex];
				string prereleasePart = text[(dashIndex + 1)..];
				if (prereleasePart.Length == 0)
				{
					return false;
				}
				prerelease = prereleasePart.Split('.');
			}
			else
			{
				releasePart = text;
				prerelease = [];
			}
			string[] releaseTokens = releasePart.Split('.');
			int[] release = new int[releaseTokens.Length];
			for (int i = 0; i < releaseTokens.Length; i++)
			{
				if (!int.TryParse(releaseTokens[i], NumberStyles.None, CultureInfo.InvariantCulture, out int value))
				{
					return false;
				}
				release[i] = value;
			}
			version = new(release, prerelease);
			return true;
		}

		public int CompareTo(NuGetVersion? other)
		{
			if (other is null)
			{
				return 1;
			}

			// Compare the numeric release components (missing trailing parts count as 0).
			int releaseLength = Math.Max(_release.Length, other._release.Length);
			for (int i = 0; i < releaseLength; i++)
			{
				int left = i < _release.Length ? _release[i] : 0;
				int right = i < other._release.Length ? other._release[i] : 0;
				if (left != right)
				{
					return left < right ? -1 : 1;
				}
			}

			// A release version always outranks a prerelease of the same release.
			bool leftPre = _prerelease.Length > 0;
			bool rightPre = other._prerelease.Length > 0;

			if (leftPre && !rightPre)
			{
				return -1;
			}
			if (!leftPre && rightPre)
			{
				return 1;
			}
			if (!leftPre && !rightPre)
			{
				return 0;
			}

			// Both are prereleases, compare their dot separated identifiers in order.
			int preLength = Math.Max(_prerelease.Length, other._prerelease.Length);
			for (int i = 0; i < preLength; i++)
			{
				// A larger set of prerelease identifiers has the higher precedence
				// when all preceding identifiers are equal.
				if (i >= _prerelease.Length)
				{
					return -1;
				}
				if (i >= other._prerelease.Length)
				{
					return 1;
				}
				string leftId = _prerelease[i];
				string rightId = other._prerelease[i];
				bool leftNumeric = int.TryParse(leftId, NumberStyles.None, CultureInfo.InvariantCulture, out int leftNum);
				bool rightNumeric = int.TryParse(rightId, NumberStyles.None, CultureInfo.InvariantCulture, out int rightNum);
				if (leftNumeric && rightNumeric)
				{
					if (leftNum != rightNum)
					{
						return leftNum < rightNum ? -1 : 1;
					}
				}
				else if (leftNumeric)
				{
					// Numeric identifiers have lower precedence than alphanumeric ones.
					return -1;
				}
				else if (rightNumeric)
				{
					return 1;
				}
				else
				{
					int comparison = string.Compare(leftId, rightId, StringComparison.OrdinalIgnoreCase);
					if (comparison != 0)
					{
						return comparison < 0 ? -1 : 1;
					}
				}
			}
			return 0;
		}
	}

	#endregion

	#region PowerShell History Cleaner

	internal readonly InfoBarSettings PowerShellHistoryInfoBar = new();
	internal bool PowerShellHistoryIsEnabled { get; set => SP(ref field, value); } = true;
	internal bool PowerShellHistoryCanRemove { get; set => SP(ref field, value); }
	internal bool PowerShellHistoryReviewExpanded { get; set => SP(ref field, value); }
	internal string? PowerShellHistoryResults { get; set => SP(ref field, value); }
	private readonly List<string> PowerShellHistoryFilesToClear = [];
	private static readonly string[] PowerShellHistoryFilePaths =
	[
		Path.Join(UserProfile, "AppData", "Roaming", "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"),
		Path.Join(UserProfile, "AppData", "Roaming", "Microsoft", "Windows", "PowerShell", "PSReadLine", "Visual Studio Code Host_history.txt")
	];

	internal async void CheckPowerShellHistory_Click()
	{
		try
		{
			PowerShellHistoryIsEnabled = false;
			PowerShellHistoryCanRemove = false;
			PowerShellHistoryInfoBar.IsClosable = false;
			(List<string> FilesToClear, int TotalLineCount, string Contents) = await Task.Run(CheckPowerShellHistory);
			PowerShellHistoryFilesToClear.Clear();
			PowerShellHistoryFilesToClear.AddRange(FilesToClear);
			PowerShellHistoryResults = Contents;
			PowerShellHistoryCanRemove = FilesToClear.Count > 0;
			if (PowerShellHistoryCanRemove)
			{
				PowerShellHistoryInfoBar.WriteSuccess($"Found {TotalLineCount} command-history line(s) across {FilesToClear.Count} non-empty file(s).");
			}
			else
			{
				PowerShellHistoryInfoBar.WriteInfo("No PowerShell command history was found to clear.");
			}
		}
		catch (Exception ex)
		{
			PowerShellHistoryFilesToClear.Clear();
			PowerShellHistoryCanRemove = false;
			PowerShellHistoryResults = null;
			PowerShellHistoryInfoBar.WriteError(ex);
		}
		finally
		{
			PowerShellHistoryIsEnabled = true;
			PowerShellHistoryInfoBar.IsClosable = true;
		}
	}

	internal async void RemovePowerShellHistory_Click()
	{
		if (PowerShellHistoryFilesToClear.Count == 0)
		{
			PowerShellHistoryCanRemove = false;
			PowerShellHistoryInfoBar.WriteWarning("There is no PowerShell history data to clear.");
			return;
		}
		try
		{
			PowerShellHistoryIsEnabled = false;
			PowerShellHistoryCanRemove = false;
			PowerShellHistoryInfoBar.IsClosable = false;
			List<string> files = new(PowerShellHistoryFilesToClear);
			(int ClearedCount, List<string> FailedPaths) = await Task.Run(() => ClearPowerShellHistory(files));
			PowerShellHistoryFilesToClear.Clear();
			PowerShellHistoryFilesToClear.AddRange(FailedPaths);
			PowerShellHistoryCanRemove = FailedPaths.Count > 0;
			PowerShellHistoryResults = FailedPaths.Count > 0 ? string.Join(Environment.NewLine, FailedPaths) : null;
			if (FailedPaths.Count == 0)
			{
				PowerShellHistoryReviewExpanded = false;
				PowerShellHistoryInfoBar.WriteSuccess($"Cleared {ClearedCount} PowerShell history file(s).");
			}
			else
			{
				PowerShellHistoryInfoBar.WriteWarning($"Cleared {ClearedCount} of {files.Count} PowerShell history file(s). The remaining files could not be cleared and are listed below.");
			}
		}
		catch (Exception ex)
		{
			PowerShellHistoryInfoBar.WriteError(ex);
		}
		finally
		{
			PowerShellHistoryIsEnabled = true;
			PowerShellHistoryInfoBar.IsClosable = true;
		}
	}

	private static (List<string> FilesToClear, int TotalLineCount, string Contents) CheckPowerShellHistory()
	{
		List<string> filesToClear = new(PowerShellHistoryFilePaths.Length);
		List<string> historyContents = new(PowerShellHistoryFilePaths.Length);
		int totalLineCount = 0;
		foreach (string path in PowerShellHistoryFilePaths)
		{
			if (!File.Exists(path))
			{
				continue;
			}
			string content = File.ReadAllText(path);
			if (content.Length == 0)
			{
				continue;
			}
			filesToClear.Add(path);
			historyContents.Add(content);
			totalLineCount += CountLines(content);
		}
		return (filesToClear, totalLineCount, string.Join(Environment.NewLine + Environment.NewLine, historyContents));
	}

	private static (int ClearedCount, List<string> FailedPaths) ClearPowerShellHistory(List<string> files)
	{
		int cleared = 0;
		List<string> failedPaths = [];
		foreach (string path in files)
		{
			// Do not recreate a history file that no longer exists. Its history is already gone,
			// so it is skipped instead of being reported as a failure that can never succeed.
			if (!File.Exists(path))
			{
				continue;
			}
			try
			{
				File.WriteAllText(path, string.Empty);
				cleared++;
			}
			catch
			{
				// PSReadLine keeps the history file open, so a single locked file must not
				// abort the whole operation and discard the work already completed.
				failedPaths.Add(path);
			}
		}
		return (cleared, failedPaths);
	}

	private static int CountLines(string content)
	{
		if (content.Length == 0)
		{
			return 0;
		}
		int count = 1;
		foreach (char character in content)
		{
			if (character == '\n')
			{
				count++;
			}
		}
		return content[^1] == '\n' ? count - 1 : count;
	}

	#endregion

	#region Run History Cleaner

	internal readonly InfoBarSettings RunHistoryInfoBar = new();
	internal bool RunHistoryIsEnabled { get; set => SP(ref field, value); } = true;
	internal bool RunHistoryCanRemove { get; set => SP(ref field, value); }
	internal bool RunHistoryReviewExpanded { get; set => SP(ref field, value); }
	internal string? RunHistoryResults { get; set => SP(ref field, value); }
	private const string RunHistoryRegistryPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU";
	private readonly List<RegistryHistoryEntry> RunHistoryEntriesToDelete = [];

	internal async void CheckRunHistory_Click()
	{
		try
		{
			RunHistoryIsEnabled = false;
			RunHistoryCanRemove = false;
			RunHistoryInfoBar.IsClosable = false;
			List<RegistryHistoryEntry> entries = await Task.Run(CheckRunHistory);
			RunHistoryEntriesToDelete.Clear();
			RunHistoryEntriesToDelete.AddRange(entries);
			RunHistoryResults = string.Join(Environment.NewLine, entries.Select(static entry => entry.DisplayText));
			RunHistoryCanRemove = entries.Count > 0;
			if (RunHistoryCanRemove)
			{
				RunHistoryInfoBar.WriteSuccess($"Found {entries.Count} Run history entry(s).");
			}
			else
			{
				RunHistoryInfoBar.WriteInfo("No Run history was found to clear.");
			}
		}
		catch (Exception ex)
		{
			RunHistoryEntriesToDelete.Clear();
			RunHistoryCanRemove = false;
			RunHistoryResults = null;
			RunHistoryInfoBar.WriteError(ex);
		}
		finally
		{
			RunHistoryIsEnabled = true;
			RunHistoryInfoBar.IsClosable = true;
		}
	}

	internal async void RemoveRunHistory_Click()
	{
		if (RunHistoryEntriesToDelete.Count == 0)
		{
			RunHistoryCanRemove = false;
			RunHistoryInfoBar.WriteWarning("There is no Run history to clear.");
			return;
		}
		try
		{
			RunHistoryIsEnabled = false;
			RunHistoryCanRemove = false;
			RunHistoryInfoBar.IsClosable = false;
			List<RegistryHistoryEntry> entries = new(RunHistoryEntriesToDelete);
			(int DeletedCount, List<string> FailedKeyPaths) = await Task.Run(() => DeleteRegistryHistoryValues(entries));
			RunHistoryEntriesToDelete.Clear();
			RunHistoryResults = null;
			if (FailedKeyPaths.Count == 0)
			{
				RunHistoryReviewExpanded = false;
				RunHistoryInfoBar.WriteSuccess($"Cleared {DeletedCount} Run history entry(s).");
			}
			else
			{
				RunHistoryInfoBar.WriteWarning($"Cleared {DeletedCount} Run history entry(s), but the operation could not be completed.");
			}
		}
		catch (Exception ex)
		{
			RunHistoryInfoBar.WriteError(ex);
		}
		finally
		{
			RunHistoryIsEnabled = true;
			RunHistoryInfoBar.IsClosable = true;
		}
	}

	// The display text strips the trailing \1 execution marker, so it is kept alongside the value
	// name rather than being recomputed at deletion time.
	private static List<RegistryHistoryEntry> CheckRunHistory()
	{
		using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RunHistoryRegistryPath, writable: false);
		if (key is null)
		{
			return [];
		}
		string[] valueNames = key.GetValueNames();
		List<RegistryHistoryEntry> entries = new(valueNames.Length);
		foreach (string valueName in valueNames)
		{
			if (string.IsNullOrEmpty(valueName) || string.Equals(valueName, "MRUList", StringComparison.OrdinalIgnoreCase))
			{
				continue;
			}
			if (key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string entry && !string.IsNullOrEmpty(entry))
			{
				entries.Add(new(RunHistoryRegistryPath, valueName, entry.EndsWith(@"\1", StringComparison.OrdinalIgnoreCase) ? entry[..^2] : entry));
			}
		}
		return entries;
	}

	#endregion

	#region File Explorer Typed Path History

	// Reviews and deletes only the string values stored under the current user TypedPaths key.
	// Registry value names are retained internally so Clear targets exactly what Check displayed.

	internal readonly InfoBarSettings TypedPathHistoryInfoBar = new();
	internal bool TypedPathHistoryIsEnabled { get; set => SP(ref field, value); } = true;
	internal bool TypedPathHistoryCanRemove { get; set => SP(ref field, value); }
	internal bool TypedPathHistoryReviewExpanded { get; set => SP(ref field, value); }
	internal string? TypedPathHistoryResults { get; set => SP(ref field, value); }
	private const string TypedPathHistoryRegistryPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths";
	private readonly List<RegistryHistoryEntry> TypedPathHistoryEntriesToDelete = [];

	internal async void CheckTypedPathHistory_Click()
	{
		try
		{
			TypedPathHistoryIsEnabled = false;
			TypedPathHistoryCanRemove = false;
			TypedPathHistoryInfoBar.IsClosable = false;
			List<RegistryHistoryEntry> entries = await Task.Run(CheckTypedPathHistory);
			TypedPathHistoryEntriesToDelete.Clear();
			TypedPathHistoryEntriesToDelete.AddRange(entries);
			TypedPathHistoryResults = string.Join(Environment.NewLine, entries.Select(static entry => entry.DisplayText));
			TypedPathHistoryCanRemove = entries.Count > 0;
			if (TypedPathHistoryCanRemove)
			{
				TypedPathHistoryInfoBar.WriteSuccess($"Found {entries.Count} File Explorer typed-path history entry(s).");
			}
			else
			{
				TypedPathHistoryInfoBar.WriteInfo("No File Explorer typed-path history was found to clear.");
			}
		}
		catch (Exception ex)
		{
			TypedPathHistoryEntriesToDelete.Clear();
			TypedPathHistoryCanRemove = false;
			TypedPathHistoryResults = null;
			TypedPathHistoryInfoBar.WriteError(ex);
		}
		finally
		{
			TypedPathHistoryIsEnabled = true;
			TypedPathHistoryInfoBar.IsClosable = true;
		}
	}

	internal async void RemoveTypedPathHistory_Click()
	{
		if (TypedPathHistoryEntriesToDelete.Count == 0)
		{
			TypedPathHistoryCanRemove = false;
			TypedPathHistoryInfoBar.WriteWarning("There is no typed-path history to clear.");
			return;
		}
		try
		{
			TypedPathHistoryIsEnabled = false;
			TypedPathHistoryCanRemove = false;
			TypedPathHistoryInfoBar.IsClosable = false;
			List<RegistryHistoryEntry> entries = new(TypedPathHistoryEntriesToDelete);
			(int DeletedCount, List<string> FailedKeyPaths) = await Task.Run(() => DeleteRegistryHistoryValues(entries));
			TypedPathHistoryEntriesToDelete.Clear();
			TypedPathHistoryResults = null;
			if (FailedKeyPaths.Count == 0)
			{
				TypedPathHistoryReviewExpanded = false;
				TypedPathHistoryInfoBar.WriteSuccess($"Cleared {DeletedCount} File Explorer typed-path history entry(s).");
			}
			else
			{
				TypedPathHistoryInfoBar.WriteWarning($"Cleared {DeletedCount} File Explorer typed-path history entry(s), but the operation could not be completed.");
			}
		}
		catch (Exception ex)
		{
			TypedPathHistoryInfoBar.WriteError(ex);
		}
		finally
		{
			TypedPathHistoryIsEnabled = true;
			TypedPathHistoryInfoBar.IsClosable = true;
		}
	}

	private static List<RegistryHistoryEntry> CheckTypedPathHistory()
	{
		using RegistryKey? key = Registry.CurrentUser.OpenSubKey(TypedPathHistoryRegistryPath, writable: false);
		if (key is null)
		{
			return [];
		}
		string[] valueNames = key.GetValueNames();
		List<RegistryHistoryEntry> entries = new(valueNames.Length);
		foreach (string valueName in valueNames)
		{
			if (!string.IsNullOrEmpty(valueName) && key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string value && !string.IsNullOrEmpty(value))
			{
				entries.Add(new(TypedPathHistoryRegistryPath, valueName, value));
			}
		}
		return entries;
	}

	#endregion

	#region File Explorer Search Box History

	// WordWheelQuery stores search terms as UTF-16 binary values and uses MRUListEx for ordering.
	// The review shows decoded terms while Clear removes the matching values and updates metadata.

	internal readonly InfoBarSettings SearchBoxHistoryInfoBar = new();
	internal bool SearchBoxHistoryIsEnabled { get; set => SP(ref field, value); } = true;
	internal bool SearchBoxHistoryCanRemove { get; set => SP(ref field, value); }
	internal bool SearchBoxHistoryReviewExpanded { get; set => SP(ref field, value); }
	internal string? SearchBoxHistoryResults { get; set => SP(ref field, value); }
	private const string SearchBoxHistoryRegistryPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery";
	private readonly List<RegistryHistoryEntry> SearchBoxHistoryEntriesToDelete = [];

	internal async void CheckSearchBoxHistory_Click()
	{
		try
		{
			SearchBoxHistoryIsEnabled = false;
			SearchBoxHistoryCanRemove = false;
			SearchBoxHistoryInfoBar.IsClosable = false;
			List<RegistryHistoryEntry> entries = await Task.Run(CheckSearchBoxHistory);
			SearchBoxHistoryEntriesToDelete.Clear();
			SearchBoxHistoryEntriesToDelete.AddRange(entries);
			SearchBoxHistoryResults = string.Join(Environment.NewLine, entries.Select(static entry => entry.DisplayText));
			SearchBoxHistoryCanRemove = entries.Count > 0;
			if (SearchBoxHistoryCanRemove)
			{
				SearchBoxHistoryInfoBar.WriteSuccess($"Found {entries.Count} File Explorer search history entry(s).");
			}
			else
			{
				SearchBoxHistoryInfoBar.WriteInfo("No File Explorer search history was found to clear.");
			}
		}
		catch (Exception ex)
		{
			SearchBoxHistoryEntriesToDelete.Clear();
			SearchBoxHistoryCanRemove = false;
			SearchBoxHistoryResults = null;
			SearchBoxHistoryInfoBar.WriteError(ex);
		}
		finally
		{
			SearchBoxHistoryIsEnabled = true;
			SearchBoxHistoryInfoBar.IsClosable = true;
		}
	}

	internal async void RemoveSearchBoxHistory_Click()
	{
		if (SearchBoxHistoryEntriesToDelete.Count == 0)
		{
			SearchBoxHistoryCanRemove = false;
			SearchBoxHistoryInfoBar.WriteWarning("There is no File Explorer search history to clear.");
			return;
		}
		try
		{
			SearchBoxHistoryIsEnabled = false;
			SearchBoxHistoryCanRemove = false;
			SearchBoxHistoryInfoBar.IsClosable = false;
			List<RegistryHistoryEntry> entries = new(SearchBoxHistoryEntriesToDelete);
			(int DeletedCount, List<string> FailedKeyPaths) = await Task.Run(() => DeleteRegistryHistoryValues(entries));
			SearchBoxHistoryEntriesToDelete.Clear();
			SearchBoxHistoryResults = null;
			if (FailedKeyPaths.Count == 0)
			{
				SearchBoxHistoryReviewExpanded = false;
				SearchBoxHistoryInfoBar.WriteSuccess($"Cleared {DeletedCount} File Explorer search history entry(s).");
			}
			else
			{
				SearchBoxHistoryInfoBar.WriteWarning($"Cleared {DeletedCount} File Explorer search history entry(s), but the operation could not be completed.");
			}
		}
		catch (Exception ex)
		{
			SearchBoxHistoryInfoBar.WriteError(ex);
		}
		finally
		{
			SearchBoxHistoryIsEnabled = true;
			SearchBoxHistoryInfoBar.IsClosable = true;
		}
	}

	private static List<RegistryHistoryEntry> CheckSearchBoxHistory()
	{
		using RegistryKey? key = Registry.CurrentUser.OpenSubKey(SearchBoxHistoryRegistryPath, writable: false);
		if (key is null)
		{
			return [];
		}
		string[] valueNames = key.GetValueNames();
		List<RegistryHistoryEntry> entries = new(valueNames.Length);
		foreach (string valueName in valueNames)
		{
			if (string.IsNullOrEmpty(valueName) || string.Equals(valueName, "MRUListEx", StringComparison.OrdinalIgnoreCase))
			{
				continue;
			}
			if (key.GetValue(valueName) is byte[] data)
			{
				string value = Encoding.Unicode.GetString(data).TrimEnd('\0');
				if (!string.IsNullOrEmpty(value))
				{
					entries.Add(new(SearchBoxHistoryRegistryPath, valueName, value));
				}
			}
		}
		return entries;
	}

	#endregion

	#region Recent Items Shortcuts

	// Enumerates only top-level .lnk files in the current user Recent special folder.
	// Deleting these shortcuts does not delete their target files.

	internal readonly InfoBarSettings RecentItemsInfoBar = new();
	internal bool RecentItemsIsEnabled { get; set => SP(ref field, value); } = true;
	internal bool RecentItemsCanRemove { get; set => SP(ref field, value); }
	internal bool RecentItemsReviewExpanded { get; set => SP(ref field, value); }
	internal string? RecentItemsResults { get; set => SP(ref field, value); }
	private readonly List<string> RecentItemsFilesToDelete = [];

	internal async void CheckRecentItems_Click()
	{
		try
		{
			RecentItemsIsEnabled = false;
			RecentItemsCanRemove = false;
			RecentItemsInfoBar.IsClosable = false;
			List<string> files = await Task.Run(CheckRecentItems);
			RecentItemsFilesToDelete.Clear();
			RecentItemsFilesToDelete.AddRange(files);
			RecentItemsResults = string.Join(Environment.NewLine, files.Select(Path.GetFileName));
			RecentItemsCanRemove = files.Count > 0;
			if (RecentItemsCanRemove)
			{
				RecentItemsInfoBar.WriteSuccess($"Found {files.Count} Recent Items shortcut(s).");
			}
			else
			{
				RecentItemsInfoBar.WriteInfo("No Recent Items shortcuts were found to clear.");
			}
		}
		catch (Exception ex)
		{
			RecentItemsFilesToDelete.Clear();
			RecentItemsCanRemove = false;
			RecentItemsResults = null;
			RecentItemsInfoBar.WriteError(ex);
		}
		finally
		{
			RecentItemsIsEnabled = true;
			RecentItemsInfoBar.IsClosable = true;
		}
	}

	internal async void RemoveRecentItems_Click()
	{
		if (RecentItemsFilesToDelete.Count == 0)
		{
			RecentItemsCanRemove = false;
			RecentItemsInfoBar.WriteWarning("There are no Recent Items shortcuts to clear.");
			return;
		}
		try
		{
			RecentItemsIsEnabled = false;
			RecentItemsCanRemove = false;
			RecentItemsInfoBar.IsClosable = false;
			List<string> files = new(RecentItemsFilesToDelete);
			(int DeletedCount, List<string> FailedPaths) = await Task.Run(() => DeleteFiles(files));
			RecentItemsFilesToDelete.Clear();
			RecentItemsFilesToDelete.AddRange(FailedPaths);
			RecentItemsCanRemove = FailedPaths.Count > 0;
			RecentItemsResults = FailedPaths.Count > 0 ? string.Join(Environment.NewLine, FailedPaths.Select(Path.GetFileName)) : null;
			if (FailedPaths.Count == 0)
			{
				RecentItemsReviewExpanded = false;
				RecentItemsInfoBar.WriteSuccess($"Cleared {DeletedCount} Recent Items shortcut(s).");
			}
			else
			{
				RecentItemsInfoBar.WriteWarning($"Cleared {DeletedCount} of {files.Count} Recent Items shortcut(s). Review the remaining files below.");
			}
		}
		catch (Exception ex)
		{
			RecentItemsInfoBar.WriteError(ex);
		}
		finally
		{
			RecentItemsIsEnabled = true;
			RecentItemsInfoBar.IsClosable = true;
		}
	}

	private static List<string> CheckRecentItems()
	{
		string folder = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
		if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder))
		{
			return [];
		}
		return [.. Directory.EnumerateFiles(folder, "*.lnk", SearchOption.TopDirectoryOnly)];
	}

	#endregion

	#region Common Open Save Dialog History

	// OpenSavePidlMRU stores PIDLs. LastVisitedPidlMRU stores an application name followed by a PIDL.
	// Only records that Windows resolves to a file-system path are displayed and selected for deletion.

	internal readonly InfoBarSettings CommonDialogHistoryInfoBar = new();
	internal bool CommonDialogHistoryIsEnabled { get; set => SP(ref field, value); } = true;
	internal bool CommonDialogHistoryCanRemove { get; set => SP(ref field, value); }
	internal bool CommonDialogHistoryReviewExpanded { get; set => SP(ref field, value); }
	internal string? CommonDialogHistoryResults { get; set => SP(ref field, value); }

	private static readonly string[] CommonDialogHistoryRegistryPaths =
	[
		@"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
		@"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
		@"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy"
	];

	private readonly List<RegistryHistoryEntry> CommonDialogHistoryEntriesToDelete = [];

	internal async void CheckCommonDialogHistory_Click()
	{
		try
		{
			CommonDialogHistoryIsEnabled = false;
			CommonDialogHistoryCanRemove = false;
			CommonDialogHistoryInfoBar.IsClosable = false;
			List<RegistryHistoryEntry> entries = await Task.Run(ReadCommonDialogHistory);
			CommonDialogHistoryEntriesToDelete.Clear();
			CommonDialogHistoryEntriesToDelete.AddRange(entries);
			CommonDialogHistoryResults = string.Join(Environment.NewLine, entries.Select(static entry => entry.DisplayText));
			CommonDialogHistoryCanRemove = entries.Count > 0;
			if (CommonDialogHistoryCanRemove)
			{
				CommonDialogHistoryInfoBar.WriteSuccess($"Found {entries.Count} common Open/Save dialog history record(s).");
			}
			else
			{
				CommonDialogHistoryInfoBar.WriteInfo("No common Open/Save dialog history was found to clear.");
			}
		}
		catch (Exception ex)
		{
			CommonDialogHistoryEntriesToDelete.Clear();
			CommonDialogHistoryCanRemove = false;
			CommonDialogHistoryResults = null;
			CommonDialogHistoryInfoBar.WriteError(ex);
		}
		finally
		{
			CommonDialogHistoryIsEnabled = true;
			CommonDialogHistoryInfoBar.IsClosable = true;
		}
	}

	internal async void RemoveCommonDialogHistory_Click()
	{
		if (CommonDialogHistoryEntriesToDelete.Count == 0)
		{
			CommonDialogHistoryCanRemove = false;
			CommonDialogHistoryInfoBar.WriteWarning("There is no common Open/Save dialog history to clear.");
			return;
		}
		try
		{
			CommonDialogHistoryIsEnabled = false;
			CommonDialogHistoryCanRemove = false;
			CommonDialogHistoryInfoBar.IsClosable = false;
			List<RegistryHistoryEntry> entries = new(CommonDialogHistoryEntriesToDelete);
			(int DeletedCount, List<string> FailedKeyPaths) = await Task.Run(() => DeleteRegistryHistoryValues(entries));
			CommonDialogHistoryEntriesToDelete.Clear();
			CommonDialogHistoryResults = null;
			if (FailedKeyPaths.Count == 0)
			{
				CommonDialogHistoryReviewExpanded = false;
				CommonDialogHistoryInfoBar.WriteSuccess($"Cleared {DeletedCount} common Open/Save dialog history record(s).");
			}
			else
			{
				CommonDialogHistoryInfoBar.WriteWarning($"Cleared {DeletedCount} common Open/Save dialog history record(s), but the operation could not be completed.");
			}
		}
		catch (Exception ex)
		{
			CommonDialogHistoryInfoBar.WriteError(ex);
		}
		finally
		{
			CommonDialogHistoryIsEnabled = true;
			CommonDialogHistoryInfoBar.IsClosable = true;
		}
	}


	// Traverses the supported Common Dialog MRU trees and collects only resolvable records.
	private static List<RegistryHistoryEntry> ReadCommonDialogHistory()
	{
		List<RegistryHistoryEntry> entries = [];
		foreach (string rootPath in CommonDialogHistoryRegistryPaths)
		{
			using RegistryKey? root = Registry.CurrentUser.OpenSubKey(rootPath, writable: false);
			if (root is not null)
			{
				ReadCommonDialogHistoryTree(root, rootPath, entries);
			}
		}
		return entries;
	}

	private static void ReadCommonDialogHistoryTree(RegistryKey key, string keyPath, List<RegistryHistoryEntry> entries)
	{
		bool isLastVisited = keyPath.Contains("LastVisitedPidlMRU", StringComparison.OrdinalIgnoreCase);
		string[] valueNames = key.GetValueNames();
		foreach (string valueName in valueNames)
		{
			if (string.IsNullOrEmpty(valueName) || string.Equals(valueName, "MRUList", StringComparison.OrdinalIgnoreCase) || string.Equals(valueName, "MRUListEx", StringComparison.OrdinalIgnoreCase))
			{
				continue;
			}
			if (key.GetValue(valueName) is byte[] data && TryGetCommonDialogDisplayText(data, isLastVisited, out string? displayText))
			{
				entries.Add(new(keyPath, valueName, displayText));
			}
		}
		string[] subKeyNames = key.GetSubKeyNames();
		foreach (string subKeyName in subKeyNames)
		{
			using RegistryKey? subKey = key.OpenSubKey(subKeyName, writable: false);
			if (subKey is not null)
			{
				ReadCommonDialogHistoryTree(subKey, $"{keyPath}\\{subKeyName}", entries);
			}
		}
	}

	// Separates the optional LastVisited application name from the PIDL and formats the visible review text.
	private static bool TryGetCommonDialogDisplayText(byte[] data, bool isLastVisited, [NotNullWhen(true)] out string? displayText)
	{
		displayText = null;
		int pidlOffset = 0;
		string? applicationName = null;
		if (isLastVisited)
		{
			int applicationNameEnd = FindUtf16NullTerminator(data);
			if (applicationNameEnd < 0)
			{
				return false;
			}
			applicationName = Encoding.Unicode.GetString(data, 0, applicationNameEnd);
			pidlOffset = applicationNameEnd + sizeof(char);
		}
		if (!TryGetFileSystemPathFromPidl(data, pidlOffset, out string? path))
		{
			return false;
		}
		displayText = !string.IsNullOrEmpty(applicationName) ? $"{applicationName}: {path}" : path;
		return true;
	}

	// Returns the byte offset of the first UTF-16 null terminator, or -1 for malformed data.
	private static int FindUtf16NullTerminator(byte[] data)
	{
		for (int offset = 0; offset + 1 < data.Length; offset += sizeof(char))
		{
			if (data[offset] == 0 && data[offset + 1] == 0)
			{
				return offset;
			}
		}
		return -1;
	}

	// Uses the Windows Shell to resolve a validated absolute PIDL. Non-file-system PIDLs are skipped.
	private static unsafe bool TryGetFileSystemPathFromPidl(byte[] data, int offset, [NotNullWhen(true)] out string? path)
	{
		path = null;
		if (!IsValidPidl(data, offset))
		{
			return false;
		}
		char[] buffer = new char[32768];
		fixed (byte* pidl = &data[offset])
		fixed (char* output = buffer)
		{
			if (!NativeMethods.SHGetPathFromIDListEx(pidl, output, (uint)buffer.Length, 0))
			{
				return false;
			}
		}
		int terminator = Array.IndexOf(buffer, '\0');
		if (terminator <= 0)
		{
			return false;
		}
		path = new string(buffer, 0, terminator);
		return true;
	}

	// Validates every SHITEMID size and requires the terminating zero-sized item at the buffer end.
	private static bool IsValidPidl(byte[] data, int offset)
	{
		if (offset < 0 || offset + sizeof(ushort) > data.Length)
		{
			return false;
		}
		int current = offset;
		while (current + sizeof(ushort) <= data.Length)
		{
			ushort itemSize = BitConverter.ToUInt16(data, current);
			if (itemSize == 0)
			{
				return current + sizeof(ushort) == data.Length;
			}
			if (itemSize < sizeof(ushort) || current + itemSize > data.Length)
			{
				return false;
			}
			current += itemSize;
		}
		return false;
	}

	#endregion

	#region RecentDocs Registry History

	// RecentDocs stores numbered binary records and MRUListEx ordering metadata at the root and
	// within extension-specific subkeys. The review shows only decoded item names.

	internal readonly InfoBarSettings RecentDocsHistoryInfoBar = new();
	internal bool RecentDocsHistoryIsEnabled { get; set => SP(ref field, value); } = true;
	internal bool RecentDocsHistoryCanRemove { get; set => SP(ref field, value); }
	internal bool RecentDocsHistoryReviewExpanded { get; set => SP(ref field, value); }
	internal string? RecentDocsHistoryResults { get; set => SP(ref field, value); }
	private const string RecentDocsHistoryRegistryPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs";
	private readonly List<RegistryHistoryEntry> RecentDocsHistoryEntriesToDelete = [];

	internal async void CheckRecentDocsHistory_Click()
	{
		try
		{
			RecentDocsHistoryIsEnabled = false;
			RecentDocsHistoryCanRemove = false;
			RecentDocsHistoryInfoBar.IsClosable = false;
			List<RegistryHistoryEntry> entries = await Task.Run(ReadRecentDocsHistory);
			RecentDocsHistoryEntriesToDelete.Clear();
			RecentDocsHistoryEntriesToDelete.AddRange(entries);
			RecentDocsHistoryResults = string.Join(Environment.NewLine, entries.Select(static entry => entry.DisplayText));
			RecentDocsHistoryCanRemove = entries.Count > 0;
			if (RecentDocsHistoryCanRemove)
			{
				RecentDocsHistoryInfoBar.WriteSuccess($"Found {entries.Count} RecentDocs Registry history record(s).");
			}
			else
			{
				RecentDocsHistoryInfoBar.WriteInfo("No RecentDocs Registry history was found to clear.");
			}
		}
		catch (Exception ex)
		{
			RecentDocsHistoryEntriesToDelete.Clear();
			RecentDocsHistoryCanRemove = false;
			RecentDocsHistoryResults = null;
			RecentDocsHistoryInfoBar.WriteError(ex);
		}
		finally
		{
			RecentDocsHistoryIsEnabled = true;
			RecentDocsHistoryInfoBar.IsClosable = true;
		}
	}

	internal async void RemoveRecentDocsHistory_Click()
	{
		if (RecentDocsHistoryEntriesToDelete.Count == 0)
		{
			RecentDocsHistoryCanRemove = false;
			RecentDocsHistoryInfoBar.WriteWarning("There is no RecentDocs Registry history to clear.");
			return;
		}
		try
		{
			RecentDocsHistoryIsEnabled = false;
			RecentDocsHistoryCanRemove = false;
			RecentDocsHistoryInfoBar.IsClosable = false;
			List<RegistryHistoryEntry> entries = new(RecentDocsHistoryEntriesToDelete);
			(int DeletedCount, List<string> FailedKeyPaths) = await Task.Run(() => DeleteRegistryHistoryValues(entries));
			RecentDocsHistoryEntriesToDelete.Clear();
			RecentDocsHistoryResults = null;
			if (FailedKeyPaths.Count == 0)
			{
				RecentDocsHistoryReviewExpanded = false;
				RecentDocsHistoryInfoBar.WriteSuccess($"Cleared {DeletedCount} RecentDocs Registry history record(s).");
			}
			else
			{
				RecentDocsHistoryInfoBar.WriteWarning($"Cleared {DeletedCount} RecentDocs Registry history record(s), but the operation could not be completed.");
			}
		}
		catch (Exception ex)
		{
			RecentDocsHistoryInfoBar.WriteError(ex);
		}
		finally
		{
			RecentDocsHistoryIsEnabled = true;
			RecentDocsHistoryInfoBar.IsClosable = true;
		}
	}


	// Reads RecentDocs values recursively because Windows stores a general MRU list at the root
	// and additional MRU lists under file-extension and Folder subkeys.
	private static List<RegistryHistoryEntry> ReadRecentDocsHistory()
	{
		using RegistryKey? root = Registry.CurrentUser.OpenSubKey(RecentDocsHistoryRegistryPath, writable: false);
		if (root is null)
		{
			return [];
		}
		List<RegistryHistoryEntry> entries = [];
		ReadRecentDocsHistoryTree(root, RecentDocsHistoryRegistryPath, entries);
		return entries;
	}

	// Adds only values whose leading UTF-16 item name can be decoded. This guarantees that every
	// Registry value selected for deletion has a corresponding human-readable review entry.
	private static void ReadRecentDocsHistoryTree(RegistryKey key, string keyPath, List<RegistryHistoryEntry> entries)
	{
		string[] valueNames = key.GetValueNames();
		foreach (string valueName in valueNames)
		{
			// MRUList and MRUListEx are ordering metadata, not history entries.
			if (string.IsNullOrEmpty(valueName) || string.Equals(valueName, "MRUList", StringComparison.OrdinalIgnoreCase) || string.Equals(valueName, "MRUListEx", StringComparison.OrdinalIgnoreCase))
			{
				continue;
			}
			if (key.GetValue(valueName) is byte[] data && TryGetRecentDocsDisplayText(data, out string? displayText))
			{
				entries.Add(new(keyPath, valueName, displayText));
			}
		}
		string[] subKeyNames = key.GetSubKeyNames();
		foreach (string subKeyName in subKeyNames)
		{
			using RegistryKey? subKey = key.OpenSubKey(subKeyName, writable: false);
			if (subKey is not null)
			{
				ReadRecentDocsHistoryTree(subKey, $"{keyPath}\\{subKeyName}", entries);
			}
		}
	}

	// RecentDocs values begin with a null-terminated UTF-16 item name followed by additional
	// Shell data. Only the documented leading display name is shown; no path is invented.
	private static bool TryGetRecentDocsDisplayText(byte[] data, [NotNullWhen(true)] out string? displayText)
	{
		displayText = null;
		int nameEnd = FindUtf16NullTerminator(data);
		if (nameEnd <= 0)
		{
			return false;
		}
		string name = Encoding.Unicode.GetString(data, 0, nameEnd);
		if (string.IsNullOrWhiteSpace(name) || name.Any(char.IsControl))
		{
			return false;
		}
		displayText = name;
		return true;
	}

	#endregion

	#region Jump List History

	// A Jump List file name is an application identifier hash, not a user-facing application name.
	// The review intentionally shows the exact data-file names that Clear will delete.

	internal readonly InfoBarSettings JumpListHistoryInfoBar = new();
	internal bool JumpListHistoryIsEnabled { get; set => SP(ref field, value); } = true;
	internal bool JumpListHistoryCanRemove { get; set => SP(ref field, value); }
	internal bool JumpListHistoryReviewExpanded { get; set => SP(ref field, value); }
	internal string? JumpListHistoryResults { get; set => SP(ref field, value); }
	private readonly List<string> JumpListHistoryFilesToDelete = [];

	internal async void CheckJumpListHistory_Click()
	{
		try
		{
			JumpListHistoryIsEnabled = false;
			JumpListHistoryCanRemove = false;
			JumpListHistoryInfoBar.IsClosable = false;
			List<string> files = await Task.Run(CheckJumpListHistory);
			JumpListHistoryFilesToDelete.Clear();
			JumpListHistoryFilesToDelete.AddRange(files);
			JumpListHistoryResults = string.Join(Environment.NewLine, files.Select(Path.GetFileName));
			JumpListHistoryCanRemove = files.Count > 0;
			if (JumpListHistoryCanRemove)
			{
				JumpListHistoryInfoBar.WriteSuccess($"Found {files.Count} Jump List data file(s). Clearing them resets recent and pinned Jump List data.");
			}
			else
			{
				JumpListHistoryInfoBar.WriteInfo("No Jump List data files were found to clear.");
			}
		}
		catch (Exception ex)
		{
			JumpListHistoryFilesToDelete.Clear();
			JumpListHistoryCanRemove = false;
			JumpListHistoryResults = null;
			JumpListHistoryInfoBar.WriteError(ex);
		}
		finally
		{
			JumpListHistoryIsEnabled = true;
			JumpListHistoryInfoBar.IsClosable = true;
		}
	}

	internal async void RemoveJumpListHistory_Click()
	{
		if (JumpListHistoryFilesToDelete.Count == 0)
		{
			JumpListHistoryCanRemove = false;
			JumpListHistoryInfoBar.WriteWarning("There are no Jump List data files to clear.");
			return;
		}
		try
		{
			JumpListHistoryIsEnabled = false;
			JumpListHistoryCanRemove = false;
			JumpListHistoryInfoBar.IsClosable = false;
			List<string> files = new(JumpListHistoryFilesToDelete);
			(int DeletedCount, List<string> FailedPaths) = await Task.Run(() => DeleteFiles(files));
			JumpListHistoryFilesToDelete.Clear();
			JumpListHistoryFilesToDelete.AddRange(FailedPaths);
			JumpListHistoryCanRemove = FailedPaths.Count > 0;
			JumpListHistoryResults = FailedPaths.Count > 0 ? string.Join(Environment.NewLine, FailedPaths.Select(Path.GetFileName)) : null;
			if (FailedPaths.Count == 0)
			{
				JumpListHistoryReviewExpanded = false;
				JumpListHistoryInfoBar.WriteSuccess($"Cleared {DeletedCount} Jump List data file(s).");
			}
			else
			{
				JumpListHistoryInfoBar.WriteWarning($"Cleared {DeletedCount} of {files.Count} Jump List data file(s). Files that are in use by Explorer cannot be deleted while it holds them open.");
			}
		}
		catch (Exception ex)
		{
			JumpListHistoryInfoBar.WriteError(ex);
		}
		finally
		{
			JumpListHistoryIsEnabled = true;
			JumpListHistoryInfoBar.IsClosable = true;
		}
	}

	private static List<string> CheckJumpListHistory()
	{
		string recentFolder = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
		if (string.IsNullOrEmpty(recentFolder))
		{
			return [];
		}
		string[] folders =
		[
			Path.Join(recentFolder, "AutomaticDestinations"),
			Path.Join(recentFolder, "CustomDestinations")
		];
		List<string> files = [];
		if (Directory.Exists(folders[0]))
		{
			files.AddRange(Directory.EnumerateFiles(folders[0], "*.automaticDestinations-ms", SearchOption.TopDirectoryOnly));
		}
		if (Directory.Exists(folders[1]))
		{
			files.AddRange(Directory.EnumerateFiles(folders[1], "*.customDestinations-ms", SearchOption.TopDirectoryOnly));
		}
		return files;
	}

	#endregion

	#region Shared History Cleaner Helpers

	// Shared helpers preserve Registry keys, delete only values captured during Check, and update
	// MRUList or MRUListEx ordering metadata only when at least one value was actually removed.

	private sealed record RegistryHistoryEntry(string KeyPath, string ValueName, string DisplayText);

	private static (int DeletedCount, List<string> FailedKeyPaths) DeleteRegistryHistoryValues(List<RegistryHistoryEntry> entries)
	{
		int deleted = 0;
		List<string> failedKeyPaths = [];
		foreach (IGrouping<string, RegistryHistoryEntry> group in entries.GroupBy(static entry => entry.KeyPath, StringComparer.OrdinalIgnoreCase))
		{
			RegistryKey? key = null;
			try
			{
				key = Registry.CurrentUser.OpenSubKey(group.Key, writable: true);
				if (key is null)
				{
					// The key exists for reading but cannot be opened for writing, so the entries
					// that Check displayed are still present. This must not be reported as success.
					failedKeyPaths.Add(group.Key);
					continue;
				}
				List<string> deletedValueNames = [];
				foreach (RegistryHistoryEntry entry in group)
				{
					if (key.GetValue(entry.ValueName) is not null)
					{
						key.DeleteValue(entry.ValueName, throwOnMissingValue: false);
						deletedValueNames.Add(entry.ValueName);
						deleted++;
					}
				}
				UpdateMruMetadata(key, deletedValueNames);
			}
			catch
			{
				// A single unwritable key must not abort the remaining keys in the batch.
				failedKeyPaths.Add(group.Key);
			}
			finally
			{
				key?.Dispose();
			}
		}
		return (deleted, failedKeyPaths);
	}

	private static void UpdateMruMetadata(RegistryKey key, List<string> deletedValueNames)
	{
		// Ordering metadata describes the values that were removed. When nothing was removed there
		// is nothing to reorder, and rewriting or deleting it here would discard valid ordering.
		if (deletedValueNames.Count == 0)
		{
			return;
		}
		if (key.GetValue("MRUList") is string mruList)
		{
			// MRUList holds exactly one character per value name. Removing characters individually
			// avoids the substring replacement hazard where deleting "1" would also corrupt "12".
			StringBuilder builder = new(mruList.Length);
			foreach (char character in mruList)
			{
				bool wasDeleted = false;
				foreach (string valueName in deletedValueNames)
				{
					if (valueName.Length == 1 && char.ToUpperInvariant(valueName[0]) == char.ToUpperInvariant(character))
					{
						wasDeleted = true;
						break;
					}
				}
				if (!wasDeleted)
				{
					_ = builder.Append(character);
				}
			}
			if (builder.Length == 0)
			{
				key.DeleteValue("MRUList", throwOnMissingValue: false);
			}
			else
			{
				key.SetValue("MRUList", builder.ToString(), RegistryValueKind.String);
			}
		}
		if (key.GetValue("MRUListEx") is byte[] mruListEx)
		{
			List<int> deletedIndexes = new(deletedValueNames.Count);
			foreach (string valueName in deletedValueNames)
			{
				if (int.TryParse(valueName, NumberStyles.None, CultureInfo.InvariantCulture, out int index))
				{
					deletedIndexes.Add(index);
				}
			}
			List<int> remainingIndexes = new(mruListEx.Length / sizeof(int));
			for (int offset = 0; offset + sizeof(int) <= mruListEx.Length; offset += sizeof(int))
			{
				int index = BitConverter.ToInt32(mruListEx, offset);
				if (index == -1)
				{
					break;
				}
				if (!deletedIndexes.Contains(index))
				{
					remainingIndexes.Add(index);
				}
			}
			if (remainingIndexes.Count == 0)
			{
				key.DeleteValue("MRUListEx", throwOnMissingValue: false);
			}
			else
			{
				byte[] updated = new byte[(remainingIndexes.Count + 1) * sizeof(int)];
				for (int i = 0; i < remainingIndexes.Count; i++)
				{
					_ = BitConverter.TryWriteBytes(updated.AsSpan(i * sizeof(int), sizeof(int)), remainingIndexes[i]);
				}
				_ = BitConverter.TryWriteBytes(updated.AsSpan(remainingIndexes.Count * sizeof(int), sizeof(int)), -1);
				key.SetValue("MRUListEx", updated, RegistryValueKind.Binary);
			}
		}
	}

	private static (int DeletedCount, List<string> FailedPaths) DeleteFiles(List<string> files)
	{
		int deleted = 0;
		List<string> failedPaths = [];
		foreach (string file in files)
		{
			try
			{
				File.Delete(file);
				deleted++;
			}
			catch
			{
				// Explorer routinely holds Jump List data files open. Collect the failure and keep
				// going so the deletions that did succeed are still reported.
				failedPaths.Add(file);
			}
		}
		return (deleted, failedPaths);
	}

	#endregion

	#endregion

	#region Diagnostics

	#region DNS Client Cache

	internal readonly InfoBarSettings DnsCacheInfoBar = new();

	internal bool DnsCacheIsEnabled { get; set => SP(ref field, value); } = true;

	internal async void FlushDnsCache_Click()
	{
		try
		{
			DnsCacheIsEnabled = false;
			DnsCacheInfoBar.IsClosable = false;
			DnsCacheInfoBar.WriteInfo("Clearing the DNS client cache...");

			// RunCommand throws when ComManager exits with a non-zero code, so reaching the next
			// statement means the method invocation itself succeeded.
			_ = await Task.Run(static () => QuantumRelayHSS.Client.RunCommand(Atlas.ComManagerProcessPath, @"do root\StandardCimv2 MSFT_DNSClientCache Clear"));

			DnsCacheInfoBar.WriteSuccess("The DNS client cache was cleared.");
		}
		catch (Exception ex)
		{
			DnsCacheInfoBar.WriteError(ex);
		}
		finally
		{
			DnsCacheIsEnabled = true;
			DnsCacheInfoBar.IsClosable = true;
		}
	}

	#endregion

	#region Reset IPv4 Addresses

	internal readonly InfoBarSettings IpAddressInfoBar = new();
	internal bool IpAddressIsEnabled { get; set => SP(ref field, value); } = true;

	internal async void ReleaseAndRenewIpAddress_Click()
	{
		try
		{
			IpAddressIsEnabled = false;
			IpAddressInfoBar.IsClosable = false;
			IpAddressInfoBar.WriteInfo("Releasing and renewing active IPv4 DHCP leases...");
			IpAddressLeaseOperationResult result = await Task.Run(ReleaseAndRenewIpAddresses);
			if (result.ApplicableAdapterCount == 0)
			{
				IpAddressInfoBar.WriteInfo("No active DHCP-enabled IPv4 adapters were found.");
			}
			else if (result.Failures.Count == 0)
			{
				IpAddressInfoBar.WriteSuccess($"Reset the IPv4 addresses for: {string.Join(", ", result.SuccessfulAdapterNames)}.");
			}
			else
			{
				string successfulAdapters = result.SuccessfulAdapterNames.Count > 0
					? $" Successfully completed: {string.Join(", ", result.SuccessfulAdapterNames)}."
					: string.Empty;
				IpAddressInfoBar.WriteWarning($"The IPv4 DHCP lease operation completed with errors.{successfulAdapters} {string.Join(" ", result.Failures)}".Trim());
			}
		}
		catch (Exception ex)
		{
			IpAddressInfoBar.WriteError(ex);
		}
		finally
		{
			IpAddressIsEnabled = true;
			IpAddressInfoBar.IsClosable = true;
		}
	}

	private static unsafe IpAddressLeaseOperationResult ReleaseAndRenewIpAddresses()
	{
		const uint noError = 0;
		const uint errorBufferOverflow = 111;
		const uint errorNoData = 232;
		const uint dhcpv4Enabled = 0x00000004;
		const uint ipv4Enabled = 0x00000080;
		const uint ifTypeSoftwareLoopback = 24;
		const uint ifOperStatusUp = 1;
		Dictionary<uint, string> applicableAdapters = [];
		uint adapterAddressesBufferSize = 0;

		uint result = NativeMethods.GetAdaptersAddresses(
			NativeMethods.AF_INET,
			0,
			IntPtr.Zero,
			IntPtr.Zero,
			ref adapterAddressesBufferSize);

		if (result != errorBufferOverflow)
		{
			if (result == noError || result == errorNoData)
			{
				return new(0, [], []);
			}
			throw new Win32Exception(unchecked((int)result));
		}

		IntPtr adapterAddressesBuffer = Marshal.AllocHGlobal(checked((int)adapterAddressesBufferSize));

		try
		{
			while (true)
			{
				result = NativeMethods.GetAdaptersAddresses(
					NativeMethods.AF_INET,
					0,
					IntPtr.Zero,
					adapterAddressesBuffer,
					ref adapterAddressesBufferSize);
				if (result != errorBufferOverflow)
				{
					break;
				}
				adapterAddressesBuffer = Marshal.ReAllocHGlobal(
					adapterAddressesBuffer,
					checked((int)adapterAddressesBufferSize));
			}
			if (result != noError)
			{
				if (result == errorNoData)
				{
					return new(0, [], []);
				}
				throw new Win32Exception(unchecked((int)result));
			}

			IP_ADAPTER_ADDRESSES* currentAdapter = (IP_ADAPTER_ADDRESSES*)adapterAddressesBuffer;

			while (currentAdapter != null)
			{
				bool hasDhcpv4 = (currentAdapter->Flags & dhcpv4Enabled) != 0;
				bool hasIpv4 = (currentAdapter->Flags & ipv4Enabled) != 0;
				bool isOperational = currentAdapter->OperStatus == ifOperStatusUp;
				bool isLoopback = currentAdapter->IfType == ifTypeSoftwareLoopback;
				bool hasUnicastAddress = currentAdapter->FirstUnicastAddress != IntPtr.Zero;
				if (hasDhcpv4 && hasIpv4 && isOperational && !isLoopback && hasUnicastAddress && currentAdapter->IfIndex != 0)
				{
					string friendlyName = currentAdapter->FriendlyName != IntPtr.Zero
						? new string((char*)currentAdapter->FriendlyName)
						: currentAdapter->IfIndex.ToString(CultureInfo.InvariantCulture);
					applicableAdapters[currentAdapter->IfIndex] = friendlyName;
				}
				currentAdapter = (IP_ADAPTER_ADDRESSES*)currentAdapter->Next;
			}
		}
		finally
		{
			Marshal.FreeHGlobal(adapterAddressesBuffer);
		}
		if (applicableAdapters.Count == 0)
		{
			return new(0, [], []);
		}

		uint interfaceInfoBufferSize = 0;
		result = NativeMethods.GetInterfaceInfo(IntPtr.Zero, ref interfaceInfoBufferSize);

		if (result != NativeMethods.ERROR_INSUFFICIENT_BUFFER)
		{
			if (result == noError || result == errorNoData)
			{
				return new(0, [], []);
			}
			throw new Win32Exception(unchecked((int)result));
		}

		IntPtr interfaceInfoBuffer = Marshal.AllocHGlobal(checked((int)interfaceInfoBufferSize));

		try
		{
			result = NativeMethods.GetInterfaceInfo(interfaceInfoBuffer, ref interfaceInfoBufferSize);
			if (result != noError)
			{
				if (result == errorNoData)
				{
					return new(0, [], []);
				}
				throw new Win32Exception(unchecked((int)result));
			}

			int adapterCount = Marshal.ReadInt32(interfaceInfoBuffer);

			List<string> successfulAdapterNames = new(applicableAdapters.Count);

			List<string> failures = new(applicableAdapters.Count);

			IP_ADAPTER_INDEX_MAP* adapterMaps = (IP_ADAPTER_INDEX_MAP*)((byte*)interfaceInfoBuffer + sizeof(int));

			for (int i = 0; i < adapterCount; i++)
			{
				IP_ADAPTER_INDEX_MAP adapterMap = adapterMaps[i];
				if (!applicableAdapters.TryGetValue(adapterMap.Index, out string? friendlyName))
				{
					continue;
				}
				uint releaseResult = NativeMethods.IpReleaseAddress(ref adapterMap);
				if (releaseResult != noError)
				{
					failures.Add($"{friendlyName}: release failed with error {releaseResult} ({GetIpAddressErrorMessage(releaseResult)}).");
					continue;
				}
				uint renewResult = NativeMethods.IpRenewAddress(ref adapterMap);
				if (renewResult != noError)
				{
					failures.Add($"{friendlyName}: the address was released, but renewal failed with error {renewResult} ({GetIpAddressErrorMessage(renewResult)}).");
					continue;
				}
				successfulAdapterNames.Add(friendlyName);
			}

			foreach (KeyValuePair<uint, string> applicableAdapter in applicableAdapters)
			{
				bool wasProcessed = successfulAdapterNames.Contains(applicableAdapter.Value, StringComparer.OrdinalIgnoreCase)
					|| failures.Any(failure => failure.StartsWith($"{applicableAdapter.Value}:", StringComparison.OrdinalIgnoreCase));
				if (!wasProcessed)
				{
					failures.Add($"{applicableAdapter.Value}: the adapter could not be matched to the IPv4 interface information returned by Windows.");
				}
			}

			return new(applicableAdapters.Count, successfulAdapterNames, failures);
		}
		finally
		{
			Marshal.FreeHGlobal(interfaceInfoBuffer);
		}
	}

	private static string GetIpAddressErrorMessage(uint errorCode) => new Win32Exception(unchecked((int)errorCode)).Message;

	private sealed record IpAddressLeaseOperationResult(int ApplicableAdapterCount, List<string> SuccessfulAdapterNames, List<string> Failures);

	#endregion

	#region Reset System Proxy

	internal readonly InfoBarSettings WinHttpAutoProxyInfoBar = new();
	internal bool WinHttpAutoProxyIsEnabled { get; set => SP(ref field, value); } = true;

	internal async void ResetWinHttpAutoProxy_Click()
	{
		try
		{
			WinHttpAutoProxyIsEnabled = false;
			WinHttpAutoProxyInfoBar.IsClosable = false;
			WinHttpAutoProxyInfoBar.WriteInfo("Resetting the system proxy settings...");
			await Task.Run(ResetWinHttpAutoProxy);
			WinHttpAutoProxyInfoBar.WriteSuccess("The system proxy settings were reset.");
		}
		catch (Exception ex)
		{
			WinHttpAutoProxyInfoBar.WriteError(ex);
		}
		finally
		{
			WinHttpAutoProxyIsEnabled = true;
			WinHttpAutoProxyInfoBar.IsClosable = true;
		}
	}

	private static void ResetWinHttpAutoProxy()
	{
		const uint winHttpAccessTypeAutomaticProxy = 4;
		const uint winHttpResetAll = 0x0000FFFF;
		const uint winHttpResetOutOfProcess = 0x00020000;

		IntPtr session = NativeMethods.WinHttpOpen(
			"Harden System Security",
			winHttpAccessTypeAutomaticProxy,
			null,
			null,
			0);
		if (session == IntPtr.Zero)
		{
			throw new Win32Exception(Marshal.GetLastPInvokeError());
		}

		try
		{
			// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpresetautoproxy#remarks
			uint result = NativeMethods.WinHttpResetAutoProxy(
				session,
				winHttpResetAll | winHttpResetOutOfProcess);
			if (result != NativeMethods.ERROR_SUCCESS)
			{
				throw new Win32Exception(unchecked((int)result));
			}
		}
		finally
		{
			_ = NativeMethods.WinHttpCloseHandle(session);
		}
	}

	#endregion

	#region Disk Health Model Updates

	internal readonly InfoBarSettings DiskHealthModelUpdatesInfoBar = new();

	internal bool DiskHealthModelUpdatesIsEnabled { get; set => SP(ref field, value); } = true;

	internal bool DiskHealthModelUpdatesIsOn { get; set => SP(ref field, value); } = IsDiskHealthModelUpdatesEnabled();

	private static readonly RegistryPolicyEntry DiskHealthModelUpdatesEnabledPolicy = new(
		source: Source.GroupPolicy,
		keyName: "Software\\Policies\\Microsoft\\Windows\\StorageHealth",
		valueName: "AllowDiskHealthModelUpdates",
		type: RegistryValueType.REG_DWORD,
		size: 4,
		data: new byte[] { 1, 0, 0, 0 },
		hive: Hive.HKLM,
		id: new("01a0b3f6-f00d-7bcc-9f65-f125d671c18a"));

	private static readonly RegistryPolicyEntry DiskHealthModelUpdatesDisabledPolicy = new(
		source: Source.GroupPolicy,
		keyName: "Software\\Policies\\Microsoft\\Windows\\StorageHealth",
		valueName: "AllowDiskHealthModelUpdates",
		type: RegistryValueType.REG_DWORD,
		size: 4,
		data: new byte[] { 0, 0, 0, 0 },
		hive: Hive.HKLM,
		id: new("01a0b3f6-f00d-7bcc-9f65-f125d671c18a"));

	[DynamicWindowsRuntimeCast(typeof(ToggleSwitch))]
	internal async void DiskHealthModelUpdates_Toggled(object sender, Microsoft.UI.Xaml.RoutedEventArgs args)
	{
		bool isEnabled = IsDiskHealthModelUpdatesEnabled();
		bool isOn = ((ToggleSwitch)sender).IsOn;
		if (isOn == isEnabled)
		{
			return;
		}

		try
		{
			DiskHealthModelUpdatesIsEnabled = false;
			DiskHealthModelUpdatesInfoBar.IsClosable = false;
			DiskHealthModelUpdatesInfoBar.WriteInfo(isOn ? "Enabling disk health model updates..." : "Disabling disk health model updates...");

			RegistryPolicyEntry policy = isOn ? DiskHealthModelUpdatesEnabledPolicy : DiskHealthModelUpdatesDisabledPolicy;
			await Task.Run(() => RegistryPolicyParser.AddPoliciesToSystem([policy], GroupPolicyContext.Machine));

			DiskHealthModelUpdatesIsOn = IsDiskHealthModelUpdatesEnabled();
			DiskHealthModelUpdatesInfoBar.WriteSuccess(DiskHealthModelUpdatesIsOn ? "Disk health model updates are enabled." : "Disk health model updates are disabled.");
		}
		catch (Exception ex)
		{
			DiskHealthModelUpdatesIsOn = IsDiskHealthModelUpdatesEnabled();
			DiskHealthModelUpdatesInfoBar.WriteError(ex);
		}
		finally
		{
			DiskHealthModelUpdatesIsEnabled = true;
			DiskHealthModelUpdatesInfoBar.IsClosable = true;
		}
	}

	private static bool IsDiskHealthModelUpdatesEnabled()
	{
		Dictionary<RegistryPolicyEntry, (bool IsCompliant, RegistryPolicyEntry? SystemEntry)> result = RegistryPolicyParser.VerifyPoliciesInSystem([DiskHealthModelUpdatesEnabledPolicy], GroupPolicyContext.Machine);
		return !result.TryGetValue(DiskHealthModelUpdatesEnabledPolicy, out (bool IsCompliant, RegistryPolicyEntry? SystemEntry) state) || state.SystemEntry is null || state.IsCompliant;
	}

	#endregion

	#region Windows Recovery Environment

	internal readonly InfoBarSettings WindowsReInfoBar = new();
	internal bool WindowsReIsEnabled { get; set => SP(ref field, value); }
	internal bool WindowsReIsOn { get; set => SP(ref field, value); }
	private const uint WimOpenExisting = 3;

	[DynamicWindowsRuntimeCast(typeof(ToggleSwitch))]
	internal async void WindowsRe_Toggled(object sender, Microsoft.UI.Xaml.RoutedEventArgs args)
	{
		bool isOn = ((ToggleSwitch)sender).IsOn;
		if (!WindowsReIsEnabled || isOn == WindowsReIsOn)
		{
			return;
		}
		try
		{
			WindowsReIsEnabled = false;
			WindowsReInfoBar.IsClosable = false;
			WindowsReInfoBar.WriteInfo(isOn ? "Enabling Windows Recovery Environment..." : "Disabling Windows Recovery Environment...");
			WinReConfigurationResult result = await Task.Run(() => ChangeWindowsReState(isOn));
			WindowsReIsOn = result.IsEnabled;
			WindowsReInfoBar.WriteSuccess($"Windows Recovery Environment was {(result.IsEnabled ? "enabled" : "disabled")}.\n\n{result.Details}");
		}
		catch (Exception ex)
		{
			try
			{
				WinReConfigurationResult result = await Task.Run(GetWindowsReConfiguration);
				WindowsReIsOn = result.IsEnabled;
			}
			catch
			{
			}
			WindowsReInfoBar.WriteError(ex);
		}
		finally
		{
			WindowsReIsEnabled = true;
			WindowsReInfoBar.IsClosable = false;
		}
	}

	private async Task RefreshWindowsReConfiguration()
	{
		try
		{
			WindowsReIsEnabled = false;
			WindowsReInfoBar.IsClosable = false;
			WinReConfigurationResult result = await Task.Run(GetWindowsReConfiguration);
			WindowsReIsOn = result.IsEnabled;
			WindowsReInfoBar.WriteInfo(result.Details);
		}
		catch (Exception ex)
		{
			WindowsReInfoBar.WriteError(ex);
		}
		finally
		{
			WindowsReIsEnabled = true;
			WindowsReInfoBar.IsClosable = false;
		}
	}

	private static unsafe WinReConfigurationResult ChangeWindowsReState(bool enable)
	{
		WINRE_CONFIG currentConfig = GetWindowsReConfig();
		if (currentConfig.WindowsReEnabled != 0 == enable)
		{
			return CreateWindowsReConfigurationResult(&currentConfig);
		}
		if (enable)
		{
			if (NativeMethods.WinReInstall(1, null) == 0)
			{
				int error = Marshal.GetLastPInvokeError();
				Win32Exception exception = new(error);
				if (error == 2)
				{
					// At this point, reagentc.exe /enable also fails
					throw new Win32Exception(error, $"Windows RE could not be enabled because no suitable destination partition was found. The recovery partition may be missing, incorrectly typed, or too small, and Windows cannot use the BitLocker-protected operating-system partition. Native error: {error}, {exception.Message}");
				}
				throw exception;
			}
		}
		else if (NativeMethods.WinReUnInstall() == 0)
		{
			throw new Win32Exception(Marshal.GetLastPInvokeError());
		}

		WINRE_CONFIG updatedConfig = GetWindowsReConfig();

		if (updatedConfig.WindowsReEnabled != 0 != enable)
		{
			throw new InvalidOperationException(enable ? "WinReInstall completed successfully, but Windows RE is still disabled." : "WinReUnInstall completed successfully, but Windows RE is still enabled.");
		}

		return CreateWindowsReConfigurationResult(&updatedConfig);
	}

	private static unsafe WinReConfigurationResult GetWindowsReConfiguration()
	{
		WINRE_CONFIG config = GetWindowsReConfig();
		return CreateWindowsReConfigurationResult(&config);
	}

	private static unsafe WINRE_CONFIG GetWindowsReConfig()
	{
		if (sizeof(WINRE_CONFIG) != WINRE_CONFIG.ExpectedSize)
		{
			throw new InvalidOperationException($"The Windows RE configuration structure has an unexpected size of {sizeof(WINRE_CONFIG)} bytes.");
		}
		WINRE_CONFIG config = default;
		config.Size = WINRE_CONFIG.ExpectedSize;
		if (NativeMethods.WinReGetConfig(null, &config) == 0)
		{
			throw new Win32Exception(Marshal.GetLastPInvokeError());
		}
		return config;
	}

	private static unsafe WinReConfigurationResult CreateWindowsReConfigurationResult(WINRE_CONFIG* config)
	{
		string winReLocation = GetWindowsReString(config->WinReLocation, WINRE_CONFIG.PathCharacterCount);
		int winReImageHashLength = Math.Min(checked((int)config->WinReImageHashLength), WINRE_CONFIG.HashLength);
		string winReImageHash = winReImageHashLength == 0 ? string.Empty : Convert.ToHexString(new ReadOnlySpan<byte>(config->WinReImageHash, winReImageHashLength));
		string version = GetWindowsReVersion(winReLocation);
		StringBuilder details = new(512);
		_ = details.AppendLine($"Windows RE version: {version}");
		_ = details.AppendLine($"Windows RE location: {winReLocation}");
		_ = details.AppendLine($"BCD identifier: {config->WindowsReBcdIdentifier}");
		_ = details.AppendLine($"Scheduled operation: {config->ScheduledOperation}");
		_ = details.AppendLine($"Automatic repair enabled: {config->IsAutoRepairOn}");
		_ = details.AppendLine($"Windows RE image hash: {winReImageHash}");
		return new(config->WindowsReEnabled != 0, details.ToString());
	}

	private static unsafe string GetWindowsReString(char* value, int capacity)
	{
		int length = 0;
		while (length < capacity && value[length] != '\0')
		{
			length++;
		}
		return new(value, 0, length);
	}

	private static unsafe string GetWindowsReVersion(string winReLocation)
	{
		if (string.IsNullOrEmpty(winReLocation))
		{
			return string.Empty;
		}
		string path = Path.Join(winReLocation, "winre.wim");
		uint creationResult;
		IntPtr wimHandle;
		fixed (char* pathPointer = path)
		{
			wimHandle = NativeMethods.WIMCreateFile(pathPointer, 0, WimOpenExisting, 0, 0, &creationResult);
		}
		if (wimHandle == IntPtr.Zero || wimHandle == NativeMethods.INVALID_HANDLE_VALUE)
		{
			throw new Win32Exception(Marshal.GetLastPInvokeError());
		}
		try
		{
			IntPtr information = IntPtr.Zero;
			uint informationSize;
			if (NativeMethods.WIMGetImageInformation(wimHandle, &information, &informationSize) == 0)
			{
				throw new Win32Exception(Marshal.GetLastPInvokeError());
			}
			try
			{
				ReadOnlySpan<char> characters = new((void*)information, checked((int)informationSize / sizeof(char)));
				int start = 0;
				while (start < characters.Length && (characters[start] == '\0' || characters[start] == '\uFEFF'))
				{
					start++;
				}
				int end = characters.Length;
				while (end > start && (characters[end - 1] == '\0' || characters[end - 1] == '\uFEFF'))
				{
					end--;
				}
				XElement? version = XDocument.Parse(new(characters[start..end])).Root?.Elements("IMAGE").FirstOrDefault()?.Element("WINDOWS")?.Element("VERSION");
				return version is null ? string.Empty : $"{version.Element("MAJOR")?.Value ?? "0"}.{version.Element("MINOR")?.Value ?? "0"}.{version.Element("BUILD")?.Value ?? "0"}.{version.Element("SPBUILD")?.Value ?? "0"}";
			}
			finally
			{
				_ = NativeMethods.LocalFree(information);
			}
		}
		finally
		{
			_ = NativeMethods.WIMCloseHandle(wimHandle);
		}
	}

	private sealed record WinReConfigurationResult(bool IsEnabled, string Details);

	#endregion

	#endregion

}
