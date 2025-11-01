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
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading;
using AppControlManager.ViewModels;

namespace HardenSystemSecurity.SecurityPolicy;

/// <summary>
/// Represents a single audit policy entry with subcategory information
/// </summary>
/// <param name="subcategoryGuid">The GUID of the audit subcategory</param>
/// <param name="subcategoryName">The friendly name of the subcategory</param>
/// <param name="categoryGuid">The GUID of the parent category</param>
/// <param name="categoryName">The friendly name of the parent category</param>
/// <param name="auditingInformation">The current audit setting</param>
internal sealed partial class AuditPolicyInfo(
	Guid subcategoryGuid,
	string subcategoryName,
	Guid categoryGuid,
	string categoryName,
	uint auditingInformation) : ViewModelBase
{
	[JsonInclude]
	[JsonPropertyOrder(4)]
	internal Guid SubcategoryGuid => subcategoryGuid;

	[JsonInclude]
	[JsonPropertyOrder(1)]
	internal string SubcategoryName => subcategoryName;

	[JsonInclude]
	[JsonPropertyOrder(3)]
	internal Guid CategoryGuid => categoryGuid;

	[JsonInclude]
	[JsonPropertyOrder(0)]
	internal string CategoryName => categoryName;

	[JsonIgnore]
	private uint _originalAuditingInformation = auditingInformation;
	[JsonIgnore]
	private uint _currentAuditingInformation = auditingInformation;

	[JsonInclude]
	[JsonPropertyOrder(2)]
	internal uint AuditingInformation
	{
		get => _currentAuditingInformation;
		set
		{
			if (_currentAuditingInformation != value)
			{
				_currentAuditingInformation = value;

				_ = Dispatcher.TryEnqueue(() =>
				{
					OnPropertyChanged(nameof(AuditSettingDescription));
					OnPropertyChanged(nameof(SelectedAuditSettingIndex));
					OnPropertyChanged(nameof(HasPendingChanges));
				});
			}
		}
	}

	[JsonIgnore]
	internal uint OriginalAuditingInformation => _originalAuditingInformation;

	/// <summary>
	/// Gets whether there are pending changes (current value different from original)
	/// </summary>
	[JsonIgnore]
	internal bool HasPendingChanges => _currentAuditingInformation != _originalAuditingInformation;

	/// <summary>
	/// Updates the original value after successful application
	/// </summary>
	internal void CommitChanges()
	{
		_originalAuditingInformation = _currentAuditingInformation;
		_ = Dispatcher.TryEnqueue(() =>
		{
			OnPropertyChanged(nameof(HasPendingChanges));
		});
	}

	/// <summary>
	/// Reverts current value back to original.
	/// </summary>
	internal void RevertChanges()
	{
		AuditingInformation = _originalAuditingInformation;
	}

	/// <summary>
	/// Gets the human-readable audit setting
	/// </summary>
	[JsonIgnore]
	internal string AuditSettingDescription => GetAuditSettingDescription(_currentAuditingInformation);

	/// <summary>
	/// Gets or sets the selected index for the ComboBox binding (0-3)
	/// </summary>
	[JsonIgnore]
	internal int SelectedAuditSettingIndex
	{
		get => (int)_currentAuditingInformation;
		set
		{
			uint newValue = (uint)Math.Max(0, Math.Min(3, value));
			AuditingInformation = newValue;
		}
	}

	/// <summary>
	/// Converts audit setting numeric value to human-readable description.
	/// </summary>
	/// <param name="auditingInformation">Numeric audit setting value</param>
	/// <returns>Human-readable description</returns>
	internal static string GetAuditSettingDescription(uint auditingInformation)
	{
		return auditingInformation switch
		{
			0 => GlobalVars.GetStr("NoAuditingText"),
			1 => GlobalVars.GetStr("SuccessText"),
			2 => GlobalVars.GetStr("FailureText"),
			3 => GlobalVars.GetStr("SuccessAndFailureText"),
			_ => GlobalVars.GetStr("UnknownState")
		};
	}
}

[JsonSerializable(typeof(AuditPolicyInfo))]
[JsonSerializable(typeof(List<AuditPolicyInfo>))]
[JsonSerializable(typeof(ObservableCollection<AuditPolicyInfo>))]
[JsonSourceGenerationOptions(
	WriteIndented = true,
	PropertyNamingPolicy = JsonKnownNamingPolicy.Unspecified,
	PropertyNameCaseInsensitive = true,
	DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal sealed partial class AuditPolicyJsonContext : JsonSerializerContext
{
}

/// <summary>
/// Represents a CSV audit policy entry to be applied
/// </summary>
/// <param name="subcategoryGuid">The GUID of the audit subcategory</param>
/// <param name="subcategoryName">The friendly name of the subcategory</param>
/// <param name="inclusionSetting">The inclusion setting from CSV</param>
/// <param name="settingValue">The numeric setting value</param>
internal sealed class CsvAuditPolicyEntry(
	Guid subcategoryGuid,
	string subcategoryName,
	string inclusionSetting,
	uint settingValue)
{
	internal Guid SubcategoryGuid => subcategoryGuid;
	internal string SubcategoryName => subcategoryName;
	internal string InclusionSetting => inclusionSetting;
	internal uint SettingValue => settingValue;
}

/// <summary>
/// Ensures required privileges are enabled for audit policy enumeration / modification.
/// This guarantees that calls to Audit* APIs succeed when run as admin where the privileges
/// are present but initially disabled in the process token.
/// If they are not enabled, the API calls will not fail but policies will not be applied either.
/// </summary>
internal static class AuditPrivilegeHelper
{
	private const string SecurityPrivilegeName = "SeSecurityPrivilege";

	private const uint TOKEN_QUERY = 0x0008;
	private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
	private const uint SE_PRIVILEGE_ENABLED = 0x00000002;

	/// <summary>
	/// Ensures we only attempt once per process
	/// </summary>
	private static bool _attempted;

	private static readonly Lock _lock = new();

	/// <summary>
	/// Ensure required privileges are enabled exactly once per process.
	/// Safe to call multiple times; subsequent calls are no-ops.
	/// </summary>
	internal static void EnsurePrivileges()
	{
		if (_attempted)
		{
			return;
		}

		lock (_lock)
		{
			if (_attempted)
			{
				return;
			}

			IntPtr processHandle = Process.GetCurrentProcess().Handle;

			bool opened = NativeMethods.OpenProcessToken(processHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out nint tokenHandle);
			if (!opened)
			{
				int error = Marshal.GetLastPInvokeError();
				throw new InvalidOperationException(string.Format(GlobalVars.GetStr("OpenProcessTokenFailedError"), error));
			}

			try
			{
				EnablePrivilege(tokenHandle, SecurityPrivilegeName);
			}
			finally
			{
				_ = NativeMethods.CloseHandle(tokenHandle);
			}

			_attempted = true;
		}
	}

	/// <summary>
	/// Enables a single privilege on the process token.
	/// </summary>
	/// <param name="tokenHandle">Token</param>
	/// <param name="privilegeName">Privilege name</param>
	private static void EnablePrivilege(IntPtr tokenHandle, string privilegeName)
	{
		bool lookup = NativeMethods.LookupPrivilegeValueW(null, privilegeName, out LUID luid);
		if (!lookup)
		{
			int errLookup = Marshal.GetLastPInvokeError();
			throw new InvalidOperationException(string.Format(GlobalVars.GetStr("LookupPrivilegeValueFailedError"), privilegeName, errLookup));
		}

		TOKEN_PRIVILEGES tp = new()
		{
			PrivilegeCount = 1,
			Privileges = new LUID_AND_ATTRIBUTES
			{
				Luid = luid,
				Attributes = SE_PRIVILEGE_ENABLED
			}
		};

		bool adjusted = NativeMethods.AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);

		int adjustError = Marshal.GetLastPInvokeError();

		if (!adjusted)
		{
			throw new InvalidOperationException(string.Format(GlobalVars.GetStr("AdjustTokenPrivilegesFailedError"), privilegeName, adjustError));
		}

		if (adjustError == 1300) // ERROR_NOT_ALL_ASSIGNED
		{
			throw new InvalidOperationException(string.Format(GlobalVars.GetStr("PrivilegeNotAssignedError"), privilegeName));
		}
	}
}

/// <summary>
/// https://learn.microsoft.com/windows/win32/api/ntsecapi/ns-ntsecapi-audit_policy_information
/// </summary>
[Flags]
internal enum AuditBitFlags : uint
{
	POLICY_AUDIT_EVENT_UNCHANGED = 0x00000000,
	POLICY_AUDIT_EVENT_SUCCESS = 0x00000001,
	POLICY_AUDIT_EVENT_FAILURE = 0x00000002,
	POLICY_AUDIT_EVENT_NONE = 0x00000004
}

/// <summary>
/// Manages audit policy operations including reading current policies and applying CSV-based policies.
/// </summary>
internal static class AuditPolicyManager
{
	/// <summary>
	/// Gets the category GUID for a given subcategory GUID
	/// </summary>
	/// <param name="subcategoryGuid">The subcategory GUID</param>
	/// <returns>The parent category GUID</returns>
	internal unsafe static Guid GetCategoryGuidForSubcategory(Guid subcategoryGuid)
	{
		// Ensure privileges before calling enumeration APIs
		AuditPrivilegeHelper.EnsurePrivileges();

		if (!NativeMethods.AuditEnumerateCategories(out IntPtr categoriesPtr, out uint categoriesCount))
		{
			int error = Marshal.GetLastPInvokeError();
			throw new InvalidOperationException(string.Format(GlobalVars.GetStr("FailedToEnumerateAuditCategoriesError"), error));
		}

		try
		{
			int guidSize = sizeof(Guid);

			for (uint i = 0; i < categoriesCount; i++)
			{
				IntPtr categoryGuidPtr = IntPtr.Add(categoriesPtr, (int)i * guidSize);
				Guid categoryGuid = *(Guid*)categoryGuidPtr;

				// Setting this to FALSE correctly restricts enumeration to subcategories actually belonging to the category.
				// When TRUE, the API returns ALL subcategories irrespective of the supplied category GUID.
				// That causes every subcategory to appear under every category. (60 * 9 = 540!!)
				if (!NativeMethods.AuditEnumerateSubCategories(categoryGuidPtr, false, out IntPtr subCatPtr, out uint subCatCount))
				{
					continue;
				}

				try
				{
					for (uint j = 0; j < subCatCount; j++)
					{
						Guid subGuid = *(Guid*)IntPtr.Add(subCatPtr, (int)j * guidSize);
						if (subGuid == subcategoryGuid)
						{
							return categoryGuid;
						}
					}
				}
				finally
				{
					NativeMethods.AuditFree(subCatPtr);
				}
			}
		}
		finally
		{
			NativeMethods.AuditFree(categoriesPtr);
		}

		throw new InvalidOperationException(string.Format(GlobalVars.GetStr("FailedToGetCategoryIdForSubCategoryError"), subcategoryGuid));
	}

	/// <summary>
	/// Gets the current audit policy settings for all available subcategories
	/// </summary>
	/// <returns>List of all audit policy information</returns>
	internal static unsafe List<AuditPolicyInfo> GetAllAuditPolicies()
	{
		// Ensure privileges before any enumeration/query
		AuditPrivilegeHelper.EnsurePrivileges();

		List<AuditPolicyInfo> auditPolicies = [];

		if (!NativeMethods.AuditEnumerateCategories(out IntPtr categoriesPtr, out uint categoriesCount))
		{
			int error = Marshal.GetLastPInvokeError();
			throw new InvalidOperationException(string.Format(GlobalVars.GetStr("FailedToEnumerateAuditCategoriesError"), error));
		}

		try
		{
			int guidSize = sizeof(Guid);
			List<(Guid subCategoryGuid, Guid categoryGuid)> allSubCategories = [];

			// Enumerate all subcategories for each category
			for (uint i = 0; i < categoriesCount; i++)
			{
				IntPtr categoryGuidPtr = IntPtr.Add(categoriesPtr, (int)i * guidSize);
				Guid categoryGuid = *(Guid*)categoryGuidPtr;

				// FALSE for the 'AllSubCategories' parameter so we only get subcategories that belong to this category.
				// TRUE would produce every subcategory for every category, causing duplicates and incorrect category mapping.
				if (!NativeMethods.AuditEnumerateSubCategories(categoryGuidPtr, false, out IntPtr subCatPtr, out uint subCatCount))
				{
					continue; // Skip categories that fail to enumerate
				}

				try
				{
					for (uint j = 0; j < subCatCount; j++)
					{
						Guid subCategoryGuid = *(Guid*)IntPtr.Add(subCatPtr, (int)j * guidSize);
						allSubCategories.Add((subCategoryGuid, categoryGuid));
					}
				}
				finally
				{
					NativeMethods.AuditFree(subCatPtr);
				}
			}

			if (allSubCategories.Count == 0)
			{
				throw new InvalidOperationException(GlobalVars.GetStr("NoAuditSubcategoriesFoundError"));
			}

			// Query audit policies for all subcategories in smaller batches to avoid API limits
			const int batchSize = 50;
			for (int batchStart = 0; batchStart < allSubCategories.Count; batchStart += batchSize)
			{
				int currentBatchSize = Math.Min(batchSize, allSubCategories.Count - batchStart);

				IntPtr batchGuidsPtr = Marshal.AllocHGlobal(currentBatchSize * guidSize);
				try
				{
					// Copy GUIDs for this batch
					for (int i = 0; i < currentBatchSize; i++)
					{
						*(Guid*)IntPtr.Add(batchGuidsPtr, i * guidSize) = allSubCategories[batchStart + i].subCategoryGuid;
					}

					if (!NativeMethods.AuditQuerySystemPolicy(batchGuidsPtr, (uint)currentBatchSize, out IntPtr auditPolicyPtr))
					{
						int error = Marshal.GetLastPInvokeError();
						throw new InvalidOperationException(string.Format(GlobalVars.GetStr("FailedToQueryAuditSystemPolicyBatchError"), batchStart, error));
					}

					if (auditPolicyPtr == IntPtr.Zero)
					{
						throw new InvalidOperationException(string.Format(GlobalVars.GetStr("AuditQuerySystemPolicyReturnedNullBatchError"), batchStart));
					}

					try
					{
						for (int i = 0; i < currentBatchSize; i++)
						{
							AUDIT_POLICY_INFORMATION info = *(AUDIT_POLICY_INFORMATION*)IntPtr.Add(auditPolicyPtr, i * sizeof(AUDIT_POLICY_INFORMATION));

							string subcategoryName = GetSubcategoryName(allSubCategories[batchStart + i].subCategoryGuid);
							string categoryName = GetCategoryName(allSubCategories[batchStart + i].categoryGuid);

							auditPolicies.Add(new AuditPolicyInfo(
								subcategoryGuid: allSubCategories[batchStart + i].subCategoryGuid,
								subcategoryName: subcategoryName,
								categoryGuid: allSubCategories[batchStart + i].categoryGuid,
								categoryName: categoryName,
								auditingInformation: info.AuditingInformation
							));
						}
					}
					finally
					{
						NativeMethods.AuditFree(auditPolicyPtr);
					}
				}
				finally
				{
					Marshal.FreeHGlobal(batchGuidsPtr);
				}
			}
		}
		finally
		{
			NativeMethods.AuditFree(categoriesPtr);
		}

		Logger.Write(string.Format(GlobalVars.GetStr("RetrievedAuditPoliciesForSubcategoriesMessage"), auditPolicies.Count));
		return auditPolicies;
	}

	/// <summary>
	/// Gets the current audit policy settings for specific subcategory GUIDs
	/// </summary>
	/// <param name="subcategoryGuids">Array of subcategory GUIDs to query</param>
	/// <returns>Dictionary where key is GUID and value is the audit setting</returns>
	internal unsafe static Dictionary<Guid, uint> GetSpecificAuditPolicies(Guid[] subcategoryGuids)
	{
		// Ensure privileges
		AuditPrivilegeHelper.EnsurePrivileges();

		if (subcategoryGuids.Length == 0)
		{
			return [];
		}

		Dictionary<Guid, uint> results = [];
		int guidSize = sizeof(Guid);
		IntPtr guidsPtr = Marshal.AllocHGlobal(subcategoryGuids.Length * guidSize);

		try
		{
			for (int i = 0; i < subcategoryGuids.Length; i++)
			{
				*(Guid*)IntPtr.Add(guidsPtr, i * guidSize) = subcategoryGuids[i];
			}

			if (!NativeMethods.AuditQuerySystemPolicy(guidsPtr, (uint)subcategoryGuids.Length, out IntPtr auditPolicyPtr))
			{
				int error = Marshal.GetLastPInvokeError();
				throw new InvalidOperationException(string.Format(GlobalVars.GetStr("FailedToQuerySpecificAuditPoliciesError"), error));
			}

			if (auditPolicyPtr == IntPtr.Zero)
			{
				throw new InvalidOperationException(GlobalVars.GetStr("AuditQuerySystemPolicyReturnedNullSpecificError"));
			}

			try
			{
				for (int i = 0; i < subcategoryGuids.Length; i++)
				{
					AUDIT_POLICY_INFORMATION info = *(AUDIT_POLICY_INFORMATION*)IntPtr.Add(auditPolicyPtr, i * sizeof(AUDIT_POLICY_INFORMATION));

					results[subcategoryGuids[i]] = info.AuditingInformation;
				}
			}
			finally
			{
				NativeMethods.AuditFree(auditPolicyPtr);
			}
		}
		finally
		{
			Marshal.FreeHGlobal(guidsPtr);
		}

		Logger.Write(string.Format(GlobalVars.GetStr("RetrievedAuditPoliciesForSpecificSubcategoriesMessage"), results.Count));
		return results;
	}

	/// <summary>
	/// Parses a CSV file containing audit policy settings.
	/// This CSV file type is found in the Microsoft Security Baselines.
	/// </summary>
	/// <param name="csvFilePath">Path to the CSV file</param>
	/// <returns>List of CSV audit policy entries</returns>
	/// <exception cref="FileNotFoundException">Thrown when CSV file doesn't exist</exception>
	/// <exception cref="InvalidDataException">Thrown when CSV format is invalid</exception>
	private static List<CsvAuditPolicyEntry> ParseAuditPolicyCsv(string csvFilePath)
	{
		if (!File.Exists(csvFilePath))
			throw new FileNotFoundException(string.Format(GlobalVars.GetStr("CsvFileNotFoundError"), csvFilePath));

		List<CsvAuditPolicyEntry> entries = [];
		string[] lines = File.ReadAllLines(csvFilePath, Encoding.UTF8);

		if (lines.Length < 2)
			throw new InvalidDataException(GlobalVars.GetStr("CsvFileMustContainHeaderAndDataError"));

		// Skip header row (index 0)
		for (int i = 1; i < lines.Length; i++)
		{
			string line = lines[i].Trim();
			if (string.IsNullOrEmpty(line))
				continue;

			try
			{
				CsvAuditPolicyEntry? entry = ParseCsvLine(line, i + 1);
				if (entry != null)
				{
					entries.Add(entry);
				}
			}
			catch (Exception ex)
			{
				throw new InvalidDataException(string.Format(GlobalVars.GetStr("ErrorParsingCsvLineError"), i + 1, ex.Message), ex);
			}
		}

		if (entries.Count == 0)
		{
			throw new InvalidDataException(GlobalVars.GetStr("NoValidAuditPolicyEntriesFoundError"));
		}

		Logger.Write(string.Format(GlobalVars.GetStr("ParsedAuditPolicyEntriesFromCsvMessage"), entries.Count));
		return entries;
	}

	/// <summary>
	/// Applies audit policies from a CSV file to the system.
	/// The CSV file is in Microsoft Security Baselines.
	/// </summary>
	/// <param name="csvFilePath">Path to the CSV file containing audit policies</param>
	internal static void ApplyAuditPoliciesFromCsv(string csvFilePath)
	{
		// Ensure privileges
		AuditPrivilegeHelper.EnsurePrivileges();

		List<CsvAuditPolicyEntry> csvEntries = ParseAuditPolicyCsv(csvFilePath);

		// Apply the audit policies
		SetAuditPolicies(ConvertCSVEntriesToAuditPolicyInfo(csvEntries));

		Logger.Write(string.Format(GlobalVars.GetStr("SuccessfullyAppliedAuditPoliciesFromCsvMessage"), csvEntries.Count));
	}

	internal static AUDIT_POLICY_INFORMATION[] ConvertCSVEntriesToAuditPolicyInfo(List<CsvAuditPolicyEntry> entries)
	{
		// Ensure privileges
		AuditPrivilegeHelper.EnsurePrivileges();

		// Convert CSV entries to audit policy structures
		AUDIT_POLICY_INFORMATION[] auditPolicies = new AUDIT_POLICY_INFORMATION[entries.Count];

		for (int i = 0; i < entries.Count; i++)
		{
			auditPolicies[i] = new AUDIT_POLICY_INFORMATION
			{
				AuditSubCategoryGuid = entries[i].SubcategoryGuid,
				AuditingInformation = entries[i].SettingValue,
				AuditCategoryGuid = GetCategoryGuidForSubcategory(entries[i].SubcategoryGuid)
			};
		}

		return auditPolicies;
	}

	/// <summary>
	/// Sets multiple audit policies on the system
	/// </summary>
	/// <param name="auditPolicies">Array of audit policy information structures</param>
	/// <returns></returns>
	internal static void SetAuditPolicies(AUDIT_POLICY_INFORMATION[] auditPolicies)
	{
		// Ensure privileges
		AuditPrivilegeHelper.EnsurePrivileges();

		if (auditPolicies.Length == 0)
		{
			return;
		}

		// Without the following logics, we would only add and never remove audit flags.
		// E.g., we couldn't move from "Success and Failure" to "Success" or "Failure".
		// E.g., If a policy was "Success" and we set it to "Failure" (or vise versa) it would just change to "Success and Failure".

		for (int i = 0; i < auditPolicies.Length; i++)
		{
			if (auditPolicies[i].AuditingInformation == (uint)AuditBitFlags.POLICY_AUDIT_EVENT_UNCHANGED)
			{
				auditPolicies[i].AuditingInformation = (uint)AuditBitFlags.POLICY_AUDIT_EVENT_NONE;
			}
		}

		// Clone and set all to POLICY_AUDIT_EVENT_NONE sentinel (0x4)
		AUDIT_POLICY_INFORMATION[] clearPhase = (AUDIT_POLICY_INFORMATION[])auditPolicies.Clone();
		for (int i = 0; i < clearPhase.Length; i++)
		{
			clearPhase[i].AuditingInformation = (uint)AuditBitFlags.POLICY_AUDIT_EVENT_NONE;
		}

		// Apply clear phase with sentinel values
		ApplyPoliciesRaw(clearPhase);

		// Apply desired final settings
		ApplyPoliciesRaw(auditPolicies);
	}

	/// <summary>
	/// Passes the AUDIT_POLICY_INFORMATION array as-is
	/// (including sentinel 0x4 values) by marshalling to unmanaged memory.
	/// </summary>
	private unsafe static void ApplyPoliciesRaw(AUDIT_POLICY_INFORMATION[] policies)
	{
		int count = policies.Length;
		if (count == 0)
		{
			return;
		}

		int structSize = sizeof(AUDIT_POLICY_INFORMATION);
		IntPtr buffer = Marshal.AllocHGlobal(structSize * count);

		try
		{
			for (int i = 0; i < count; i++)
			{
				*(AUDIT_POLICY_INFORMATION*)IntPtr.Add(buffer, i * structSize) = policies[i];
			}

			bool ok = NativeMethods.AuditSetSystemPolicy(buffer, (uint)count);
			if (!ok)
			{
				int error = Marshal.GetLastPInvokeError();
				throw new InvalidOperationException(string.Format(GlobalVars.GetStr("FailedToApplyAuditPolicyToSystemError"), error));
			}
		}
		finally
		{
			Marshal.FreeHGlobal(buffer);
		}
	}

	/// <summary>
	/// Parses a single CSV line into an audit policy entry.
	/// </summary>
	/// <param name="line">CSV line to parse</param>
	/// <param name="lineNumber">Line number for error reporting</param>
	/// <returns>CsvAuditPolicyEntry or null if parsing fails</returns>
	internal static CsvAuditPolicyEntry? ParseCsvLine(string line, int lineNumber)
	{
		// Split CSV line, handling quoted values
		string[] parts = SplitCsvLine(line);

		if (parts.Length < 7)
		{
			throw new InvalidDataException(string.Format(GlobalVars.GetStr("CsvLineExpectedColumnsError"), lineNumber, parts.Length));
		}

		// Extract relevant columns:
		// 0: Machine Name, 1: Policy Target, 2: Subcategory, 3: Subcategory GUID,
		// 4: Inclusion Setting, 5: Exclusion Setting, 6: Setting Value

		string subcategoryName = parts[2].Trim();
		string guidString = parts[3].Trim();
		string inclusionSetting = parts[4].Trim();
		string settingValueString = parts[6].Trim();

		// Parse GUID - remove curly braces if present
		guidString = guidString.Trim('{', '}');
		if (!Guid.TryParse(guidString, CultureInfo.InvariantCulture, out Guid subcategoryGuid))
		{
			throw new InvalidDataException(string.Format(GlobalVars.GetStr("CsvLineInvalidGuidFormatError"), lineNumber, guidString));
		}

		// Parse setting value
		if (!uint.TryParse(settingValueString, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint settingValue))
		{
			throw new InvalidDataException(string.Format(GlobalVars.GetStr("CsvLineInvalidSettingValueError"), lineNumber, settingValueString));
		}

		// Validate setting value range (0-3)
		if (settingValue > 3)
		{
			throw new InvalidDataException(string.Format(GlobalVars.GetStr("CsvLineSettingValueOutOfRangeError"), lineNumber, settingValue));
		}

		return new CsvAuditPolicyEntry(
			subcategoryGuid: subcategoryGuid,
			subcategoryName: subcategoryName,
			inclusionSetting: inclusionSetting,
			settingValue: settingValue
		);
	}

	/// <summary>
	/// Splits a CSV line into parts, handling quoted values.
	/// </summary>
	/// <param name="line">CSV line to split</param>
	/// <returns>Array of CSV parts</returns>
	private static string[] SplitCsvLine(string line)
	{
		List<string> parts = [];
		StringBuilder currentPart = new();
		bool inQuotes = false;

		for (int i = 0; i < line.Length; i++)
		{
			char c = line[i];

			if (c == '"')
			{
				inQuotes = !inQuotes;
			}
			else if (c == ',' && !inQuotes)
			{
				parts.Add(currentPart.ToString());
				_ = currentPart.Clear();
			}
			else
			{
				_ = currentPart.Append(c);
			}
		}

		// Add the last part
		parts.Add(currentPart.ToString());

		return [.. parts];
	}

	/// <summary>
	/// Gets the friendly name of an audit subcategory.
	/// </summary>
	/// <param name="subcategoryGuid">The subcategory GUID</param>
	/// <returns>Friendly name or GUID string if lookup fails</returns>
	private unsafe static string GetSubcategoryName(Guid subcategoryGuid)
	{
		// Allocating space for one GUID on the stack to avoid heap allocation and runtime marshalling APIs.
		Guid* pGuid = stackalloc Guid[1];
		*pGuid = subcategoryGuid;

		try
		{
			// Calling native API with pointer to our GUID.
			if (NativeMethods.AuditLookupSubCategoryNameW((IntPtr)pGuid, out IntPtr namePtr) && namePtr != IntPtr.Zero)
			{
				try
				{
					string? name = Marshal.PtrToStringUni(namePtr);
					return name ?? subcategoryGuid.ToString("B");
				}
				finally
				{
					// Free the string allocated by the API
					// Marshal.FreeHGlobal(namePtr);
					// Must be freed via AuditFree per documentation, not FreeHGlobal: https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditlookupsubcategorynamew#parameters
					NativeMethods.AuditFree(namePtr);
				}
			}
		}
		catch
		{
			// Fall through to return GUID string
		}

		// Fallback, return the GUID in braces format.
		return subcategoryGuid.ToString("B");
	}

	/// <summary>
	/// Gets the friendly name of an audit category
	/// </summary>
	/// <param name="categoryGuid">The category GUID</param>
	/// <returns>Friendly name or GUID string if lookup fails</returns>
	private unsafe static string GetCategoryName(Guid categoryGuid)
	{
		Guid* pGuid = stackalloc Guid[1];
		*pGuid = categoryGuid;

		try
		{
			if (NativeMethods.AuditLookupCategoryNameW((IntPtr)pGuid, out IntPtr namePtr) && namePtr != IntPtr.Zero)
			{
				try
				{
					string? name = Marshal.PtrToStringUni(namePtr);
					return name ?? categoryGuid.ToString("B");
				}
				finally
				{
					// Free the string allocated by the API
					// Marshal.FreeHGlobal(namePtr);
					// Must be freed via AuditFree per documentation, not FreeHGlobal: https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditlookupsubcategorynamew#parameters
					NativeMethods.AuditFree(namePtr);
				}
			}
		}
		catch
		{
			// Fall through to return GUID string
		}

		return categoryGuid.ToString("B");
	}
}
