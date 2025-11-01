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
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;

namespace HardenSystemSecurity.GroupPolicy;

internal static class RegistryPolicyParser
{
	internal static readonly string LocalPolicyMachineFilePath = Path.Combine(GlobalVars.SystemDrive, "Windows", "System32", "GroupPolicy", "Machine", "Registry.pol");
	internal static readonly string LocalPolicyUserFilePath = Path.Combine(GlobalVars.SystemDrive, "Windows", "System32", "GroupPolicy", "User", "Registry.pol");

	/// <summary>
	/// Lock to synchronize access to the policy file operations.
	/// </summary>
	private static readonly Lock _policyFileLock = new();

	/// <summary>
	/// Executes a file operation with retry logic and exponential backoff for handling sharing violations.
	/// </summary>
	/// <typeparam name="T">Return type of the operation</typeparam>
	/// <param name="operation">The file operation to execute</param>
	/// <param name="maxRetries">Maximum number of retry attempts</param>
	/// <param name="baseDelayMs">Base delay in milliseconds for exponential backoff</param>
	/// <returns>Result of the operation</returns>
	private static T ExecuteWithRetry<T>(Func<T> operation, int maxRetries = 5, int baseDelayMs = 100)
	{
		int attempt = 0;
		while (true)
		{
			try
			{
				return operation();
			}
			catch (IOException ex) when (IsFileSharingViolation(ex) && attempt < maxRetries)
			{
				attempt++;
				int delay = baseDelayMs * (int)Math.Pow(2, attempt - 1);

				// Some jitter to prevent thundering herd
				using RandomNumberGenerator rng = RandomNumberGenerator.Create();
				byte[] randomBytes = new byte[4];
				rng.GetBytes(randomBytes);
				int jitter = Math.Abs(BitConverter.ToInt32(randomBytes, 0)) % (delay / 4);
				int totalDelay = delay + jitter;

				Logger.Write($"File sharing violation on attempt {attempt}/{maxRetries + 1}. Retrying in {totalDelay}ms. Error: {ex.Message}");

				Thread.Sleep(totalDelay);
			}
			catch (UnauthorizedAccessException ex) when (attempt < maxRetries)
			{
				attempt++;
				int delay = baseDelayMs * (int)Math.Pow(2, attempt - 1);

				Logger.Write($"Access denied on attempt {attempt}/{maxRetries + 1}. Retrying in {delay}ms. Error: {ex.Message}");

				Thread.Sleep(delay);
			}
		}
	}

	/// <summary>
	/// Determines if an IOException is a file sharing violation.
	/// </summary>
	/// <param name="ex">The IOException to check</param>
	/// <returns>True if it's a sharing violation</returns>
	private static bool IsFileSharingViolation(IOException ex)
	{
		return ex.HResult == unchecked((int)0x80070020) || // ERROR_SHARING_VIOLATION
			   ex.HResult == unchecked((int)0x80070021) || // ERROR_LOCK_VIOLATION
			   ex.Message.Contains("being used by another process", StringComparison.OrdinalIgnoreCase) ||
			   ex.Message.Contains("sharing violation", StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Parses a .POL file from the specified file path.
	/// </summary>
	/// <param name="filePath"></param>
	/// <returns></returns>
	/// <exception cref="FileNotFoundException"></exception>
	internal static RegistryPolicyFile ParseFile(string filePath)
	{
		if (!File.Exists(filePath))
			throw new FileNotFoundException(string.Format(GlobalVars.GetStr("FileNotFoundPath"), filePath));

		return ExecuteWithRetry(() =>
		{
			using FileStream fileStream = new(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
			return ParseStream(fileStream);
		});
	}

	internal static RegistryPolicyFile ParseStream(Stream stream)
	{
		using BinaryReader reader = new(stream);

		// Read header
		if (stream.Length < 8)
			throw new InvalidDataException(GlobalVars.GetStr("FileTooSmallForValidHeader"));

		uint signature = reader.ReadUInt32();
		uint version = reader.ReadUInt32();

		if (signature != RegistryPolicyFile.REGISTRY_FILE_SIGNATURE)
			throw new InvalidDataException(string.Format(GlobalVars.GetStr("InvalidSignatureExpected"), signature, RegistryPolicyFile.REGISTRY_FILE_SIGNATURE));

		List<RegistryPolicyEntry> entries = [];

		// Read entries
		while (stream.Position < stream.Length)
		{
			try
			{
				RegistryPolicyEntry? entry = ReadEntry(reader);
				if (entry != null)
					entries.Add(entry);
			}
			catch (EndOfStreamException)
			{
				// End of file reached
				break;
			}
			catch (Exception ex)
			{
				throw new InvalidDataException(string.Format(GlobalVars.GetStr("ErrorReadingEntryAtPosition"), stream.Position, ex.Message), ex);
			}
		}

		return new RegistryPolicyFile(signature: signature, version: version, entries: entries);
	}

	private static RegistryPolicyEntry? ReadEntry(BinaryReader reader)
	{
		// Check if we have enough data for the minimum entry structure
		if (reader.BaseStream.Position + 4 >= reader.BaseStream.Length)
			return null;

		// Read opening bracket '[' (should be '[' in Unicode)
		ushort openingBracket = reader.ReadUInt16();
		if (openingBracket != 0x005B) // '[' in Unicode
			throw new InvalidDataException(string.Format(GlobalVars.GetStr("ExpectedOpeningBracketAtStartOfEntry"), openingBracket));

		// Read key name (null-terminated Unicode string)
		string keyName = ReadUnicodeString(reader);

		// Read semicolon delimiter (should be ';' in Unicode)
		ushort delimiter1 = reader.ReadUInt16();
		if (delimiter1 != 0x003B) // ';' in Unicode
			throw new InvalidDataException(string.Format(GlobalVars.GetStr("ExpectedSemicolonDelimiterAfterKeyName"), delimiter1));

		// Read value name (null-terminated Unicode string)
		string valueName = ReadUnicodeString(reader);

		// Read semicolon delimiter
		ushort delimiter2 = reader.ReadUInt16();
		if (delimiter2 != 0x003B) // ';' in Unicode
			throw new InvalidDataException(string.Format(GlobalVars.GetStr("ExpectedSemicolonDelimiterAfterValueName"), delimiter2));

		// Read type (4 bytes)
		RegistryValueType type = (RegistryValueType)reader.ReadUInt32();

		// Read semicolon delimiter
		ushort delimiter3 = reader.ReadUInt16();
		if (delimiter3 != 0x003B) // ';' in Unicode
			throw new InvalidDataException(string.Format(GlobalVars.GetStr("ExpectedSemicolonDelimiterAfterType"), delimiter3));

		// Read size (4 bytes)
		uint size = reader.ReadUInt32();

		// Read semicolon delimiter
		ushort delimiter4 = reader.ReadUInt16();
		if (delimiter4 != 0x003B) // ';' in Unicode
			throw new InvalidDataException(string.Format(GlobalVars.GetStr("ExpectedSemicolonDelimiterAfterSize"), delimiter4));

		// Read data
		byte[] data;
		if (size > 0)
		{
			data = reader.ReadBytes((int)size);
			if (data.Length != size)
				throw new InvalidDataException(string.Format(GlobalVars.GetStr("CouldNotReadBytesOfData"), size, data.Length));
		}
		else
		{
			data = [];
		}

		// Read closing bracket ']' (should be ']' in Unicode)
		ushort closingBracket = reader.ReadUInt16();
		if (closingBracket != 0x005D) // ']' in Unicode
			throw new InvalidDataException(string.Format(GlobalVars.GetStr("ExpectedClosingBracketAfterData"), closingBracket));

		return new RegistryPolicyEntry(source: Source.GroupPolicy, keyName: keyName, valueName: valueName, type: type, size: size, data: data, hive: Hive.HKLM);
	}

	private static string ReadUnicodeString(BinaryReader reader)
	{
		List<char> chars = [];

		while (true)
		{
			if (reader.BaseStream.Position + 2 > reader.BaseStream.Length)
				throw new EndOfStreamException(GlobalVars.GetStr("UnexpectedEndOfStreamReadingUnicodeString"));

			ushort ch = reader.ReadUInt16();
			if (ch == 0) // Null terminator
				break;

			chars.Add((char)ch);
		}

		return new string(chars.ToArray());
	}

	/// <summary>
	/// Creates a .POL file.
	/// </summary>
	/// <param name="filePath"></param>
	/// <param name="policyFile"></param>
	internal static void WriteFile(string filePath, RegistryPolicyFile policyFile)
	{
		_ = ExecuteWithRetry(() =>
	   {
		   using FileStream fileStream = new(filePath, FileMode.Create, FileAccess.Write, FileShare.Read);
		   WriteStream(fileStream, policyFile);
		   return true;
	   });
	}

	private static void WriteStream(Stream stream, RegistryPolicyFile policyFile)
	{
		using BinaryWriter writer = new(stream);

		// Write header
		writer.Write(RegistryPolicyFile.REGISTRY_FILE_SIGNATURE);
		writer.Write(RegistryPolicyFile.REGISTRY_FILE_VERSION);

		// Write entries
		foreach (RegistryPolicyEntry entry in policyFile.Entries)
		{
			WriteEntry(writer, entry);
		}
	}

	private static void WriteEntry(BinaryWriter writer, RegistryPolicyEntry entry)
	{
		// Write opening bracket '['
		writer.Write((ushort)0x005B); // '['

		// Write key name
		WriteUnicodeString(writer, entry.KeyName);

		// Write semicolon delimiter
		writer.Write((ushort)0x003B); // ';'

		// Write value name
		WriteUnicodeString(writer, entry.ValueName);

		// Write semicolon delimiter
		writer.Write((ushort)0x003B); // ';'

		// Write type
		writer.Write((uint)entry.Type);

		// Write semicolon delimiter
		writer.Write((ushort)0x003B); // ';'

		// Write size
		writer.Write(entry.Size);

		// Write semicolon delimiter
		writer.Write((ushort)0x003B); // ';'

		// Write data
		if (!entry.Data.IsEmpty)
		{
			writer.Write(entry.Data.Span);
		}

		// Write closing bracket
		writer.Write((ushort)0x005D); // ']'
	}

	private static void WriteUnicodeString(BinaryWriter writer, string value)
	{
		if (string.IsNullOrEmpty(value))
		{
			writer.Write((ushort)0); // Just null terminator
			return;
		}

		foreach (char c in value)
		{
			writer.Write((ushort)c);
		}
		writer.Write((ushort)0); // Null terminator
	}

	/// <summary>
	/// Determines if two registry policy entries are equivalent based on type, size, and data
	/// </summary>
	/// <param name="entry1">First entry</param>
	/// <param name="entry2">Second entry</param>
	/// <returns>True if entries have the same type, size, and data</returns>
	private static bool EntriesAreEquivalent(RegistryPolicyEntry entry1, RegistryPolicyEntry entry2)
	{
		return entry1.Type == entry2.Type &&
			   entry1.Size == entry2.Size &&
			   entry1.Data.Span.SequenceEqual(entry2.Data.Span);
	}

	/// <summary>
	/// Merges multiple policy files together with detailed reporting. The main policy file serves as the base,
	/// and entries from the other policy files are added to it. If an entry with the same
	/// KeyName and ValueName exists in both the main file and any other file, the entry
	/// from the other file takes priority and overwrites the main file's entry.
	/// </summary>
	/// <param name="mainPolicyFile">The main policy file that serves as the base</param>
	/// <param name="otherPolicyFiles">One or more policy files to merge into the main file</param>
	/// <returns>A MergeResult containing the merged file and detailed operation information</returns>
	/// <exception cref="ArgumentNullException">Thrown when mainPolicyFile is null</exception>
	/// <exception cref="ArgumentException">Thrown when otherPolicyFiles is null or empty</exception>
	internal static MergeResult MergePolicyFilesWithReport(RegistryPolicyFile mainPolicyFile, params RegistryPolicyFile[] otherPolicyFiles)
	{
		if (otherPolicyFiles.Length == 0)
			throw new ArgumentException(GlobalVars.GetStr("AtLeastOneOtherPolicyFileMustBeProvided"), nameof(otherPolicyFiles));

		CSEMgr.RegisterCSEGuids();

		// Dictionary to store entries with KeyName+ValueName as the key for uniqueness
		Dictionary<string, RegistryPolicyEntry> mergedEntries = new(StringComparer.OrdinalIgnoreCase);
		List<MergeOperation> operations = [];

		// First add all entries from the main policy file (no operations recorded for these)
		foreach (RegistryPolicyEntry entry in mainPolicyFile.Entries)
		{
			string key = $"{entry.KeyName}|{entry.ValueName}";
			mergedEntries[key] = entry;
		}

		// Then process entries from other policy files
		foreach (RegistryPolicyFile otherPolicyFile in otherPolicyFiles)
		{

			foreach (RegistryPolicyEntry entry in otherPolicyFile.Entries)
			{
				string key = $"{entry.KeyName}|{entry.ValueName}";

				if (mergedEntries.TryGetValue(key, out RegistryPolicyEntry? existingEntry))
				{
					// Entry exists in main file, check if it's actually different
					if (!EntriesAreEquivalent(existingEntry, entry))
					{
						// Only record as replacement if the entries are actually different
						operations.Add(new MergeOperation(operationType: OperationType.Replaced, keyName: entry.KeyName, valueName: entry.ValueName, oldEntry: existingEntry, newEntry: entry));
						mergedEntries[key] = entry; // Replace with new entry
					}
					// If entries are equivalent, do nothing (no operation recorded)
				}
				else
				{
					// New entry that doesn't exist in main file
					operations.Add(new MergeOperation(operationType: OperationType.Added, keyName: entry.KeyName, valueName: entry.ValueName, oldEntry: null, newEntry: entry));
					mergedEntries[key] = entry;
				}
			}
		}

		// Create a new policy file with the merged entries
		List<RegistryPolicyEntry> finalEntries = mergedEntries.Values.ToList();

		RegistryPolicyFile mergedFile = new(
			signature: RegistryPolicyFile.REGISTRY_FILE_SIGNATURE,
			version: RegistryPolicyFile.REGISTRY_FILE_VERSION,
			entries: finalEntries
		);

		return new MergeResult(mergedFile: mergedFile, operations: operations);
	}

	/// <summary>
	/// Merges multiple policy files from file paths together with detailed reporting. The main policy file serves as the base,
	/// and entries from the other policy files are added to it. If an entry with the same
	/// KeyName and ValueName exists in both the main file and any other file, the entry
	/// from the other file takes priority and overwrites the main file's entry.
	/// </summary>
	/// <param name="mainPolicyFilePath">The path to the main policy file that serves as the base</param>
	/// <param name="otherPolicyFilePaths">One or more paths to policy files to merge into the main file</param>
	/// <returns>A MergeResult containing the merged file and detailed operation information</returns>
	/// <exception cref="ArgumentException">Thrown when mainPolicyFilePath is null or empty, or otherPolicyFilePaths is null or empty</exception>
	/// <exception cref="FileNotFoundException">Thrown when any of the specified files cannot be found</exception>
	internal static MergeResult MergePolicyFilesWithReport(string mainPolicyFilePath, params string[] otherPolicyFilePaths)
	{
		if (string.IsNullOrWhiteSpace(mainPolicyFilePath))
			throw new ArgumentException(GlobalVars.GetStr("MainPolicyFilePathCannotBeNullOrEmpty"), nameof(mainPolicyFilePath));

		if (otherPolicyFilePaths.Length == 0)
			throw new ArgumentException(GlobalVars.GetStr("AtLeastOneOtherPolicyFilePathMustBeProvided"), nameof(otherPolicyFilePaths));

		// Parse the main policy file
		RegistryPolicyFile mainPolicyFile = ParseFile(mainPolicyFilePath);

		// Parse all other policy files
		RegistryPolicyFile[] otherPolicyFiles = new RegistryPolicyFile[otherPolicyFilePaths.Length];
		for (int i = 0; i < otherPolicyFilePaths.Length; i++)
		{
			if (string.IsNullOrWhiteSpace(otherPolicyFilePaths[i]))
				throw new ArgumentException(string.Format(GlobalVars.GetStr("PolicyFilePathAtIndexCannotBeNullOrEmpty"), i), nameof(otherPolicyFilePaths));

			otherPolicyFiles[i] = ParseFile(otherPolicyFilePaths[i]);
		}

		// Merge the policy files
		return MergePolicyFilesWithReport(mainPolicyFile, otherPolicyFiles);
	}

	/// <summary>
	/// Adds the policies it receives to the system and logs the merge operation results.
	/// </summary>
	/// <param name="policies">Policies to add to the system.</param>
	internal static void AddPoliciesToSystem(List<RegistryPolicyEntry> policies, GroupPolicyContext context)
	{
		lock (_policyFileLock)
		{
			try
			{
				string PolicyContextFilePath = context is GroupPolicyContext.Machine ? LocalPolicyMachineFilePath : LocalPolicyUserFilePath;

				CSEMgr.RegisterCSEGuids();

				// Read the current system policies
				RegistryPolicyFile policyFile = ParseFile(PolicyContextFilePath);
				Logger.Write(string.Format(GlobalVars.GetStr("LoadedExistingPolicyFileWithEntries"), policyFile.Entries.Count));

				// Dictionary to store entries with KeyName+ValueName as the key for uniqueness
				Dictionary<string, RegistryPolicyEntry> mergedEntries = new(StringComparer.OrdinalIgnoreCase);
				List<MergeOperation> operations = [];

				// First add all entries from the main policy file (no operations recorded for these)
				foreach (RegistryPolicyEntry entry in policyFile.Entries)
				{
					string key = $"{entry.KeyName}|{entry.ValueName}";
					mergedEntries[key] = entry;
				}

				// Then process entries from other policies
				foreach (RegistryPolicyEntry entry in policies)
				{
					string key = $"{entry.KeyName}|{entry.ValueName}";

					if (mergedEntries.TryGetValue(key, out RegistryPolicyEntry? existingEntry))
					{
						// Entry exists in main file, check if it's actually different
						if (!EntriesAreEquivalent(existingEntry, entry))
						{
							// Only record as replacement if the entries are actually different
							operations.Add(new MergeOperation(operationType: OperationType.Replaced, keyName: entry.KeyName, valueName: entry.ValueName, oldEntry: existingEntry, newEntry: entry));
							mergedEntries[key] = entry; // Replace with new entry
						}
						// If entries are equivalent, do nothing (no operation recorded)
					}
					else
					{
						// New entry that doesn't exist in main file
						operations.Add(new MergeOperation(operationType: OperationType.Added, keyName: entry.KeyName, valueName: entry.ValueName, oldEntry: null, newEntry: entry));
						mergedEntries[key] = entry;
					}
				}

				// Create a new policy file with the merged entries
				List<RegistryPolicyEntry> finalEntries = mergedEntries.Values.ToList();

				RegistryPolicyFile mergedFile = new(
					signature: RegistryPolicyFile.REGISTRY_FILE_SIGNATURE,
					version: RegistryPolicyFile.REGISTRY_FILE_VERSION,
					entries: finalEntries
				);

				// Replace the system policy with the new one.
				WriteFile(PolicyContextFilePath, mergedFile);

				// Print merge operations
				foreach (MergeOperation operation in operations)
				{
					Logger.Write(operation.ToString());
				}

				Logger.Write(string.Format(GlobalVars.GetStr("TotalOperationsLog"), operations.Count));
				Logger.Write(string.Format(GlobalVars.GetStr("AddedEntriesLog"), operations.Count(op => op.OperationType == OperationType.Added)));
				Logger.Write(string.Format(GlobalVars.GetStr("ReplacedEntries"), operations.Count(op => op.OperationType == OperationType.Replaced)));

				RefreshPolicies.Refresh();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				throw;
			}
		}
	}

	/// <summary>
	/// Verifies if the specified policies exist in the system and match the expected values.
	/// Returns false for all policies if the policy file doesn't exist.
	/// </summary>
	/// <param name="policies">Policies to verify in the system.</param>
	/// <returns>
	/// A dictionary with policy entries as keys and their verification status (true if applied, false if not applied or different) as values,
	/// and also returns the matched system entry (if found) so callers can display the actual current value without reparsing the file.
	/// </returns>
	internal static Dictionary<RegistryPolicyEntry, (bool IsCompliant, RegistryPolicyEntry? SystemEntry)> VerifyPoliciesInSystem(List<RegistryPolicyEntry> policies, GroupPolicyContext context)
	{
		Dictionary<RegistryPolicyEntry, (bool IsCompliant, RegistryPolicyEntry? SystemEntry)> verificationResults = [];

		try
		{
			string PolicyContextFilePath = context is GroupPolicyContext.Machine ? LocalPolicyMachineFilePath : LocalPolicyUserFilePath;

			// Check if the policy file exists
			if (!File.Exists(PolicyContextFilePath))
			{
				Logger.Write(GlobalVars.GetStr("PolicyFileDoesNotExistMarkingAllPoliciesAsNotVerified"));

				// Mark all policies as unverified since the file doesn't exist
				foreach (RegistryPolicyEntry policy in policies)
				{
					verificationResults[policy] = (false, null);
				}

				Logger.Write(string.Format(GlobalVars.GetStr("VerificationCompletePolicyFileDoesNotExist"), policies.Count));
				return verificationResults;
			}

			// Read the current system policies
			RegistryPolicyFile policyFile = ParseFile(PolicyContextFilePath);

			// Lookup dictionary for faster searches
			Dictionary<string, RegistryPolicyEntry> systemPolicies = new(StringComparer.OrdinalIgnoreCase);
			foreach (RegistryPolicyEntry entry in policyFile.Entries)
			{
				string key = $"{entry.KeyName}|{entry.ValueName}";
				systemPolicies[key] = entry;
			}

			// Verify each policy
			foreach (RegistryPolicyEntry policy in policies)
			{
				string key = $"{policy.KeyName}|{policy.ValueName}";

				if (systemPolicies.TryGetValue(key, out RegistryPolicyEntry? systemPolicy))
				{
					// Policy exists, check if values match
					bool isEquivalent = EntriesAreEquivalent(policy, systemPolicy);
					verificationResults[policy] = (isEquivalent, systemPolicy);

					Logger.Write(isEquivalent ?
						string.Format(GlobalVars.GetStr("VerifyPolicyMatch"), policy.KeyName, policy.ValueName) :
						string.Format(GlobalVars.GetStr("VerifyPolicyMismatch"), policy.KeyName, policy.ValueName));
				}
				else
				{
					// Policy doesn't exist in system
					verificationResults[policy] = (false, null);
					Logger.Write(string.Format(GlobalVars.GetStr("VerifyPolicyNotFound"), policy.KeyName, policy.ValueName));
				}
			}

			Logger.Write(string.Format(GlobalVars.GetStr("VerificationCompletePoliciesMatch"), verificationResults.Count(kvp => kvp.Value.IsCompliant), policies.Count));
		}
		catch (Exception ex)
		{
			Logger.Write(ex);

			// Mark all policies as unverified on error
			foreach (RegistryPolicyEntry policy in policies)
			{
				verificationResults[policy] = (false, null);
			}
		}

		return verificationResults;
	}

	/// <summary>
	/// Removes the specified policies from the system.
	/// Gracefully handles the case where the policy file doesn't exist.
	/// </summary>
	/// <param name="policies">Policies to remove from the system.</param>
	internal static void RemovePoliciesFromSystem(List<RegistryPolicyEntry> policies, GroupPolicyContext context)
	{
		lock (_policyFileLock)
		{
			try
			{
				string PolicyContextFilePath = context is GroupPolicyContext.Machine ? LocalPolicyMachineFilePath : LocalPolicyUserFilePath;

				if (!File.Exists(PolicyContextFilePath))
				{
					Logger.Write(GlobalVars.GetStr("PolicyFileDoesNotExistNothingToRemove"));
					return;
				}

				RemovePoliciesFromPOLFile(PolicyContextFilePath, policies);
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				throw;
			}
		}
	}

	/// <summary>
	/// Removes policies from a specific POL file and saves the updated file back to disk.
	/// </summary>
	/// <param name="polFilePath">Path to the POL file to modify</param>
	/// <param name="policies">List of policies to remove from the file</param>
	internal static void RemovePoliciesFromPOLFile(string polFilePath, List<RegistryPolicyEntry> policies)
	{
		// Read the current system policies
		RegistryPolicyFile policyFile = ParseFile(polFilePath);

		// Set of keys to remove
		HashSet<string> policiesToRemove = new(StringComparer.OrdinalIgnoreCase);
		foreach (RegistryPolicyEntry policy in policies)
		{
			string key = $"{policy.KeyName}|{policy.ValueName}";
			_ = policiesToRemove.Add(key);
		}

		// Filter out the policies to be removed
		List<RegistryPolicyEntry> remainingEntries = [];
		List<string> removedEntries = [];

		foreach (RegistryPolicyEntry entry in policyFile.Entries)
		{
			string key = $"{entry.KeyName}|{entry.ValueName}";
			if (policiesToRemove.Contains(key))
			{
				removedEntries.Add($"{entry.KeyName}\\{entry.ValueName}");
			}
			else
			{
				remainingEntries.Add(entry);
			}
		}

		// Create a new policy file without the removed entries
		RegistryPolicyFile updatedFile = new(
			signature: RegistryPolicyFile.REGISTRY_FILE_SIGNATURE,
			version: RegistryPolicyFile.REGISTRY_FILE_VERSION,
			entries: remainingEntries
		);

		// Write the updated policy file
		WriteFile(polFilePath, updatedFile);

		foreach (string removedEntry in removedEntries)
		{
			Logger.Write(string.Format(GlobalVars.GetStr("RemovedPolicyEntry"), removedEntry));
		}

		if (string.Equals(polFilePath, LocalPolicyUserFilePath, StringComparison.OrdinalIgnoreCase) ||
			string.Equals(polFilePath, LocalPolicyMachineFilePath, StringComparison.OrdinalIgnoreCase))
		{
			// Refresh the policies if it's a system policy file
			RefreshPolicies.Refresh();
		}

		Logger.Write(string.Format(GlobalVars.GetStr("PolicyRemovalComplete"), removedEntries.Count));

	}
}
