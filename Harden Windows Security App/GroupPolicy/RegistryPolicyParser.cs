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
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using AppControlManager;
using AppControlManager.Others;

namespace HardenWindowsSecurity.GroupPolicy;


internal static class RegistryPolicyParser
{
	internal const string LocalPolicyFilePath = @"C:\Windows\System32\GroupPolicy\Machine\Registry.pol";

	/// <summary>
	/// Parses a .POL file from the specified file path.
	/// </summary>
	/// <param name="filePath"></param>
	/// <returns></returns>
	/// <exception cref="FileNotFoundException"></exception>
	internal static RegistryPolicyFile ParseFile(string filePath)
	{
		if (!File.Exists(filePath))
			throw new FileNotFoundException($"File not found: {filePath}");

		using FileStream fileStream = File.OpenRead(filePath);
		return ParseStream(fileStream);
	}

	internal static RegistryPolicyFile ParseStream(Stream stream)
	{
		using BinaryReader reader = new(stream);

		// Read header
		if (stream.Length < 8)
			throw new InvalidDataException("File is too small to contain a valid header");

		uint signature = reader.ReadUInt32();
		uint version = reader.ReadUInt32();

		if (signature != RegistryPolicyFile.REGISTRY_FILE_SIGNATURE)
			throw new InvalidDataException($"Invalid signature: 0x{signature:X8}. Expected: 0x{RegistryPolicyFile.REGISTRY_FILE_SIGNATURE:X8}");

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
				throw new InvalidDataException($"Error reading entry at position {stream.Position}: {ex.Message}", ex);
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
			throw new InvalidDataException($"Expected opening bracket at start of entry, got: 0x{openingBracket:X4}");

		// Read key name (null-terminated Unicode string)
		string keyName = ReadUnicodeString(reader);

		// Read semicolon delimiter (should be ';' in Unicode)
		ushort delimiter1 = reader.ReadUInt16();
		if (delimiter1 != 0x003B) // ';' in Unicode
			throw new InvalidDataException($"Expected semicolon delimiter after key name, got: 0x{delimiter1:X4}");

		// Read value name (null-terminated Unicode string)
		string valueName = ReadUnicodeString(reader);

		// Read semicolon delimiter
		ushort delimiter2 = reader.ReadUInt16();
		if (delimiter2 != 0x003B) // ';' in Unicode
			throw new InvalidDataException($"Expected semicolon delimiter after value name, got: 0x{delimiter2:X4}");

		// Read type (4 bytes)
		RegistryValueType type = (RegistryValueType)reader.ReadUInt32();

		// Read semicolon delimiter
		ushort delimiter3 = reader.ReadUInt16();
		if (delimiter3 != 0x003B) // ';' in Unicode
			throw new InvalidDataException($"Expected semicolon delimiter after type, got: 0x{delimiter3:X4}");

		// Read size (4 bytes)
		uint size = reader.ReadUInt32();

		// Read semicolon delimiter
		ushort delimiter4 = reader.ReadUInt16();
		if (delimiter4 != 0x003B) // ';' in Unicode
			throw new InvalidDataException($"Expected semicolon delimiter after size, got: 0x{delimiter4:X4}");

		// Read data
		byte[] data;
		if (size > 0)
		{
			data = reader.ReadBytes((int)size);
			if (data.Length != size)
				throw new InvalidDataException($"Could not read {size} bytes of data, only got {data.Length} bytes");
		}
		else
		{
			data = [];
		}

		// Read closing bracket ']' (should be ']' in Unicode)
		ushort closingBracket = reader.ReadUInt16();
		if (closingBracket != 0x005D) // ']' in Unicode
			throw new InvalidDataException($"Expected closing bracket after data, got: 0x{closingBracket:X4}");

		return new RegistryPolicyEntry(source: Source.GroupPolicy, keyName: keyName, valueName: valueName, type: type, size: size, data: data);
	}

	private static string ReadUnicodeString(BinaryReader reader)
	{
		List<char> chars = [];

		while (true)
		{
			if (reader.BaseStream.Position + 2 > reader.BaseStream.Length)
				throw new EndOfStreamException("Unexpected end of stream while reading Unicode string");

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
		using FileStream fileStream = File.Create(filePath);
		WriteStream(fileStream, policyFile);
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
		if (entry.Data != null && entry.Data.Length > 0)
		{
			writer.Write(entry.Data);
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
	/// Compares two byte arrays for equality
	/// </summary>
	/// <param name="array1">First byte array</param>
	/// <param name="array2">Second byte array</param>
	/// <returns>True if arrays are equal, false otherwise</returns>
	private static bool ByteArraysEqual(byte[] array1, byte[] array2)
	{
		if (array1.Length != array2.Length)
			return false;

		return array1.SequenceEqual(array2);
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
			   ByteArraysEqual(entry1.Data, entry2.Data);
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
			throw new ArgumentException("At least one other policy file must be provided", nameof(otherPolicyFiles));

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
			throw new ArgumentException("Main policy file path cannot be null or empty", nameof(mainPolicyFilePath));

		if (otherPolicyFilePaths.Length == 0)
			throw new ArgumentException("At least one other policy file path must be provided", nameof(otherPolicyFilePaths));

		// Parse the main policy file
		RegistryPolicyFile mainPolicyFile = ParseFile(mainPolicyFilePath);

		// Parse all other policy files
		RegistryPolicyFile[] otherPolicyFiles = new RegistryPolicyFile[otherPolicyFilePaths.Length];
		for (int i = 0; i < otherPolicyFilePaths.Length; i++)
		{
			if (string.IsNullOrWhiteSpace(otherPolicyFilePaths[i]))
				throw new ArgumentException($"Policy file path at index {i} cannot be null or empty", nameof(otherPolicyFilePaths));

			otherPolicyFiles[i] = ParseFile(otherPolicyFilePaths[i]);
		}

		// Merge the policy files
		return MergePolicyFilesWithReport(mainPolicyFile, otherPolicyFiles);
	}

	/// <summary>
	/// Adds the policies it receives to the system and logs the merge operation results.
	/// </summary>
	/// <param name="policies">Policies to add to the system.</param>
	internal static void AddPoliciesToSystem(List<RegistryPolicyEntry> policies)
	{
		// Read the current system policies
		RegistryPolicyFile policyFile = ParseFile(LocalPolicyFilePath);

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
		WriteFile(LocalPolicyFilePath, mergedFile);

		// Print merge operations
		foreach (MergeOperation operation in operations)
		{
			Logger.Write(operation.ToString());
		}

		Logger.Write($"Total operations: {operations.Count}");
		Logger.Write($"Added entries: {operations.Count(op => op.OperationType == OperationType.Added)}");
		Logger.Write($"Replaced entries: {operations.Count(op => op.OperationType == OperationType.Replaced)}");

		bool result = NativeMethods.RefreshPolicyEx(true, NativeMethods.RP_FORCE);

		if (!result)
		{
			int error = Marshal.GetLastWin32Error();
			Logger.Write($"RefreshPolicyEx failed with error code: {error}");
		}
	}

	/// <summary>
	/// Verifies if the specified policies exist in the system and match the expected values.
	/// </summary>
	/// <param name="policies">Policies to verify in the system.</param>
	/// <returns>A dictionary with policy entries as keys and their verification status (true if applied, false if not applied or different) as values</returns>
	internal static Dictionary<RegistryPolicyEntry, bool> VerifyPoliciesInSystem(List<RegistryPolicyEntry> policies)
	{
		Dictionary<RegistryPolicyEntry, bool> verificationResults = [];

		try
		{
			// Read the current system policies
			RegistryPolicyFile policyFile = ParseFile(LocalPolicyFilePath);

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
					verificationResults[policy] = isEquivalent;

					Logger.Write($"VERIFY: {policy.KeyName}\\{policy.ValueName} = {(isEquivalent ? "MATCH" : "MISMATCH")}");
				}
				else
				{
					// Policy doesn't exist in system
					verificationResults[policy] = false;
					Logger.Write($"VERIFY: {policy.KeyName}\\{policy.ValueName} = NOT FOUND");
				}
			}

			Logger.Write($"Verification complete: {verificationResults.Count(kvp => kvp.Value)} of {policies.Count} policies match");
		}
		catch (Exception ex)
		{
			Logger.Write(ErrorWriter.FormatException(ex));

			// Mark all policies as unverified on error
			foreach (RegistryPolicyEntry policy in policies)
			{
				verificationResults[policy] = false;
			}
		}

		return verificationResults;
	}

	/// <summary>
	/// Removes the specified policies from the system.
	/// </summary>
	/// <param name="policies">Policies to remove from the system.</param>
	internal static void RemovePoliciesFromSystem(List<RegistryPolicyEntry> policies)
	{
		// Read the current system policies
		RegistryPolicyFile policyFile = ParseFile(LocalPolicyFilePath);

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
		WriteFile(LocalPolicyFilePath, updatedFile);

		foreach (string removedEntry in removedEntries)
		{
			Logger.Write($"REMOVED: {removedEntry}");
		}

		bool result = NativeMethods.RefreshPolicyEx(true, NativeMethods.RP_FORCE);

		if (!result)
		{
			int error = Marshal.GetLastWin32Error();
			Logger.Write($"RefreshPolicyEx failed with error code: {error}");
		}

		Logger.Write($"Policy removal complete: {removedEntries.Count} policies removed");
	}
}
