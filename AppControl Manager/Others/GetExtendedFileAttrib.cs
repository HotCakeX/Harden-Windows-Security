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
using System.Globalization;
using System.Runtime.InteropServices;

namespace AppControlManager.Others;

/// <summary>
/// Represents extended file information, including properties like original file name, internal name, product name, and
/// version.
/// </summary>
public sealed partial class ExFileInfo
{
	// Constants used for encoding fallback and error handling
	private const string UnicodeFallbackCode = "04B0";
	private const string Cp1252FallbackCode = "04E4";

	/// <summary>
	/// Constant representing the neutral file version, set to 2. Used for identifying a specific version in file
	/// operations.
	/// </summary>
	public const int FILE_VER_GET_NEUTRAL = 2;

	/// <summary>
	/// Represents an error code indicating that a specified resource type could not be found. The value is -2147023083.
	/// </summary>
	public const int HR_ERROR_RESOURCE_TYPE_NOT_FOUND = -2147023083;

	// Properties to hold file information

	/// <summary>
	/// Holds the original name of the file. It can be null if no name is provided.
	/// </summary>
	public string? OriginalFileName { get; set; }

	/// <summary>
	/// Represents the internal name of an entity, which can be null. It is a string property that can be accessed and
	/// modified.
	/// </summary>
	public string? InternalName { get; set; }

	/// <summary>
	/// Represents the name of a product. It can be null, indicating that the product name is not specified.
	/// </summary>
	public string? ProductName { get; set; }

	/// <summary>
	/// Represents the version of an object, allowing for nullable values. It can be used to track or specify the
	/// versioning of data.
	/// </summary>
	public Version? Version { get; set; }

	/// <summary>
	/// Represents an optional description of a file. It can hold a string value or be null.
	/// </summary>
	public string? FileDescription { get; set; }

	// Importing external functions from Version.dll to work with file version info
	// https://learn.microsoft.com/he-il/windows/win32/api/winver/nf-winver-getfileversioninfosizeexa
	[LibraryImport("Version.dll", EntryPoint = "GetFileVersionInfoSizeExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	private static partial int GetFileVersionInfoSizeEx(uint dwFlags, string filename, out int handle);

	// https://learn.microsoft.com/he-il/windows/win32/api/winver/nf-winver-verqueryvaluea
	[LibraryImport("Version.dll", EntryPoint = "VerQueryValueW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static partial bool VerQueryValue(IntPtr block, string subBlock, out IntPtr buffer, out int len);

	// https://learn.microsoft.com/he-il/windows/win32/api/winver/nf-winver-getfileversioninfoexa
	[LibraryImport("Version.dll", EntryPoint = "GetFileVersionInfoExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static partial bool GetFileVersionInfoEx(uint dwFlags, string filename, int handle, int len, [Out] byte[] data);

	// Private constructor to prevent direct instantiation
	private ExFileInfo() { }

	/// <summary>
	/// Retrieves extended file information, including version, original file name, internal name, file description, and
	/// product name.
	/// </summary>
	/// <param name="filePath">Specifies the path to the file for which extended information is being retrieved.</param>
	/// <returns>Returns an object containing the extended file information, with properties set to null in case of an error.</returns>
	public static ExFileInfo GetExtendedFileInfo(string filePath)
	{
		ExFileInfo ExFileInfo = new();

		// Get the size of the version information block
		int versionInfoSize = GetFileVersionInfoSizeEx(FILE_VER_GET_NEUTRAL, filePath, out int handle);

		if (versionInfoSize == 0)
		{
			return ExFileInfo;
		}

		// Allocate array for version data and retrieve it
		byte[] versionData = new byte[versionInfoSize];
		if (!GetFileVersionInfoEx(FILE_VER_GET_NEUTRAL, filePath, handle, versionInfoSize, versionData))
			return ExFileInfo;

		try
		{
			Span<byte> spanData = new(versionData);

			// Extract version from the version data
			if (!TryGetVersion(spanData, out Version? version))
				throw Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error())!;

			ExFileInfo.Version = version; // Set the Version property

			// Extract locale and encoding information
			if (!TryGetLocaleAndEncoding(spanData, out string? locale, out string? encoding))
				throw Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error())!;

			// Retrieve various file information based on locale and encoding
			ExFileInfo.OriginalFileName = CheckAndSetNull(GetLocalizedResource(spanData, encoding!, locale!, "\\OriginalFileName"));
			ExFileInfo.InternalName = CheckAndSetNull(GetLocalizedResource(spanData, encoding!, locale!, "\\InternalName"));
			ExFileInfo.FileDescription = CheckAndSetNull(GetLocalizedResource(spanData, encoding!, locale!, "\\FileDescription"));
			ExFileInfo.ProductName = CheckAndSetNull(GetLocalizedResource(spanData, encoding!, locale!, "\\ProductName"));
		}
		catch
		{
			// In case of an error, set all properties to null
			ExFileInfo.Version = null;
			ExFileInfo.OriginalFileName = null;
			ExFileInfo.InternalName = null;
			ExFileInfo.FileDescription = null;
			ExFileInfo.ProductName = null;
		}
		return ExFileInfo;
	}

	// Extract the version from the data
	private static bool TryGetVersion(Span<byte> data, out Version? version)
	{
		version = null;
		// Query the root block for version info
		if (!VerQueryValue(Marshal.UnsafeAddrOfPinnedArrayElement(data.ToArray(), 0), "\\", out nint buffer, out _))
			return false;

		// Marshal the version info structure
		FileVersionInfo fileInfo = Marshal.PtrToStructure<FileVersionInfo>(buffer);

		// Construct Version object from version info
		version = new Version(
			(int)(fileInfo.dwFileVersionMS >> 16),
			(int)(fileInfo.dwFileVersionMS & ushort.MaxValue),
			(int)(fileInfo.dwFileVersionLS >> 16),
			(int)(fileInfo.dwFileVersionLS & ushort.MaxValue)
		);
		return true;
	}

	// Extract locale and encoding information from the data
	private static bool TryGetLocaleAndEncoding(Span<byte> data, out string? locale, out string? encoding)
	{
		locale = null;
		encoding = null;
		// Query the translation block for locale and encoding
		if (!VerQueryValue(Marshal.UnsafeAddrOfPinnedArrayElement(data.ToArray(), 0), "\\VarFileInfo\\Translation", out nint buffer, out _))
			return false;

		// Copy the translation values
		short[] translations = new short[2];
		Marshal.Copy(buffer, translations, 0, 2);

		// Convert the translation values to hex strings
		locale = translations[0].ToString("X4", CultureInfo.InvariantCulture);
		encoding = translations[1].ToString("X4", CultureInfo.InvariantCulture);
		return true;
	}

	// Get localized resource string based on encoding and locale
	private static string? GetLocalizedResource(Span<byte> versionBlock, string encoding, string locale, string resource)
	{
		string[] encodings = [encoding, Cp1252FallbackCode, UnicodeFallbackCode];

		foreach (string enc in encodings)
		{
			string subBlock = $"StringFileInfo\\{locale}{enc}{resource}";

			if (VerQueryValue(Marshal.UnsafeAddrOfPinnedArrayElement(versionBlock.ToArray(), 0), subBlock, out nint buffer, out _))
				return Marshal.PtrToStringAuto(buffer);

			// If error is not resource type not found, throw the error
			if (Marshal.GetHRForLastWin32Error() != HR_ERROR_RESOURCE_TYPE_NOT_FOUND)
				throw Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error())!;
		}
		return null;
	}

	// Check if a string is null or whitespace and return null if it is
	private static string? CheckAndSetNull(string? value)
	{
		return string.IsNullOrWhiteSpace(value) ? null : value;
	}

	// Structure to hold file version information
	[StructLayout(LayoutKind.Sequential)]
	private struct FileVersionInfo
	{
		public uint dwSignature;
		public uint dwStrucVersion;
		public uint dwFileVersionMS;
		public uint dwFileVersionLS;
		public uint dwProductVersionMS;
		public uint dwProductVersionLS;
		public uint dwFileFlagsMask;
		public uint dwFileFlags;
		public uint dwFileOS;
		public uint dwFileType;
		public uint dwFileSubtype;
		public uint dwFileDateMS;
		public uint dwFileDateLS;
	}
}
