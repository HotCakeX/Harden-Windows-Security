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

using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;

namespace AppControlManager.Others;

/// <summary>
/// Represents extended file information, including properties like original file name, internal name, product name, and
/// version.
/// </summary>
internal static partial class GetExtendedFileAttrib
{
	/// <summary>
	/// Constants used for encoding fallback and error handling
	/// </summary>
	private const string UnicodeFallbackCode = "04B0";
	private const string Cp1252FallbackCode = "04E4";

	/// <summary>
	/// Constant representing the neutral file version, set to 2. Used for identifying a specific version in file
	/// operations.
	/// https://learn.microsoft.com/windows/win32/api/winver/nf-winver-getfileversioninfoexw#parameters
	/// </summary>
	private const uint FILE_VER_GET_NEUTRAL = 2;

	/// <summary>
	/// Retrieves extended file information, including version, original file name, internal name, file description, and
	/// product name.
	/// </summary>
	/// <param name="filePath">Specifies the path to the file for which extended information is being retrieved.</param>
	/// <returns>Returns an object containing the extended file information, with properties set to null in case of an error.</returns>
	internal static ExFileInfo Get(string filePath)
	{
		// Obj to return with everything set to null when there is an error/problem
		ExFileInfo BadCaseReturnVal = new(null, null, null, null, null);

		// Get the size of the version information block
		int versionInfoSize = NativeMethods.GetFileVersionInfoSizeExW(FILE_VER_GET_NEUTRAL, filePath, out int handle);

		if (versionInfoSize == 0)
		{
			return BadCaseReturnVal;
		}

		// Allocate array for version data and retrieve it
		byte[] versionData = new byte[versionInfoSize];

		if (!NativeMethods.GetFileVersionInfoExW(FILE_VER_GET_NEUTRAL, filePath, handle, versionInfoSize, versionData))
		{
			return BadCaseReturnVal;
		}

		try
		{
			Span<byte> spanData = new(versionData);

			// Extract version from the version data
			if (!TryGetVersion(spanData, out Version? version))
			{
				return BadCaseReturnVal;
			}

			// Extract locale and encoding information
			if (!TryGetLocaleAndEncoding(spanData, out string? locale, out string? encoding))
			{
				return BadCaseReturnVal;
			}

			// Retrieve various file information based on locale and encoding and return the result
			return new ExFileInfo(
				version: version,
				originalFileName: CheckAndSetNull(GetLocalizedResource(spanData, encoding!, locale!, "\\OriginalFileName")),
				internalName: CheckAndSetNull(GetLocalizedResource(spanData, encoding!, locale!, "\\InternalName")),
				fileDescription: CheckAndSetNull(GetLocalizedResource(spanData, encoding!, locale!, "\\FileDescription")),
				productName: CheckAndSetNull(GetLocalizedResource(spanData, encoding!, locale!, "\\ProductName"))
			);
		}
		catch (Exception ex)
		{
			Logger.Write(
				string.Format(
					GlobalVars.GetStr("CouldNotGetExFileInfoErrorMessage"),
					filePath,
					ex.Message
				)
			);

			return BadCaseReturnVal;
		}
	}

	/// <summary>
	/// Extracts version information from a byte array and outputs it as a Version object.
	/// </summary>
	/// <param name="data">The byte array containing version information to be extracted.</param>
	/// <param name="version">Outputs the extracted version information as a Version object.</param>
	/// <returns>Returns true if the version was successfully extracted, otherwise false.</returns>
	private static unsafe bool TryGetVersion(Span<byte> data, out Version? version)
	{
		version = null;

		// pin span directly
		fixed (byte* pData = data)
		{
			IntPtr basePtr = (IntPtr)pData;

			// Query the root block for version info and make sure the returned length is large enough for the struct
			if (NativeMethods.VerQueryValueW(basePtr, "\\", out nint buffer, out uint len) == 0 || buffer == IntPtr.Zero || len < sizeof(VS_FIXEDFILEINFO))
			{
				return false;
			}

			// Directly read the unmanaged VS_FIXEDFILEINFO structure (blittable)
			VS_FIXEDFILEINFO fileInfo = *(VS_FIXEDFILEINFO*)buffer;

			// Construct Version object from version info
			version = new Version(
				(int)(fileInfo.dwFileVersionMS >> 16),
				(int)(fileInfo.dwFileVersionMS & ushort.MaxValue),
				(int)(fileInfo.dwFileVersionLS >> 16),
				(int)(fileInfo.dwFileVersionLS & ushort.MaxValue)
			);
			return true;
		}
	}

	/// <summary>
	/// Extracts locale and encoding information from a byte span.
	/// </summary>
	/// <param name="data">The byte span containing data from which locale and encoding are extracted.</param>
	/// <param name="locale">Outputs the locale information derived from the data.</param>
	/// <param name="encoding">Outputs the encoding information derived from the data.</param>
	/// <returns>Returns a boolean indicating the success of the extraction process.</returns>
	private static unsafe bool TryGetLocaleAndEncoding(Span<byte> data, out string? locale, out string? encoding)
	{
		locale = null;
		encoding = null;

		// pin span instead of allocating a new array each call.
		fixed (byte* pData = data)
		{
			IntPtr basePtr = (IntPtr)pData;

			// Query the translation block for locale and encoding, verifying length is at least 4 bytes (2 WORDs)
			if (NativeMethods.VerQueryValueW(basePtr, "\\VarFileInfo\\Translation", out nint buffer, out uint len) == 0 || buffer == IntPtr.Zero || len < 4)
			{
				return false;
			}

			// Cast directly to ushort* (WORD)
			ushort* pTranslations = (ushort*)buffer;

			// Convert the translation values to hex strings
			locale = pTranslations[0].ToString("X4", CultureInfo.InvariantCulture);
			encoding = pTranslations[1].ToString("X4", CultureInfo.InvariantCulture);
			return true;
		}
	}

	/// <summary>
	/// Retrieves a localized resource string using specified encoding and locale from a version block.
	/// </summary>
	/// <param name="versionBlock">This parameter provides the binary data containing version information.</param>
	/// <param name="encoding">Specifies the character encoding to be used for interpreting the resource string.</param>
	/// <param name="locale">Indicates the locale for which the resource string is being requested.</param>
	/// <param name="resource">Identifies the specific resource string to retrieve from the version information.</param>
	/// <returns>Returns the localized resource string or null if not found.</returns>
	private static unsafe string? GetLocalizedResource(Span<byte> versionBlock, string encoding, string locale, string resource)
	{
		ReadOnlySpan<string> encodings = [encoding, Cp1252FallbackCode, UnicodeFallbackCode];

		// pin once, reuse base pointer across attempts.
		fixed (byte* pData = versionBlock)
		{
			IntPtr basePtr = (IntPtr)pData;

			foreach (string enc in encodings)
			{
				string subBlock = $"\\StringFileInfo\\{locale}{enc}{resource}";

				// Grab the length to safely instantiate the string
				if (NativeMethods.VerQueryValueW(basePtr, subBlock, out nint buffer, out uint len) != 0 && buffer != IntPtr.Zero && len > 0)
				{
					ReadOnlySpan<char> valueSpan = new((void*)buffer, (int)len);
					valueSpan = valueSpan.TrimEnd('\0');

					// If the resulting string is empty, return the interned string.Empty to avoid allocating a new object on the heap
					return valueSpan.IsEmpty ? string.Empty : new string(valueSpan);
				}
			}
		}
		return null;
	}

	/// <summary>
	/// Check if a string is null or whitespace and return null if it is
	/// </summary>
	/// <param name="value"></param>
	/// <returns></returns>
	private static string? CheckAndSetNull(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
