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
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CommonCore;

internal static partial class Firmware
{

	internal static readonly Guid EfiGlobalVariableGuid = new("8BE4DF61-93CA-11D2-AA0D-00E098032B8C");
	internal static readonly Guid EfiImageSecurityDatabaseGuid = new("D719B2CB-3D3A-4596-A3BC-DAD00E67656F");
	internal static readonly Guid EfiCertX509Guid = new("A5C059A1-94E4-4AA7-87B5-AB155C2BF072");
	internal static readonly Guid EfiCertSha256Guid = new("C1C41626-504C-4092-ACA9-41F936934328");

	/// <summary>
	/// Map of supported UEFI variables and their expected Vendor GUIDs
	/// </summary>
	private static readonly FrozenDictionary<string, Guid> UefiVariableMap =
		new Dictionary<string, Guid>(StringComparer.OrdinalIgnoreCase)
		{
			{ "PK", EfiGlobalVariableGuid },
			{ "KEK", EfiGlobalVariableGuid },
			{ "db", EfiImageSecurityDatabaseGuid },
			{ "dbx", EfiImageSecurityDatabaseGuid },
			{ "PKDefault", EfiGlobalVariableGuid },
			{ "KEKDefault", EfiGlobalVariableGuid },
			{ "dbDefault", EfiGlobalVariableGuid },
			{ "dbxDefault", EfiGlobalVariableGuid }
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	private static void ValidateUefiVariable(string name, Guid vendorGuid)
	{
		if (!UefiVariableMap.TryGetValue(name, out Guid expectedGuid))
		{
			throw new InvalidOperationException($"Unsupported UEFI variable '{name}'.");
		}

		if (!expectedGuid.Equals(vendorGuid))
		{
			throw new InvalidOperationException($"UEFI variable '{name}' must use GUID '{{{expectedGuid}}}', but '{{{vendorGuid}}}' was supplied.");
		}
	}

	/// <summary>
	/// Record for non-Cert UEFI items
	/// </summary>
	internal sealed record UefiHashEntry(Guid Owner, string Hash, string Algorithm);

	private const uint SystemEnvironmentInformation = 2;
	private const int STATUS_SUCCESS = 0;
	private const int STATUS_BUFFER_TOO_SMALL = unchecked((int)0xC0000023);
	private const int SE_PRIVILEGE_ENABLED = 0x0002;
	private const int ERROR_INSUFFICIENT_BUFFER = 122;
	private const int ERROR_ENVVAR_NOT_FOUND = 203;
	private const uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;
	private const uint TOKEN_QUERY = 0x00000008;

	/// <summary>
	/// Enables the SeSystemEnvironmentPrivilege required to read UEFI variables.
	/// </summary>
	private static bool EnableSystemEnvironmentPrivilege()
	{
		if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out IntPtr token))
			return false;

		try
		{
			if (!NativeMethods.LookupPrivilegeValueW(null, "SeSystemEnvironmentPrivilege", out LUID luid))
				return false;

			TOKEN_PRIVILEGES tp = new()
			{
				PrivilegeCount = 1,
				Privileges = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = SE_PRIVILEGE_ENABLED }
			};

			if (!NativeMethods.AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
				return false;

			return Marshal.GetLastPInvokeError() == 0;
		}
		finally
		{
			_ = NativeMethods.CloseHandle(token);
		}
	}

	/// <summary>
	/// Verifies if a UEFI variable exists using <see cref="NativeMethods.NtEnumerateSystemEnvironmentValuesEx"/>.
	/// This ensures we don't blindly call <see cref="NativeMethods.GetFirmwareEnvironmentVariableExW"/> on non-existent variables.
	/// </summary>
	/// <param name="name">The variable name.</param>
	/// <param name="vendorGuid">The vendor GUID.</param>
	/// <returns>True if found, false otherwise.</returns>
	private static unsafe bool VerifyUefiVariableExists(string name, Guid vendorGuid)
	{
		// Start with 1MB buffer
		uint size = 1024 * 1024;

		IntPtr buffer = IntPtr.Zero;

		try
		{
			buffer = (nint)NativeMemory.Alloc(size);
			int status = NativeMethods.NtEnumerateSystemEnvironmentValuesEx(SystemEnvironmentInformation, buffer, ref size);

			if (status == STATUS_BUFFER_TOO_SMALL)
			{
				NativeMemory.Free((void*)buffer);
				buffer = IntPtr.Zero; // To prevent double free if the next Alloc fails
				buffer = (nint)NativeMemory.Alloc(size);
				status = NativeMethods.NtEnumerateSystemEnvironmentValuesEx(SystemEnvironmentInformation, buffer, ref size);
			}

			if (status != STATUS_SUCCESS)
			{
				// If enumeration fails return false
				return false;
			}

			byte* ptr = (byte*)buffer;
			uint offset = 0;

			while (offset + sizeof(VARIABLE_HEADER) <= size)
			{
				VARIABLE_HEADER* hdr = (VARIABLE_HEADER*)(ptr + offset);
				if (hdr->Size == 0) break;

				if (hdr->VendorGuid.Equals(vendorGuid))
				{
					int nameLen = (int)(hdr->DataOffset - sizeof(VARIABLE_HEADER));
					// Ensure the name and data offsets are within the allocated buffer
					if (nameLen > 0 && (offset + hdr->DataOffset) <= size)
					{
						string currentName = Encoding.Unicode.GetString(ptr + offset + sizeof(VARIABLE_HEADER), nameLen).TrimEnd('\0');
						if (string.Equals(currentName, name, StringComparison.OrdinalIgnoreCase))
						{
							return true;
						}
					}
				}

				offset += hdr->Size;
			}
		}
		finally
		{
			if (buffer != IntPtr.Zero)
				NativeMemory.Free((void*)buffer);
		}

		return false;
	}

	/// <summary>
	/// Retrieves raw bytes of a UEFI variable.
	/// Checks for existence using <see cref="NativeMethods.NtEnumerateSystemEnvironmentValuesEx"/> first.
	/// </summary>
	private static unsafe byte[] GetUefiVariableBytes(string name, Guid vendorGuid)
	{
		// Validation for correct GUID/type mapping
		// This is enforced before privilege enabling and reads to avoid wrong data usage.
		// The caller is responsible for indicating expected content type through GetUefiCertificates/GetUefiHashes.
		// The validation is split between those entry points.
		if (!EnableSystemEnvironmentPrivilege())
		{
			throw new UnauthorizedAccessException("Failed to enable SeSystemEnvironmentPrivilege.");
		}

		if (!VerifyUefiVariableExists(name, vendorGuid))
		{
			throw new FileNotFoundException($"UEFI Variable '{name}' with GUID '{{{vendorGuid}}}' was not found in the system environment enumeration.");
		}

		string guidStr = $"{{{vendorGuid:D}}}";
		uint size = 1024;

		while (true)
		{
			void* buffer = NativeMemory.Alloc(size);
			try
			{
				uint read = NativeMethods.GetFirmwareEnvironmentVariableExW(name, guidStr, (IntPtr)buffer, size, out _);

				if (read > 0)
				{
					return new Span<byte>(buffer, (int)read).ToArray();
				}
				else
				{
					int error = Marshal.GetLastPInvokeError();
					if (error == ERROR_INSUFFICIENT_BUFFER)
					{
						size *= 2;

						// 32MB limit safety
						if (size > 32 * 1024 * 1024)
						{
							throw new InvalidOperationException($"UEFI variable '{name}' is too large.");
						}

						continue;
					}
					else if (error == ERROR_ENVVAR_NOT_FOUND)
					{
						// Should not happen if VerifyUefiVariableExists returned true
						return [];
					}
					else
					{
						throw new Win32Exception(error, $"Failed to read UEFI variable '{name}'.");
					}
				}
			}
			finally
			{
				NativeMemory.Free(buffer);
			}
		}
	}


	/// <summary>
	/// Retrieves contents of a signature list variable (e.g. db, dbx), parsing for both X.509 and SHA-256.
	/// </summary>
	/// <returns>A list containing X509Certificate2 objects and UefiHashEntry objects.</returns>
	internal static List<object> GetUefiCertificatesOrHashes(string name, Guid vendorGuid)
	{
		ValidateUefiVariable(name, vendorGuid);

		byte[] data = GetUefiVariableBytes(name, vendorGuid);

		if (data.Length == 0)
			return [];

		return ParseEfiSignatureListMixed(data);
	}


	/// <summary>
	/// Parses EFI_SIGNATURE_LIST for both X.509 certificates and SHA-256 hashes.
	/// </summary>
	private static List<object> ParseEfiSignatureListMixed(ReadOnlySpan<byte> data)
	{
		List<object> results = [];
		int offset = 0;

		while (offset + 28 <= data.Length)
		{
			Guid sigType = new(data.Slice(offset, 16));
			uint listSize = BitConverter.ToUInt32(data.Slice(offset + 16, 4));
			uint headerSize = BitConverter.ToUInt32(data.Slice(offset + 20, 4));
			uint sigSize = BitConverter.ToUInt32(data.Slice(offset + 24, 4));

			if (listSize == 0 || offset + listSize > data.Length) break;

			int itemsStart = offset + 28 + (int)headerSize;
			int itemsEnd = offset + (int)listSize;

			if (sigSize >= 16 && itemsStart <= itemsEnd)
			{
				int p = itemsStart;
				while (p + sigSize <= itemsEnd)
				{
					if (sigType.Equals(EfiCertX509Guid))
					{
						// SignatureOwner is at p (16 bytes), SignatureData starts at p+16
						int certLen = (int)sigSize - 16;
						if (certLen > 0)
						{
							byte[] rawCert = data.Slice(p + 16, certLen).ToArray();
							try
							{
								X509Certificate2 cert = X509CertificateLoader.LoadCertificate(rawCert);
								results.Add(cert);
							}
							catch { }
						}
					}
					else if (sigType.Equals(EfiCertSha256Guid))
					{
						Guid owner = new(data.Slice(p, 16));
						int hashLen = (int)sigSize - 16;
						if (hashLen == 32) // SHA-256 must be 32 bytes
						{
							string hash = Convert.ToHexString(data.Slice(p + 16, hashLen));
							results.Add(new UefiHashEntry(owner, hash, "SHA-256"));
						}
					}

					p += (int)sigSize;
				}
			}

			offset += (int)listSize;
		}
		return results;
	}
}
