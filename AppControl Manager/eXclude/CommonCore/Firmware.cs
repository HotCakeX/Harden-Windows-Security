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
	private const int STATUS_BUFFER_OVERFLOW = unchecked((int)0x80000005);
	private const int SE_PRIVILEGE_ENABLED = 0x0002;
	private const int ERROR_INSUFFICIENT_BUFFER = 122;
	private const int ERROR_ENVVAR_NOT_FOUND = 203;
	private const int ERROR_INVALID_FUNCTION = 1;
	private const uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;
	private const uint TOKEN_QUERY = 0x00000008;
	private const string OsIndicationsVariableName = "OsIndications";
	private const string OsIndicationsSupportedVariableName = "OsIndicationsSupported";
	private const uint EfiVariableNonVolatile = 0x00000001;
	private const uint EfiVariableBootServiceAccess = 0x00000002;
	private const uint EfiVariableRuntimeAccess = 0x00000004;
	private const ulong EfiOsIndicationsBootToFirmwareUi = 0x0000000000000001;
	private const uint EwxReboot = 0x00000002;
	private const uint EwxForceIfHung = 0x00000010;
	private const uint ShtdnReasonMajorOperatingSystem = 0x00020000;
	private const uint ShtdnReasonMinorReconfig = 0x00000004;
	private const uint ShtdnReasonFlagPlanned = 0x80000000;
	private const uint BcdLibraryObjectListRecoverySequence = 0x14000008;
	private const uint BcdBootMgrObjectListBootSequence = 0x24000002;
	private const uint BcdElementFlagsNone = 0;
	private static readonly Guid BcdBootManagerGuid = new("9DEA862C-5CDD-4E70-ACC1-F32B344D4795");
	private static readonly Guid BcdCurrentBootEntryGuid = new("FA926493-6F1C-4193-A414-58F0B2456D1E");
	private static readonly string EfiGlobalVariableGuidString = $"{{{EfiGlobalVariableGuid:D}}}";

	/// <summary>
	/// Enables the SeSystemEnvironmentPrivilege required to read UEFI variables.
	/// </summary>
	private static bool EnableSystemEnvironmentPrivilege()
	{
		try
		{
			EnablePrivilege("SeSystemEnvironmentPrivilege");
			return true;
		}
		catch
		{
			return false;
		}
	}

	/// <summary>
	/// Reboots the operating system directly into the firmware settings UI when the platform supports it.
	/// </summary>
	internal static void RebootToUefiFirmwareSettings()
	{
		EnablePrivilege("SeSystemEnvironmentPrivilege");

		if (!TryReadUefiUInt64GlobalVariable(OsIndicationsSupportedVariableName, out ulong supportedOsIndications, out _))
		{
			throw new NotSupportedException("This system firmware does not expose OsIndicationsSupported.");
		}

		if ((supportedOsIndications & EfiOsIndicationsBootToFirmwareUi) == 0)
		{
			throw new NotSupportedException("This system firmware does not support rebooting directly into the UEFI settings UI.");
		}

		bool hadExistingOsIndications = TryReadUefiUInt64GlobalVariable(OsIndicationsVariableName, out ulong currentOsIndications, out uint osIndicationsAttributes);

		uint attributesToUse = osIndicationsAttributes != 0
			? osIndicationsAttributes
			: EfiVariableNonVolatile | EfiVariableBootServiceAccess | EfiVariableRuntimeAccess;

		WriteUefiUInt64GlobalVariable(OsIndicationsVariableName, currentOsIndications | EfiOsIndicationsBootToFirmwareUi, attributesToUse);

		EnablePrivilege("SeShutdownPrivilege");

		if (!NativeMethods.ExitWindowsEx(EwxReboot | EwxForceIfHung, ShtdnReasonMajorOperatingSystem | ShtdnReasonMinorReconfig | ShtdnReasonFlagPlanned))
		{
			int rebootError = Marshal.GetLastPInvokeError();

			try
			{
				if (hadExistingOsIndications)
				{
					WriteUefiUInt64GlobalVariable(OsIndicationsVariableName, currentOsIndications, attributesToUse);
				}
				else
				{
					DeleteUefiGlobalVariable(OsIndicationsVariableName, attributesToUse);
				}
			}
			catch
			{
				// Preserve the reboot failure as the primary error if the rollback also fails.
			}

			throw new Win32Exception(rebootError, "Failed to reboot after requesting the UEFI firmware settings UI.");
		}
	}

	/// <summary>
	/// Reboots the operating system directly into the configured Windows Recovery Environment on the next boot.
	/// </summary>
	internal static void RebootToWindowsRecoveryEnvironment()
	{
		Guid[] recoverySequence = GetWindowsRecoveryEnvironmentBootSequence();
		SetBootManagerOneTimeBootSequence(recoverySequence);
		EnablePrivilege("SeShutdownPrivilege");
		if (!NativeMethods.ExitWindowsEx(EwxReboot | EwxForceIfHung, ShtdnReasonMajorOperatingSystem | ShtdnReasonMinorReconfig | ShtdnReasonFlagPlanned))
		{
			throw new Win32Exception(Marshal.GetLastPInvokeError(), "Failed to reboot after requesting Windows Recovery Environment.");
		}
	}

	/// <summary>
	/// Retrieves the configured recovery boot applications for the current Windows boot entry from the BCD store.
	/// </summary>
	private static Guid[] GetWindowsRecoveryEnvironmentBootSequence()
	{
		IntPtr storeHandle = IntPtr.Zero;
		IntPtr currentBootEntryHandle = IntPtr.Zero;
		try
		{
			ThrowIfBcdFailed(NativeMethods.BcdOpenSystemStore(out storeHandle), "Failed to open the BCD system store.");
			Guid currentBootEntryGuid = BcdCurrentBootEntryGuid;
			ThrowIfBcdFailed(NativeMethods.BcdOpenObject(storeHandle, ref currentBootEntryGuid, out currentBootEntryHandle), "Failed to open the current Windows boot entry in the BCD store.");
			Guid[] recoverySequence = GetBcdGuidListElement(currentBootEntryHandle, BcdLibraryObjectListRecoverySequence, "Windows Recovery Environment is not configured for the current Windows boot entry.");
			if (recoverySequence.Length == 0)
			{
				throw new InvalidOperationException("Windows Recovery Environment is not configured for the current Windows boot entry.");
			}
			return recoverySequence;
		}
		finally
		{
			if (currentBootEntryHandle != IntPtr.Zero)
			{
				_ = NativeMethods.BcdCloseObject(currentBootEntryHandle);
			}
			if (storeHandle != IntPtr.Zero)
			{
				_ = NativeMethods.BcdCloseStore(storeHandle);
			}
		}
	}

	/// <summary>
	/// Writes the one-time boot sequence on the Windows Boot Manager BCD object.
	/// </summary>
	private static unsafe void SetBootManagerOneTimeBootSequence(ReadOnlySpan<Guid> bootSequence)
	{
		IntPtr storeHandle = IntPtr.Zero;
		IntPtr bootManagerHandle = IntPtr.Zero;
		try
		{
			ThrowIfBcdFailed(NativeMethods.BcdOpenSystemStore(out storeHandle), "Failed to open the BCD system store.");
			Guid bootManagerGuid = BcdBootManagerGuid;
			ThrowIfBcdFailed(NativeMethods.BcdOpenObject(storeHandle, ref bootManagerGuid, out bootManagerHandle), "Failed to open the Windows Boot Manager BCD object.");
			int dataSize = checked(bootSequence.Length * 16);
			IntPtr buffer = Marshal.AllocHGlobal(dataSize);
			try
			{
				Span<byte> data = new((void*)buffer, dataSize);
				for (int i = 0; i < bootSequence.Length; i++)
				{
					if (!bootSequence[i].TryWriteBytes(data.Slice(i * 16, 16)))
					{
						throw new InvalidOperationException("Failed to serialize a BCD object identifier.");
					}
				}
				ThrowIfBcdFailed(NativeMethods.BcdSetElementDataWithFlags(bootManagerHandle, BcdBootMgrObjectListBootSequence, BcdElementFlagsNone, buffer, (uint)dataSize), "Failed to set the one-time Windows Boot Manager boot sequence.");
			}
			finally
			{
				Marshal.FreeHGlobal(buffer);
			}
		}
		finally
		{
			if (bootManagerHandle != IntPtr.Zero)
			{
				_ = NativeMethods.BcdCloseObject(bootManagerHandle);
			}
			if (storeHandle != IntPtr.Zero)
			{
				_ = NativeMethods.BcdCloseStore(storeHandle);
			}
		}
	}

	/// <summary>
	/// Reads a GUID list element from a BCD object.
	/// </summary>
	private static unsafe Guid[] GetBcdGuidListElement(IntPtr objectHandle, uint elementType, string missingElementMessage)
	{
		uint dataSize = 0;
		int queryStatus = NativeMethods.BcdGetElementDataWithFlags(objectHandle, elementType, BcdElementFlagsNone, IntPtr.Zero, ref dataSize);
		if (queryStatus < 0 && queryStatus != STATUS_BUFFER_TOO_SMALL && queryStatus != STATUS_BUFFER_OVERFLOW)
		{
			ThrowIfBcdFailed(queryStatus, missingElementMessage);
		}
		if (dataSize == 0)
		{
			throw new InvalidOperationException(missingElementMessage);
		}
		if ((dataSize % 16) != 0)
		{
			throw new InvalidOperationException($"BCD element 0x{elementType:X8} returned an invalid GUID list size of {dataSize} bytes.");
		}
		IntPtr buffer = Marshal.AllocHGlobal(checked((int)dataSize));
		try
		{
			ThrowIfBcdFailed(NativeMethods.BcdGetElementDataWithFlags(objectHandle, elementType, BcdElementFlagsNone, buffer, ref dataSize), $"Failed to read BCD element 0x{elementType:X8}.");
			List<Guid> identifiers = [];
			byte* data = (byte*)buffer;
			for (int offset = 0; offset < dataSize; offset += 16)
			{
				Guid identifier = new(new ReadOnlySpan<byte>(data + offset, 16));
				if (!identifier.Equals(Guid.Empty))
				{
					identifiers.Add(identifier);
				}
			}
			return [.. identifiers];
		}
		finally
		{
			Marshal.FreeHGlobal(buffer);
		}
	}

	/// <summary>
	/// Throws a Win32Exception when a BCD API returns a failing NTSTATUS value.
	/// </summary>
	private static void ThrowIfBcdFailed(int status, string message)
	{
		if (status >= 0)
		{
			return;
		}
		int win32Error = NativeMethods.RtlNtStatusToDosError(status);
		throw new Win32Exception(win32Error, $"{message} NTSTATUS: 0x{status:X8}.");
	}

	/// <summary>
	/// Enables a privilege required for firmware or reboot operations.
	/// </summary>
	private static void EnablePrivilege(string privilegeName)
	{
		if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out IntPtr tokenHandle))
		{
			throw new Win32Exception(Marshal.GetLastPInvokeError(), $"Failed to open the current process token for privilege '{privilegeName}'.");
		}

		try
		{
			if (!NativeMethods.LookupPrivilegeValueW(null, privilegeName, out LUID luid))
			{
				throw new Win32Exception(Marshal.GetLastPInvokeError(), $"Failed to look up privilege '{privilegeName}'.");
			}

			TOKEN_PRIVILEGES tokenPrivileges = new()
			{
				PrivilegeCount = 1,
				Privileges = new LUID_AND_ATTRIBUTES
				{
					Luid = luid,
					Attributes = SE_PRIVILEGE_ENABLED
				}
			};

			if (!NativeMethods.AdjustTokenPrivileges(tokenHandle, false, ref tokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero))
			{
				throw new Win32Exception(Marshal.GetLastPInvokeError(), $"Failed to enable privilege '{privilegeName}'.");
			}

			int adjustError = Marshal.GetLastPInvokeError();

			if (adjustError != 0)
			{
				throw new Win32Exception(adjustError, $"The process token does not allow enabling privilege '{privilegeName}'.");
			}
		}
		finally
		{
			_ = NativeMethods.CloseHandle(tokenHandle);
		}
	}

	/// <summary>
	/// Reads a UInt64 global UEFI variable value when present.
	/// </summary>
	private static bool TryReadUefiUInt64GlobalVariable(string variableName, out ulong value, out uint attributes)
	{
		IntPtr buffer = Marshal.AllocHGlobal(sizeof(ulong));

		try
		{
			uint read = NativeMethods.GetFirmwareEnvironmentVariableExW(variableName, EfiGlobalVariableGuidString, buffer, sizeof(ulong), out attributes);

			if (read == sizeof(ulong))
			{
				value = unchecked((ulong)Marshal.ReadInt64(buffer));
				return true;
			}

			if (read == 0)
			{
				int error = Marshal.GetLastPInvokeError();

				if (error == ERROR_ENVVAR_NOT_FOUND)
				{
					value = 0;
					attributes = 0;
					return false;
				}

				if (error == ERROR_INVALID_FUNCTION)
				{
					throw new NotSupportedException("UEFI firmware variables are not available on this Windows installation.");
				}

				throw new Win32Exception(error, $"Failed to read UEFI variable '{variableName}'.");
			}

			throw new InvalidOperationException($"UEFI variable '{variableName}' returned {read} bytes instead of the expected {sizeof(ulong)} bytes.");
		}
		finally
		{
			Marshal.FreeHGlobal(buffer);
		}
	}

	/// <summary>
	/// Writes a UInt64 value to a global UEFI variable.
	/// </summary>
	private static void WriteUefiUInt64GlobalVariable(string variableName, ulong value, uint attributes)
	{
		IntPtr buffer = Marshal.AllocHGlobal(sizeof(ulong));

		try
		{
			Marshal.WriteInt64(buffer, unchecked((long)value));

			if (!NativeMethods.SetFirmwareEnvironmentVariableExW(variableName, EfiGlobalVariableGuidString, buffer, sizeof(ulong), attributes))
			{
				int error = Marshal.GetLastPInvokeError();

				if (error == ERROR_INVALID_FUNCTION)
				{
					throw new NotSupportedException("UEFI firmware variables are not available on this Windows installation.");
				}

				throw new Win32Exception(error, $"Failed to write UEFI variable '{variableName}'.");
			}
		}
		finally
		{
			Marshal.FreeHGlobal(buffer);
		}
	}

	/// <summary>
	/// Deletes a global UEFI variable when rollback is required.
	/// </summary>
	private static void DeleteUefiGlobalVariable(string variableName, uint attributes)
	{
		if (!NativeMethods.SetFirmwareEnvironmentVariableExW(variableName, EfiGlobalVariableGuidString, IntPtr.Zero, 0, attributes))
		{
			throw new Win32Exception(Marshal.GetLastPInvokeError(), $"Failed to delete UEFI variable '{variableName}' during rollback.");
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
