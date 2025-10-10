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
using System.Runtime.InteropServices;
using System.Text;

namespace HardenSystemSecurity.Arcane;

internal static class EccCurveManager
{
	private const string BCRYPT_ECDH_ALGORITHM = "ECDH";
	private const string BCRYPT_ECC_CURVE_NAME = "ECCCurveName";
	private const string BCRYPT_ECC_CURVE_NAME_LIST = "ECCCurveNameList";
	private const string BCRYPT_ECC_PARAMETERS = "ECCParameters";

	internal static List<EccCurveSslProvider> EnumerateSslProviderCurves()
	{
		List<EccCurveSslProvider> list = [];

		ulong providerHandle = 0;
		IntPtr pCurves = IntPtr.Zero;
		uint curveCount = 0;

		try
		{
			int status = NativeMethods.SslOpenProvider(ref providerHandle, IntPtr.Zero, 0);
			if (status != 0)
			{
				return list;
			}

			status = NativeMethods.SslEnumEccCurves(providerHandle, ref curveCount, ref pCurves, 0);
			if (status != 0 || pCurves == IntPtr.Zero || curveCount == 0)
			{
				return list;
			}

			// Structure from sslprovider.h with proper alignment:
			// WCHAR szCurveName[255]       - offset 0, 510 bytes
			// CHAR szOID[255]              - offset 510, 255 bytes
			// [3 bytes padding for DWORD alignment]
			// DWORD dwPublicKeyLength      - offset 768, 4 bytes (aligned to 4-byte boundary)
			// DWORD dwCurveType            - offset 772, 4 bytes
			// DWORD dwFlags                - offset 776, 4 bytes
			// Total: 780 bytes

			const int CURVE_NAME_CHARS = 255;
			const int OID_CHARS = 255;
			const int NAME_OFFSET = 0;
			const int OID_OFFSET = 510;       // After name (510 bytes)
			const int BITS_OFFSET = 768;      // After OID + 3 bytes padding (510 + 255 + 3)
			const int TYPE_OFFSET = 772;      // After bits (768 + 4)
			const int FLAGS_OFFSET = 776;     // After type (772 + 4)
			const int STRUCT_SIZE = 780;      // Total aligned size

			// Read all curves
			for (uint i = 0; i < curveCount; i++)
			{
				IntPtr curvePtr = IntPtr.Add(pCurves, (int)(i * STRUCT_SIZE));

				// Read Unicode curve name (WCHAR[255] at offset 0)
				string name = ReadUnicodeString(curvePtr, NAME_OFFSET, CURVE_NAME_CHARS);

				// Read ANSI OID string (CHAR[255] at offset 510)
				string oid = ReadAnsiString(curvePtr, OID_OFFSET, OID_CHARS);

				// Read DWORD fields at aligned offsets
				uint bits = unchecked((uint)Marshal.ReadInt32(curvePtr, BITS_OFFSET));
				uint curveType = unchecked((uint)Marshal.ReadInt32(curvePtr, TYPE_OFFSET));
				uint flags = unchecked((uint)Marshal.ReadInt32(curvePtr, FLAGS_OFFSET));

				if (string.IsNullOrWhiteSpace(name))
				{
					continue;
				}

				list.Add(new EccCurveSslProvider(
					name.Trim(),
					oid.Trim(),
					bits,
					curveType,
					flags
				));
			}
		}
		finally
		{
			if (pCurves != IntPtr.Zero)
			{
				_ = NativeMethods.SslFreeBuffer(pCurves);
			}
			if (providerHandle != 0)
			{
				_ = NativeMethods.SslFreeObject(providerHandle, 0);
			}
		}

		return list;
	}


	// Helper methods
	private static string ReadUnicodeString(IntPtr basePtr, int byteOffset, int maxChars)
	{
		StringBuilder sb = new();

		for (int i = 0; i < maxChars; i++)
		{
			short ch = Marshal.ReadInt16(basePtr, byteOffset + (i * 2));
			if (ch == 0)
			{
				break;
			}
			_ = sb.Append((char)ch);
		}

		return sb.ToString();
	}

	private static string ReadAnsiString(IntPtr basePtr, int byteOffset, int maxChars)
	{
		StringBuilder sb = new();

		for (int i = 0; i < maxChars; i++)
		{
			byte b = Marshal.ReadByte(basePtr, byteOffset + i);
			if (b == 0)
			{
				break;
			}
			_ = sb.Append((char)b);
		}

		return sb.ToString();
	}

	internal static List<EccCurveCng> EnumerateCngCurves()
	{
		List<EccCurveCng> result = [];
		IntPtr hAlg = IntPtr.Zero;

		try
		{
			int status = NativeMethods.BCryptOpenAlgorithmProvider(out hAlg, BCRYPT_ECDH_ALGORITHM, null, 0);
			if (status != 0 || hAlg == IntPtr.Zero)
			{
				return result;
			}

			// Get the curve name list size
			status = NativeMethods.BCryptGetProperty(hAlg, BCRYPT_ECC_CURVE_NAME_LIST, IntPtr.Zero, 0, out uint cbNeeded, 0);
			if (status != 0 || cbNeeded <= 0)
			{
				return result;
			}

			IntPtr pBuffer = Marshal.AllocHGlobal((nint)cbNeeded);
			try
			{
				status = NativeMethods.BCryptGetProperty(hAlg, BCRYPT_ECC_CURVE_NAME_LIST, pBuffer, cbNeeded, out uint cbCopied, 0);
				if (status != 0 || cbCopied < 8)
				{
					return result;
				}

				// From bcrypt.h:
				// typedef struct _BCRYPT_ECC_CURVE_NAMES {
				//     ULONG dwEccCurveNames;
				//     LPWSTR *pEccCurveNames;
				// } BCRYPT_ECC_CURVE_NAMES;

				// Read the curve count (first DWORD at offset 0)
				uint curveCount = unchecked((uint)Marshal.ReadInt32(pBuffer, 0));

				if (curveCount == 0 || curveCount > 1000)
				{
					return result;
				}

				// Read the pointer to the array of string pointers
				// The structure has padding, so the pointer is at offset IntPtr.Size
				// On 64-bit: offset 8, on 32-bit: offset 4
				IntPtr pNamesArray = Marshal.ReadIntPtr(pBuffer, IntPtr.Size);

				if (pNamesArray == IntPtr.Zero)
				{
					return result;
				}

				// pNamesArray points to an array of curveCount pointers
				// Each pointer points to a null-terminated Unicode string
				for (uint i = 0; i < curveCount; i++)
				{
					try
					{
						// Read the pointer to the curve name string
						IntPtr pCurveName = Marshal.ReadIntPtr(pNamesArray, (int)(i * (uint)IntPtr.Size));

						if (pCurveName == IntPtr.Zero)
						{
							continue;
						}

						// Read the curve name string
						string? curveName = Marshal.PtrToStringUni(pCurveName);

						if (string.IsNullOrWhiteSpace(curveName))
						{
							continue;
						}

						// Get detailed information about this curve
						EccCurveCng? curveInfo = GetCurveDetails(hAlg, curveName);
						if (curveInfo != null)
						{
							result.Add(curveInfo);
						}
					}
					catch
					{
						// Skip this curve on error and continue with the next one
						continue;
					}
				}
			}
			finally
			{
				Marshal.FreeHGlobal(pBuffer);
			}
		}
		finally
		{
			if (hAlg != IntPtr.Zero)
			{
				_ = NativeMethods.BCryptCloseAlgorithmProvider(hAlg, 0);
			}
		}

		result.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
		return result;
	}


	private static EccCurveCng? GetCurveDetails(IntPtr hAlg, string curveName)
	{
		IntPtr hAlgLocal = IntPtr.Zero;
		IntPtr pCurveName = IntPtr.Zero;

		try
		{
			int status = NativeMethods.BCryptOpenAlgorithmProvider(out hAlgLocal, BCRYPT_ECDH_ALGORITHM, null, 0);
			if (status != 0 || hAlgLocal == IntPtr.Zero)
			{
				return new EccCurveCng(
					curveName,
					GetOidForCurve(curveName),
					0
				);
			}

			pCurveName = Marshal.StringToHGlobalUni(curveName);

			int nameLen = (curveName.Length + 1) * 2;
			status = NativeMethods.BCryptSetProperty(hAlgLocal, BCRYPT_ECC_CURVE_NAME, pCurveName, nameLen, 0);
			if (status != 0)
			{
				return new EccCurveCng(
					curveName,
					GetOidForCurve(curveName),
					0
				);
			}

			// Query the key length property to get the actual bit length
			status = NativeMethods.BCryptGetProperty(hAlgLocal, "KeyLengths", IntPtr.Zero, 0, out uint cbKeyLengths, 0);

			uint bits = 0;

			if (status == 0 && cbKeyLengths >= 12)
			{
				// BCRYPT_KEY_LENGTHS_STRUCT has three ULONG fields:
				// ULONG dwMinLength;
				// ULONG dwMaxLength;
				// ULONG dwIncrement;
				IntPtr pKeyLengths = Marshal.AllocHGlobal((nint)cbKeyLengths);
				try
				{
					status = NativeMethods.BCryptGetProperty(hAlgLocal, "KeyLengths", pKeyLengths, cbKeyLengths, out uint cbCopied, 0);
					if (status == 0 && cbCopied >= 12)
					{
						// Read dwMaxLength (second DWORD at offset 4)
						bits = unchecked((uint)Marshal.ReadInt32(pKeyLengths, 4));
					}
				}
				finally
				{
					Marshal.FreeHGlobal(pKeyLengths);
				}
			}

			// If we couldn't get the key length from KeyLengths property, fall back to ECC parameters
			if (bits == 0)
			{
				status = NativeMethods.BCryptGetProperty(hAlgLocal, BCRYPT_ECC_PARAMETERS, IntPtr.Zero, 0, out uint cbNeeded, 0);
				if (status == 0 && cbNeeded >= 20)
				{
					IntPtr pParams = Marshal.AllocHGlobal((nint)cbNeeded);
					try
					{
						status = NativeMethods.BCryptGetProperty(hAlgLocal, BCRYPT_ECC_PARAMETERS, pParams, cbNeeded, out uint cbCopied, 0);
						if (status == 0 && cbCopied >= 20)
						{
							// Read cbFieldLength at offset 16
							uint cbFieldLength = unchecked((uint)Marshal.ReadInt32(pParams, 16));
							bits = cbFieldLength * 8;
						}
					}
					finally
					{
						Marshal.FreeHGlobal(pParams);
					}
				}
			}

			return new EccCurveCng(
				curveName,
				GetOidForCurve(curveName),
				bits
			);
		}
		catch
		{
			return new EccCurveCng(
				curveName,
				GetOidForCurve(curveName),
				0
			);
		}
		finally
		{
			if (pCurveName != IntPtr.Zero)
			{
				Marshal.FreeHGlobal(pCurveName);
			}
			if (hAlgLocal != IntPtr.Zero)
			{
				_ = NativeMethods.BCryptCloseAlgorithmProvider(hAlgLocal, 0);
			}
		}
	}

	private static string GetOidForCurve(string curveName)
	{
		IntPtr pName = Marshal.StringToHGlobalUni(curveName);
		try
		{
			IntPtr pInfo = NativeMethods.CryptFindOIDInfo(2, pName, 0);
			if (pInfo != IntPtr.Zero)
			{
				IntPtr pszOID = Marshal.ReadIntPtr(pInfo, IntPtr.Size);
				if (pszOID != IntPtr.Zero)
				{
					string? oid = Marshal.PtrToStringAnsi(pszOID);
					if (!string.IsNullOrEmpty(oid))
					{
						return oid;
					}
				}
			}
		}
		finally
		{
			Marshal.FreeHGlobal(pName);
		}

		return string.Empty;
	}
}
