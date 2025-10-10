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

namespace HardenSystemSecurity.Arcane;

internal static class CipherSuiteManager
{
	private const uint CRYPT_LOCAL = 0x00000001;
	private const uint NCRYPT_SCHANNEL_INTERFACE = 0x00010002;
	private const string SSL_CONTEXT = "SSL";
	private const int NTE_NO_MORE_ITEMS = unchecked((int)0x8009002A);

	private const int OFF_PROTOCOL = 0;
	private const int OFF_CIPHER_SUITE = 4;
	private const int OFF_BASE_CIPHER_SUITE = 8;
	private const int OFF_SZ_CIPHER_SUITE = 12;
	private const int OFF_SZ_CIPHER = 140;
	private const int OFF_CIPHER_LEN = 268;
	private const int OFF_CIPHER_BLOCK_LEN = 272;
	private const int OFF_SZ_HASH = 276;
	private const int OFF_HASH_LEN = 404;
	private const int OFF_SZ_EXCHANGE = 408;
	private const int OFF_MIN_EXCHANGE = 536;
	private const int OFF_MAX_EXCHANGE = 540;
	private const int OFF_SZ_CERTIFICATE = 544;
	private const int OFF_KEY_TYPE = 672;

	internal static unsafe List<TlsCipherSuite> EnumerateConfiguredCipherSuites()
	{
		List<TlsCipherSuite> cipherSuites = [];

		IntPtr contextFunctions = IntPtr.Zero;
		uint functionCount = 0;
		IntPtr providerRefs = IntPtr.Zero;
		IntPtr cipherSuitePtr = IntPtr.Zero;
		IntPtr enumState = IntPtr.Zero;
		ulong providerHandle = 0;

		try
		{
			int status = NativeMethods.BCryptEnumContextFunctions(
				CRYPT_LOCAL,
				SSL_CONTEXT,
				NCRYPT_SCHANNEL_INTERFACE,
				ref functionCount,
				ref contextFunctions);

			if (status < 0)
			{
				throw new InvalidOperationException($"BCryptEnumContextFunctions failed with error 0x{status:X8}");
			}

			if (contextFunctions == IntPtr.Zero || functionCount == 0)
			{
				return cipherSuites;
			}

			CRYPT_CONTEXT_FUNCTIONS contextFuncsStruct = *(CRYPT_CONTEXT_FUNCTIONS*)contextFunctions;
			IntPtr namesArrayPtr = contextFuncsStruct.rgpszFunctions;

			for (uint i = 0; i < contextFuncsStruct.cFunctions; i++)
			{
				IntPtr functionNamePtr = Marshal.ReadIntPtr(namesArrayPtr, checked((int)(i * (uint)IntPtr.Size)));
				if (functionNamePtr == IntPtr.Zero)
				{
					continue;
				}

				string cipherSuiteName = Marshal.PtrToStringUni(functionNamePtr) ?? string.Empty;
				if (cipherSuiteName.Length == 0)
				{
					continue;
				}

				TlsCipherSuite suite = new(cipherSuiteName);
				cipherSuites.Add(suite);

				providerRefs = IntPtr.Zero;
				uint providerCount = 0;

				status = NativeMethods.BCryptResolveProviders(
					SSL_CONTEXT,
					NCRYPT_SCHANNEL_INTERFACE,
					cipherSuiteName,
					null,
					1U,
					2U,
					ref providerCount,
					ref providerRefs);

				if (status >= 0 && providerRefs != IntPtr.Zero)
				{
					CRYPT_PROVIDER_REFS providerRefsStruct = *(CRYPT_PROVIDER_REFS*)providerRefs;

					for (uint p = 0; p < providerRefsStruct.cProviders; p++)
					{
						IntPtr providerRefPtr = Marshal.ReadIntPtr(providerRefsStruct.rgpProviders, checked((int)(p * (uint)IntPtr.Size)));
						if (providerRefPtr == IntPtr.Zero)
						{
							continue;
						}

						CRYPT_PROVIDER_REF providerRef = *(CRYPT_PROVIDER_REF*)providerRefPtr;
						if (providerRef.pszProvider == IntPtr.Zero)
						{
							continue;
						}

						status = NativeMethods.SslOpenProvider(ref providerHandle, providerRef.pszProvider, 0U);
						if (status < 0 || providerHandle == 0)
						{
							continue;
						}

						enumState = IntPtr.Zero;

						while (true)
						{
							cipherSuitePtr = IntPtr.Zero;

							status = NativeMethods.SslEnumCipherSuites(
								providerHandle,
								0UL,
								ref cipherSuitePtr,
								ref enumState,
								0U);

							if (status == NTE_NO_MORE_ITEMS)
							{
								break;
							}

							if (status < 0)
							{
								break;
							}

							if (cipherSuitePtr == IntPtr.Zero)
							{
								continue;
							}

							string enumSuiteName = ReadUnicodeString(cipherSuitePtr, OFF_SZ_CIPHER_SUITE);
							if (string.Equals(enumSuiteName, cipherSuiteName, StringComparison.OrdinalIgnoreCase))
							{
								PopulateSuiteFromStruct(cipherSuitePtr, suite);
							}

							_ = NativeMethods.SslFreeBuffer(cipherSuitePtr);
							cipherSuitePtr = IntPtr.Zero;
						}

						if (enumState != IntPtr.Zero)
						{
							_ = NativeMethods.SslFreeBuffer(enumState);
							enumState = IntPtr.Zero;
						}

						if (providerHandle != 0)
						{
							_ = NativeMethods.SslFreeObject(providerHandle, 0U);
							providerHandle = 0;
						}
					}

					NativeMethods.BCryptFreeBuffer(providerRefs);
					providerRefs = IntPtr.Zero;
				}
			}
		}
		finally
		{
			if (contextFunctions != IntPtr.Zero)
			{
				NativeMethods.BCryptFreeBuffer(contextFunctions);
			}

			if (providerRefs != IntPtr.Zero)
			{
				NativeMethods.BCryptFreeBuffer(providerRefs);
			}

			if (cipherSuitePtr != IntPtr.Zero)
			{
				_ = NativeMethods.SslFreeBuffer(cipherSuitePtr);
			}

			if (enumState != IntPtr.Zero)
			{
				_ = NativeMethods.SslFreeBuffer(enumState);
			}

			if (providerHandle != 0)
			{
				_ = NativeMethods.SslFreeObject(providerHandle, 0U);
			}
		}

		return cipherSuites;
	}

	internal static unsafe List<TlsCipherSuite> EnumerateAllCipherSuites()
	{
		Dictionary<string, TlsCipherSuite> byName = new(StringComparer.OrdinalIgnoreCase);

		IntPtr providerRefs = IntPtr.Zero;
		ulong providerHandle = 0;

		try
		{
			uint providerCount = 0;
			int status = NativeMethods.BCryptResolveProviders(
				SSL_CONTEXT,
				NCRYPT_SCHANNEL_INTERFACE,
				null,
				null,
				1U,
				2U,
				ref providerCount,
				ref providerRefs);

			List<IntPtr> providerRefPtrs = [];

			if (status >= 0 && providerRefs != IntPtr.Zero)
			{
				CRYPT_PROVIDER_REFS refs = *(CRYPT_PROVIDER_REFS*)providerRefs;
				for (uint p = 0; p < refs.cProviders; p++)
				{
					IntPtr providerRefPtr = Marshal.ReadIntPtr(refs.rgpProviders, checked((int)(p * (uint)IntPtr.Size)));
					if (providerRefPtr != IntPtr.Zero)
					{
						providerRefPtrs.Add(providerRefPtr);
					}
				}
			}

			if (providerRefPtrs.Count == 0)
			{
				status = NativeMethods.SslOpenProvider(ref providerHandle, IntPtr.Zero, 0U);
				if (status >= 0 && providerHandle != 0)
				{
					EnumerateFromProviderHandle(providerHandle, byName);
					_ = NativeMethods.SslFreeObject(providerHandle, 0U);
					providerHandle = 0;
				}
			}
			else
			{
				for (int i = 0; i < providerRefPtrs.Count; i++)
				{
					IntPtr providerRefPtr = providerRefPtrs[i];
					CRYPT_PROVIDER_REF providerRef = *(CRYPT_PROVIDER_REF*)providerRefPtr;
					if (providerRef.pszProvider == IntPtr.Zero)
					{
						continue;
					}

					status = NativeMethods.SslOpenProvider(ref providerHandle, providerRef.pszProvider, 0U);
					if (status < 0 || providerHandle == 0)
					{
						continue;
					}

					EnumerateFromProviderHandle(providerHandle, byName);

					_ = NativeMethods.SslFreeObject(providerHandle, 0U);
					providerHandle = 0;
				}
			}
		}
		finally
		{
			if (providerRefs != IntPtr.Zero)
			{
				NativeMethods.BCryptFreeBuffer(providerRefs);
			}
		}

		List<TlsCipherSuite> result = [.. byName.Values];
		result.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
		return result;
	}

	private static string GetProtocolName(uint protocol)
	{
		return protocol switch
		{
			0x0300 => "SSL 3.0",
			0x0301 => "TLS 1.0",
			0x0302 => "TLS 1.1",
			0x0303 => "TLS 1.2",
			0x0304 => "TLS 1.3",
			0xFEFD => "DTLS 1.2",
			0xFEFF => "DTLS 1.0",
			_ => $"Unknown (0x{protocol:X4})",
		};
	}

	private static void PopulateSuiteFromStruct(IntPtr cipherSuitePtr, TlsCipherSuite suite)
	{
		uint dwProtocol = ReadUInt32(cipherSuitePtr, OFF_PROTOCOL);
		if (!suite.Protocols.Contains(dwProtocol))
		{
			suite.Protocols.Add(dwProtocol);
			suite.ProtocolNames.Add(GetProtocolName(dwProtocol));
		}

		if (suite.Cipher.Length == 0)
		{
			suite.Cipher = ReadUnicodeString(cipherSuitePtr, OFF_SZ_CIPHER);
			suite.CipherSuite = ReadUInt32(cipherSuitePtr, OFF_CIPHER_SUITE);
			suite.BaseCipherSuite = ReadUInt32(cipherSuitePtr, OFF_BASE_CIPHER_SUITE);
			suite.CipherLength = ReadUInt32(cipherSuitePtr, OFF_CIPHER_LEN);
			suite.CipherBlockLength = ReadUInt32(cipherSuitePtr, OFF_CIPHER_BLOCK_LEN);
		}

		if (suite.Exchange.Length == 0)
		{
			suite.Exchange = ReadUnicodeString(cipherSuitePtr, OFF_SZ_EXCHANGE);
			suite.MinimumExchangeLength = ReadUInt32(cipherSuitePtr, OFF_MIN_EXCHANGE);
			suite.MaximumExchangeLength = ReadUInt32(cipherSuitePtr, OFF_MAX_EXCHANGE);
		}

		if (suite.Hash.Length == 0)
		{
			suite.Hash = ReadUnicodeString(cipherSuitePtr, OFF_SZ_HASH);
			suite.HashLength = ReadUInt32(cipherSuitePtr, OFF_HASH_LEN);
		}

		if (suite.Certificate.Length == 0)
		{
			suite.Certificate = ReadUnicodeString(cipherSuitePtr, OFF_SZ_CERTIFICATE);
			suite.KeyType = ReadUInt32(cipherSuitePtr, OFF_KEY_TYPE);
		}
	}

	private static void EnumerateFromProviderHandle(ulong providerHandle, Dictionary<string, TlsCipherSuite> byName)
	{
		IntPtr enumState = IntPtr.Zero;
		IntPtr cipherSuitePtr = IntPtr.Zero;

		try
		{
			while (true)
			{
				cipherSuitePtr = IntPtr.Zero;

				int status = NativeMethods.SslEnumCipherSuites(
					providerHandle,
					0UL,
					ref cipherSuitePtr,
					ref enumState,
					0U);

				if (status == NTE_NO_MORE_ITEMS)
				{
					break;
				}
				if (status < 0)
				{
					break;
				}
				if (cipherSuitePtr == IntPtr.Zero)
				{
					continue;
				}

				string name = ReadUnicodeString(cipherSuitePtr, OFF_SZ_CIPHER_SUITE);
				if (name.Length != 0)
				{
					if (!byName.TryGetValue(name, out TlsCipherSuite? suite))
					{
						suite = new TlsCipherSuite(name);
						byName[name] = suite;

						suite.CipherSuite = ReadUInt32(cipherSuitePtr, OFF_CIPHER_SUITE);
						suite.BaseCipherSuite = ReadUInt32(cipherSuitePtr, OFF_BASE_CIPHER_SUITE);
						suite.Cipher = ReadUnicodeString(cipherSuitePtr, OFF_SZ_CIPHER);
						suite.CipherLength = ReadUInt32(cipherSuitePtr, OFF_CIPHER_LEN);
						suite.CipherBlockLength = ReadUInt32(cipherSuitePtr, OFF_CIPHER_BLOCK_LEN);
						suite.Hash = ReadUnicodeString(cipherSuitePtr, OFF_SZ_HASH);
						suite.HashLength = ReadUInt32(cipherSuitePtr, OFF_HASH_LEN);
						suite.Exchange = ReadUnicodeString(cipherSuitePtr, OFF_SZ_EXCHANGE);
						suite.MinimumExchangeLength = ReadUInt32(cipherSuitePtr, OFF_MIN_EXCHANGE);
						suite.MaximumExchangeLength = ReadUInt32(cipherSuitePtr, OFF_MAX_EXCHANGE);
						suite.Certificate = ReadUnicodeString(cipherSuitePtr, OFF_SZ_CERTIFICATE);
						suite.KeyType = ReadUInt32(cipherSuitePtr, OFF_KEY_TYPE);
					}

					uint protocol = ReadUInt32(cipherSuitePtr, OFF_PROTOCOL);
					if (!suite.Protocols.Contains(protocol))
					{
						suite.Protocols.Add(protocol);
						suite.ProtocolNames.Add(GetProtocolName(protocol));
					}
				}

				_ = NativeMethods.SslFreeBuffer(cipherSuitePtr);
				cipherSuitePtr = IntPtr.Zero;
			}
		}
		finally
		{
			if (cipherSuitePtr != IntPtr.Zero)
			{
				_ = NativeMethods.SslFreeBuffer(cipherSuitePtr);
			}
			if (enumState != IntPtr.Zero)
			{
				_ = NativeMethods.SslFreeBuffer(enumState);
			}
		}
	}

	private static uint ReadUInt32(IntPtr basePtr, int offset)
	{
		return unchecked((uint)Marshal.ReadInt32(basePtr, offset));
	}

	private static string ReadUnicodeString(IntPtr basePtr, int offset)
	{
		IntPtr strPtr = IntPtr.Add(basePtr, offset);
		string s = Marshal.PtrToStringUni(strPtr) ?? string.Empty;
		return s;
	}
}
