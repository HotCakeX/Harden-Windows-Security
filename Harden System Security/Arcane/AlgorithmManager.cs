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

internal static class AlgorithmManager
{
	internal const uint BCRYPT_CIPHER_OPERATION = 0x00000001;
	internal const uint BCRYPT_HASH_OPERATION = 0x00000002;
	internal const uint BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION = 0x00000004;
	internal const uint BCRYPT_SECRET_AGREEMENT_OPERATION = 0x00000008;
	internal const uint BCRYPT_SIGNATURE_OPERATION = 0x00000010;
	internal const uint BCRYPT_RNG_OPERATION = 0x00000020;
	internal const uint BCRYPT_KEY_DERIVATION_OPERATION = 0x00000040;

	private const string BCRYPT_PARAMETER_SET_NAME = "ParameterSetName";

	// Known post-quantum parameter sets
	private static readonly string[] MlDsaParameterSets =
	[
		"MLDSA44",
		"MLDSA65",
		"MLDSA87"
	];

	private static readonly string[] MlKemParameterSets =
	[
		"MLKEM512",
		"MLKEM768",
		"MLKEM1024"
	];

	private static readonly string[] SlhDsaParameterSets =
	[
		"SLHDSA128F",
		"SLHDSA128S",
		"SLHDSA192F",
		"SLHDSA192S",
		"SLHDSA256F",
		"SLHDSA256S"
	];

	internal static List<CryptoAlgorithm> EnumerateAllAlgorithms()
	{
		List<CryptoAlgorithm> allAlgorithms = [];

		uint allOperations = BCRYPT_CIPHER_OPERATION |
							BCRYPT_HASH_OPERATION |
							BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION |
							BCRYPT_SECRET_AGREEMENT_OPERATION |
							BCRYPT_SIGNATURE_OPERATION |
							BCRYPT_RNG_OPERATION |
							BCRYPT_KEY_DERIVATION_OPERATION;

		IntPtr pAlgList = IntPtr.Zero;
		uint algCount = 0;

		try
		{
			int status = NativeMethods.BCryptEnumAlgorithms(allOperations, out algCount, out pAlgList, 0);

			if (status != 0 || pAlgList == IntPtr.Zero || algCount == 0)
			{
				return allAlgorithms;
			}

			int structSize = IntPtr.Size + 8;

			for (uint i = 0; i < algCount; i++)
			{
				IntPtr currentAlg = IntPtr.Add(pAlgList, (int)(i * structSize));

				IntPtr pszName = Marshal.ReadIntPtr(currentAlg, 0);
				uint dwClass = unchecked((uint)Marshal.ReadInt32(currentAlg, IntPtr.Size));
				uint dwFlags = unchecked((uint)Marshal.ReadInt32(currentAlg, IntPtr.Size + 4));

				if (pszName == IntPtr.Zero)
				{
					continue;
				}

				string algorithmName = Marshal.PtrToStringUni(pszName) ?? string.Empty;

				if (string.IsNullOrWhiteSpace(algorithmName))
				{
					continue;
				}

				CryptoAlgorithm algorithm = new()
				{
					Name = algorithmName,
					OperationClass = dwClass,
					Flags = dwFlags,
					AlgorithmType = GetAlgorithmTypeDescription(dwClass),
					IsOpenable = false,
					IsPostQuantum = false,
					SupportsKeyGeneration = false
				};

				allAlgorithms.Add(algorithm);
			}
		}
		finally
		{
			if (pAlgList != IntPtr.Zero)
			{
				NativeMethods.BCryptFreeBuffer(pAlgList);
			}
		}

		return allAlgorithms;
	}

	/// <summary>
	/// Tests algorithm availability and detects post-quantum capabilities.
	/// For PQ algorithms, performs additional tests for key generation and parameter sets.
	/// </summary>
	internal static void TestAlgorithmAvailability(List<CryptoAlgorithm> algorithms)
	{
		foreach (CryptoAlgorithm alg in algorithms)
		{
			IntPtr hAlgorithm = IntPtr.Zero;

			try
			{
				// Test if algorithm can be opened
				int status = NativeMethods.BCryptOpenAlgorithmProvider(
					out hAlgorithm,
					alg.Name,
					null,
					0
				);

				if (status == 0 && hAlgorithm != IntPtr.Zero)
				{
					alg.IsOpenable = true;

					// Detect if this is a post-quantum algorithm by name pattern
					alg.IsPostQuantum = IsPostQuantumAlgorithmName(alg.Name);

					// If it's a PQ algorithm, perform additional testing
					if (alg.IsPostQuantum)
					{
						TestPostQuantumCapabilities(hAlgorithm, alg);
					}
				}
				else
				{
					alg.IsOpenable = false;
				}
			}
			catch
			{
				alg.IsOpenable = false;
			}
			finally
			{
				// Ensure the algorithm provider handle is always closed if opened
				if (hAlgorithm != IntPtr.Zero)
				{
					if (NativeMethods.BCryptCloseAlgorithmProvider(hAlgorithm, 0) != 0)
					{
						Logger.Write($"Failed to close algorithm provider for {alg.Name}", LogTypeIntel.Warning);
					}
				}
			}
		}
	}

	/// <summary>
	/// Performs deep testing of post-quantum algorithm capabilities.
	/// Includes proper key pair finalization. Some providers might require
	/// BCryptFinalizeKeyPair before a key is considered valid, and parameter
	/// set assignment must occur prior to finalization.
	/// Strategy:
	///  1. Do a simple generate+finalize once to decide SupportsKeyGeneration.
	///  2. For each candidate parameter set:
	///     a. Generate a fresh key pair.
	///     b. Set the parameter set property (must be before finalization).
	///     c. Finalize the key pair.
	///     d. If all succeeded, record the parameter set as supported.
	///     e. Destroy the key handle.
	/// We create a new key per parameter set to avoid state contamination
	/// and to handle providers that lock parameter set choice at generation time.
	/// </summary>
	private static void TestPostQuantumCapabilities(IntPtr hAlgorithm, CryptoAlgorithm alg)
	{
		// 1. Baseline key generation capability test
		IntPtr hProbeKey = IntPtr.Zero;
		try
		{
			int genStatus = NativeMethods.BCryptGenerateKeyPair(hAlgorithm, out hProbeKey, 0, 0);
			if (genStatus == 0 && hProbeKey != IntPtr.Zero)
			{
				int finalizeStatus = NativeMethods.BCryptFinalizeKeyPair(hProbeKey, 0);
				if (finalizeStatus == 0)
				{
					alg.SupportsKeyGeneration = true;
				}
			}
		}
		finally
		{
			if (hProbeKey != IntPtr.Zero)
			{
				if (NativeMethods.BCryptDestroyKey(hProbeKey) != 0)
				{
					Logger.Write($"Failed to destroy probe key for {alg.Name}", LogTypeIntel.Warning);
				}
			}
		}

		// 2. Parameter set probing (only if algorithm name maps to known parameter sets)
		string[] parameterSetsToTest = GetParameterSetsForAlgorithm(alg.Name);
		if (parameterSetsToTest.Length == 0)
		{
			return;
		}

		foreach (string paramSet in parameterSetsToTest)
		{
			IntPtr hKey = IntPtr.Zero;
			try
			{
				int status = NativeMethods.BCryptGenerateKeyPair(hAlgorithm, out hKey, 0, 0);
				if (status != 0 || hKey == IntPtr.Zero)
				{
					continue;
				}

				// Set parameter set before finalizing the key pair.
				bool propertyOk = TestParameterSet(hKey, paramSet);
				if (!propertyOk)
				{
					continue;
				}

				// Finalize after property set; required for some providers.
				status = NativeMethods.BCryptFinalizeKeyPair(hKey, 0);
				if (status == 0)
				{
					// Only add if finalization succeeded with the parameter applied.
					alg.SupportedParameterSets.Add(paramSet);

					// If earlier baseline probe failed but we successfully
					// generated+finalized here, we can mark key generation support.
					if (!alg.SupportsKeyGeneration)
					{
						alg.SupportsKeyGeneration = true;
					}
				}
			}
			finally
			{
				if (hKey != IntPtr.Zero)
				{
					if (NativeMethods.BCryptDestroyKey(hKey) != 0)
					{
						Logger.Write($"Failed to destroy key for {alg.Name} with parameter set {paramSet}", LogTypeIntel.Warning);
					}
				}
			}
		}
	}

	/// <summary>
	/// Tests if a specific parameter set is supported for a key pair.
	/// </summary>
	private static bool TestParameterSet(IntPtr hKeyPair, string parameterSet)
	{
		try
		{
			IntPtr pParamSet = Marshal.StringToHGlobalUni(parameterSet);

			try
			{
				int paramSetLen = (parameterSet.Length + 1) * 2;

				int status = NativeMethods.BCryptSetProperty(
					hKeyPair,
					BCRYPT_PARAMETER_SET_NAME,
					pParamSet,
					paramSetLen,
					0
				);

				return status == 0;
			}
			finally
			{
				Marshal.FreeHGlobal(pParamSet);
			}
		}
		catch
		{
			return false;
		}
	}

	/// <summary>
	/// Determines which parameter sets to test based on algorithm name.
	/// </summary>
	private static string[] GetParameterSetsForAlgorithm(string algorithmName)
	{
		if (algorithmName.Contains("MLDSA", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("ML-DSA", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("DILITHIUM", StringComparison.OrdinalIgnoreCase))
		{
			return MlDsaParameterSets;
		}

		if (algorithmName.Contains("MLKEM", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("ML-KEM", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("KYBER", StringComparison.OrdinalIgnoreCase))
		{
			return MlKemParameterSets;
		}

		if (algorithmName.Contains("SLHDSA", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("SLH-DSA", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("SPHINCS", StringComparison.OrdinalIgnoreCase))
		{
			return SlhDsaParameterSets;
		}

		return [];
	}

	/// <summary>
	/// Detects if an algorithm name indicates post-quantum cryptography.
	/// Based on NIST-standardized PQ algorithm naming conventions.
	/// </summary>
	private static bool IsPostQuantumAlgorithmName(string algorithmName)
	{
		// NIST Round 3 Winners (Standardized - FIPS 203, 204, 205)
		if (algorithmName.Contains("MLKEM", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("ML-KEM", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("KYBER", StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}

		if (algorithmName.Contains("MLDSA", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("ML-DSA", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("DILITHIUM", StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}

		if (algorithmName.Contains("SLHDSA", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("SLH-DSA", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("SPHINCS", StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}

		// NIST Round 4 and other candidates
		if (algorithmName.Contains("FALCON", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("NTRU", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("SABER", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("FRODO", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("CRYSTALS", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("BIKE", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("HQC", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("MCELIECE", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("CLASSIC-MCELIECE", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("XMSS", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("LMS", StringComparison.OrdinalIgnoreCase) ||
			algorithmName.Contains("PICNIC", StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}

		return false;
	}

	internal static unsafe List<string> EnumerateRegisteredProviders()
	{
		List<string> providers = [];
		uint cbBuffer = 0;
		IntPtr ppBuffer = IntPtr.Zero;

		try
		{
			int status = NativeMethods.BCryptEnumRegisteredProviders(ref cbBuffer, ref ppBuffer);

			if (status != 0 || ppBuffer == IntPtr.Zero)
			{
				return providers;
			}

			CRYPT_PROVIDERS providersStruct = *(CRYPT_PROVIDERS*)ppBuffer;

			if (providersStruct.rgpszProviders == IntPtr.Zero || providersStruct.cProviders == 0)
			{
				return providers;
			}

			for (uint i = 0; i < providersStruct.cProviders; i++)
			{
				IntPtr pProviderName = Marshal.ReadIntPtr(providersStruct.rgpszProviders, (int)(i * (uint)IntPtr.Size));

				if (pProviderName == IntPtr.Zero)
				{
					continue;
				}

				string providerName = Marshal.PtrToStringUni(pProviderName) ?? string.Empty;

				if (!string.IsNullOrWhiteSpace(providerName))
				{
					providers.Add(providerName);
				}
			}
		}
		finally
		{
			if (ppBuffer != IntPtr.Zero)
			{
				NativeMethods.BCryptFreeBuffer(ppBuffer);
			}
		}

		providers.Sort(StringComparer.OrdinalIgnoreCase);
		return providers;
	}

	private static string GetAlgorithmTypeDescription(uint dwClass)
	{
		List<string> types = [];

		if ((dwClass & BCRYPT_CIPHER_OPERATION) != 0)
		{
			types.Add("Cipher");
		}
		if ((dwClass & BCRYPT_HASH_OPERATION) != 0)
		{
			types.Add("Hash");
		}
		if ((dwClass & BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION) != 0)
		{
			types.Add("Asymmetric Encryption");
		}
		if ((dwClass & BCRYPT_SECRET_AGREEMENT_OPERATION) != 0)
		{
			types.Add("Secret Agreement");
		}
		if ((dwClass & BCRYPT_SIGNATURE_OPERATION) != 0)
		{
			types.Add("Signature");
		}
		if ((dwClass & BCRYPT_RNG_OPERATION) != 0)
		{
			types.Add("RNG");
		}
		if ((dwClass & BCRYPT_KEY_DERIVATION_OPERATION) != 0)
		{
			types.Add("Key Derivation");
		}

		return types.Count > 0 ? string.Join(", ", types) : "Unknown";
	}
}
