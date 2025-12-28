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

using System.Security.Cryptography;
using CommonCore.Interop;

namespace CommonCore;

internal static class LLPackageReader
{
	/// <summary>
	/// Contains details about an app package.
	/// </summary>
	internal sealed class PackageDetails(string certCN, HashAlgorithmName hashAlgorithm, string packageFamilyName, string version)
	{
		internal string CertCN => certCN;
		internal HashAlgorithmName HashAlgorithm => hashAlgorithm;
		internal string PackageFamilyName => packageFamilyName;
		internal string Version => version;
	}

	/// <summary>
	/// Gets package details from an app package file.
	/// </summary>
	internal static PackageDetails GetPackageDetails(string packagePath)
	{
		// S_OK (0) or S_FALSE (1, already initialized) are success codes.
		int hr = NativeMethods.CoInitializeEx(IntPtr.Zero, 0x2); // COINIT_APARTMENTTHREADED

		// RPC_E_CHANGED_MODE = -2147417850 (0x80010106)
		if (hr < 0 && hr != -2147417850)
		{
			throw new InvalidOperationException($"CoInitializeEx failed with HRESULT 0x{hr:X}");
		}

		try
		{
			if (packagePath.EndsWith(".msixbundle", StringComparison.OrdinalIgnoreCase))
			{
				return InspectBundle(packagePath);
			}
			else
			{
				return InspectPackage(packagePath);
			}
		}
		finally
		{
			// Only Uninitialize if we successfully initialized (S_OK or S_FALSE).
			// If hr was RPC_E_CHANGED_MODE, we didn't initialize, so we shouldn't uninitialize.
			if (hr >= 0)
			{
				NativeMethods.CoUninitialize();
			}
		}
	}

	private unsafe static PackageDetails InspectPackage(string path)
	{
		int hr;

		// Initialize all pointers to Zero so we can safely check/release them in finally block
		IntPtr pStream = IntPtr.Zero;
		IntPtr pAppxFactory = IntPtr.Zero;
		IntPtr pPackageReader = IntPtr.Zero;
		IntPtr pManifestReader = IntPtr.Zero;
		IntPtr pPackageId = IntPtr.Zero;
		IntPtr pBlockMapReader = IntPtr.Zero;
		IntPtr pUri = IntPtr.Zero;

		// Output values
		string certificateCN = string.Empty;
		HashAlgorithmName hashingAlgo = HashAlgorithmName.SHA256;
		string packageFamilyName = string.Empty;
		string version = string.Empty;

		try
		{
			// Create Stream
			fixed (char* pPath = path)
			{
				hr = NativeMethods.SHCreateStreamOnFileEx(
					(ushort*)pPath,
					0x00000000 | 0x00000020, // STGM_READ | STGM_SHARE_DENY_WRITE
					0,
					0,
					IntPtr.Zero,
					&pStream);
			}

			if (hr != 0) throw new InvalidOperationException($"Failed to create stream. HR: 0x{hr:X}");

			// Create IAppxFactory
			Guid clsid = new("5842a140-ff9f-4166-8f5c-62f5b7b0c781");
			Guid iid = new("beb94909-e451-438b-b5a7-d79e767b75d8");

			hr = NativeMethods.CoCreateInstance(in clsid, IntPtr.Zero, 1, in iid, out pAppxFactory);
			if (hr != 0) throw new InvalidOperationException($"Failed to create AppxFactory. HR: 0x{hr:X}");

			RawIAppxFactory* factory = (RawIAppxFactory*)pAppxFactory;

			// Create Package Reader
			hr = factory->Vtbl->CreatePackageReader((void*)pAppxFactory, pStream, &pPackageReader);
			if (hr != 0) throw new InvalidOperationException($"CreatePackageReader failed. HR: 0x{hr:X}");

			RawIAppxPackageReader* packageReader = (RawIAppxPackageReader*)pPackageReader;

			// Get Manifest
			hr = packageReader->Vtbl->GetManifest((void*)pPackageReader, &pManifestReader);
			if (hr != 0) throw new InvalidOperationException($"GetManifest failed. HR: 0x{hr:X}");

			RawIAppxManifestReader* manifestReader = (RawIAppxManifestReader*)pManifestReader;

			// Get PackageId
			hr = manifestReader->Vtbl->GetPackageId((void*)pManifestReader, &pPackageId);
			if (hr != 0) throw new InvalidOperationException($"GetPackageId failed. HR: 0x{hr:X}");

			RawIAppxManifestPackageId* packageId = (RawIAppxManifestPackageId*)pPackageId;

			// Get Publisher (for Common Name)
			ushort* pPublisherDn = null;
			hr = packageId->Vtbl->GetPublisher((void*)pPackageId, &pPublisherDn);

			// Only process if successful
			if (hr == 0)
			{
				try
				{
					string publisherDn = new((char*)pPublisherDn);
					certificateCN = ParseCommonName(publisherDn);
				}
				finally
				{
					// Must always free the string memory allocated by the callee
					NativeMethods.CoTaskMemFree((IntPtr)pPublisherDn);
				}
			}
			else
			{
				throw new InvalidOperationException($"Failed to get Publisher from PackageId. HR: 0x{hr:X}");
			}

			// Get Package Family Name
			ushort* pPfn = null;
			hr = packageId->Vtbl->GetPackageFamilyName((void*)pPackageId, &pPfn);
			if (hr == 0)
			{
				try
				{
					packageFamilyName = new((char*)pPfn);
				}
				finally
				{
					NativeMethods.CoTaskMemFree((IntPtr)pPfn);
				}
			}
			else
			{
				throw new InvalidOperationException($"Failed to get PackageFamilyName. HR: 0x{hr:X}");
			}

			// Get Version
			ulong versionNum = 0;
			hr = packageId->Vtbl->GetVersion((void*)pPackageId, &versionNum);

			version = hr == 0 ? ParseVersion(versionNum) : throw new InvalidOperationException($"Failed to get Version. HR: 0x{hr:X}");

			// Get BlockMap (for Hashing Algorithm)
			hr = packageReader->Vtbl->GetBlockMap((void*)pPackageReader, &pBlockMapReader);

			if (hr == 0 && pBlockMapReader != IntPtr.Zero)
			{
				RawIAppxBlockMapReader* blockMapReader = (RawIAppxBlockMapReader*)pBlockMapReader;

				// Get HashMethod (IUri)
				hr = blockMapReader->Vtbl->GetHashMethod((void*)pBlockMapReader, &pUri);

				if (hr == 0 && pUri != IntPtr.Zero)
				{
					RawIUri* uri = (RawIUri*)pUri;

					// Get Absolute URI (BSTR)
					ushort* pBstrUri = null;
					hr = uri->Vtbl->GetAbsoluteUri((void*)pUri, &pBstrUri);

					if (hr == 0)
					{
						try
						{
							string uriString = new((char*)pBstrUri);
							hashingAlgo = ParseHashAlg(uriString);
						}
						finally
						{
							NativeMethods.SysFreeString((IntPtr)pBstrUri);
						}
					}
					else
					{
						throw new InvalidOperationException($"[BlockMap] Failed to get Absolute URI from IUri object. HR: 0x{hr:X}");
					}
				}
				else
				{
					throw new InvalidOperationException($"[BlockMap] No HashMethod found (HR: 0x{hr:X}).");
				}
			}
			else
			{
				throw new InvalidOperationException($"[BlockMap] Failed to get BlockMapReader. HR: 0x{hr:X}");
			}

			return new PackageDetails(
				certCN: certificateCN,
				hashAlgorithm: hashingAlgo,
				packageFamilyName: packageFamilyName,
				version: version);
		}
		finally
		{
			// Release in reverse order of creation
			Release(pUri);
			Release(pBlockMapReader);
			Release(pPackageId);
			Release(pManifestReader);
			Release(pPackageReader);
			Release(pAppxFactory);
			Release(pStream);
		}
	}

	private unsafe static PackageDetails InspectBundle(string path)
	{
		int hr;

		// Initialize all pointers to Zero
		IntPtr pStream = IntPtr.Zero;
		IntPtr pBundleFactory = IntPtr.Zero;
		IntPtr pBundleReader = IntPtr.Zero;
		IntPtr pManifestReader = IntPtr.Zero;
		IntPtr pPackageId = IntPtr.Zero;
		IntPtr pBlockMapReader = IntPtr.Zero;
		IntPtr pUri = IntPtr.Zero;

		// Output values
		string certificateCN = string.Empty;
		HashAlgorithmName hashingAlgo = HashAlgorithmName.SHA256;
		string packageFamilyName = string.Empty;
		string version = string.Empty;

		try
		{
			// Create Stream
			fixed (char* pPath = path)
			{
				hr = NativeMethods.SHCreateStreamOnFileEx(
					(ushort*)pPath,
					0x00000000 | 0x00000020, // STGM_READ | STGM_SHARE_DENY_WRITE
					0,
					0,
					IntPtr.Zero,
					&pStream);
			}

			if (hr != 0) throw new InvalidOperationException($"Failed to create stream for bundle. HR: 0x{hr:X}");

			// Create IAppxBundleFactory

			// CLSID_AppxBundleFactory
			Guid clsid = new("378E0446-5384-43B7-8877-E7DBDD883446");
			// IID_IAppxBundleFactory
			Guid iid = new("BBA65864-965F-4A5F-855F-F074BDBF3A7B");

			hr = NativeMethods.CoCreateInstance(in clsid, IntPtr.Zero, 1, in iid, out pBundleFactory);
			if (hr != 0) throw new InvalidOperationException($"Failed to create AppxBundleFactory. HR: 0x{hr:X}");

			RawIAppxBundleFactory* factory = (RawIAppxBundleFactory*)pBundleFactory;

			// Create Bundle Reader
			hr = factory->Vtbl->CreateBundleReader((void*)pBundleFactory, pStream, &pBundleReader);
			if (hr != 0) throw new InvalidOperationException($"CreateBundleReader failed. HR: 0x{hr:X}");

			RawIAppxBundleReader* bundleReader = (RawIAppxBundleReader*)pBundleReader;

			// Get Bundle Manifest
			hr = bundleReader->Vtbl->GetManifest((void*)pBundleReader, &pManifestReader);
			if (hr != 0) throw new InvalidOperationException($"GetManifest (Bundle) failed. HR: 0x{hr:X}");

			RawIAppxBundleManifestReader* manifestReader = (RawIAppxBundleManifestReader*)pManifestReader;

			// Get PackageId - Bundle uses the same IAppxManifestPackageId interface
			hr = manifestReader->Vtbl->GetPackageId((void*)pManifestReader, &pPackageId);
			if (hr != 0) throw new InvalidOperationException($"GetPackageId (Bundle) failed. HR: 0x{hr:X}");

			RawIAppxManifestPackageId* packageId = (RawIAppxManifestPackageId*)pPackageId;

			// Get Publisher (for Common Name)
			ushort* pPublisherDn = null;
			hr = packageId->Vtbl->GetPublisher((void*)pPackageId, &pPublisherDn);

			if (hr == 0)
			{
				try
				{
					string publisherDn = new((char*)pPublisherDn);
					certificateCN = ParseCommonName(publisherDn);
				}
				finally
				{
					NativeMethods.CoTaskMemFree((IntPtr)pPublisherDn);
				}
			}
			else
			{
				throw new InvalidOperationException($"Failed to get Publisher from Bundle PackageId. HR: 0x{hr:X}");
			}

			// Get Package Family Name
			ushort* pPfn = null;
			hr = packageId->Vtbl->GetPackageFamilyName((void*)pPackageId, &pPfn);
			if (hr == 0)
			{
				try
				{
					packageFamilyName = new((char*)pPfn);
				}
				finally
				{
					NativeMethods.CoTaskMemFree((IntPtr)pPfn);
				}
			}
			else
			{
				throw new InvalidOperationException($"Failed to get PackageFamilyName from Bundle. HR: 0x{hr:X}");
			}

			// Get Version
			ulong versionNum = 0;
			hr = packageId->Vtbl->GetVersion((void*)pPackageId, &versionNum);

			version = hr == 0 ? ParseVersion(versionNum) : throw new InvalidOperationException($"Failed to get Version from Bundle. HR: 0x{hr:X}");

			// Get BlockMap (for Hashing Algorithm)
			// IAppxBundleReader::GetBlockMap returns IAppxBlockMapReader, same as package reader
			hr = bundleReader->Vtbl->GetBlockMap((void*)pBundleReader, &pBlockMapReader);

			if (hr == 0 && pBlockMapReader != IntPtr.Zero)
			{
				RawIAppxBlockMapReader* blockMapReader = (RawIAppxBlockMapReader*)pBlockMapReader;

				// Get HashMethod
				hr = blockMapReader->Vtbl->GetHashMethod((void*)pBlockMapReader, &pUri);

				if (hr == 0 && pUri != IntPtr.Zero)
				{
					RawIUri* uri = (RawIUri*)pUri;

					// Get Absolute URI
					ushort* pBstrUri = null;
					hr = uri->Vtbl->GetAbsoluteUri((void*)pUri, &pBstrUri);

					if (hr == 0)
					{
						try
						{
							string uriString = new((char*)pBstrUri);
							hashingAlgo = ParseHashAlg(uriString);
						}
						finally
						{
							NativeMethods.SysFreeString((IntPtr)pBstrUri);
						}
					}
					else
					{
						throw new InvalidOperationException($"[Bundle BlockMap] Failed to get Absolute URI from IUri object. HR: 0x{hr:X}");
					}
				}
				else
				{
					throw new InvalidOperationException($"[Bundle BlockMap] No HashMethod found (HR: 0x{hr:X}).");
				}
			}
			else
			{
				throw new InvalidOperationException($"[Bundle BlockMap] Failed to get BlockMapReader. HR: 0x{hr:X}");
			}

			return new PackageDetails(
				certCN: certificateCN,
				hashAlgorithm: hashingAlgo,
				packageFamilyName: packageFamilyName,
				version: version);
		}
		finally
		{
			// Release in reverse order
			Release(pUri);
			Release(pBlockMapReader);
			Release(pPackageId);
			Release(pManifestReader);
			Release(pBundleReader);
			Release(pBundleFactory);
			Release(pStream);
		}
	}

	private unsafe static void Release(IntPtr ptr)
	{
		if (ptr != IntPtr.Zero)
		{
			RawIUnknown* pUnk = (RawIUnknown*)ptr;
			_ = pUnk->Vtbl->Release((void*)ptr);
		}
	}

	private static string ParseCommonName(string dn)
	{
		if (string.IsNullOrWhiteSpace(dn))
			throw new ArgumentException("Distinguished Name is null or empty.", nameof(dn));

		string[] parts = dn.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

		foreach (string p in parts)
		{
			if (p.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
			{
				return p[3..].Trim('"');
			}
		}

		throw new InvalidOperationException("Common Name (CN) not found in Distinguished Name.");
	}

	private static HashAlgorithmName ParseHashAlg(string uri)
	{
		if (uri.EndsWith("sha256", StringComparison.OrdinalIgnoreCase)) return HashAlgorithmName.SHA256;
		if (uri.EndsWith("sha384", StringComparison.OrdinalIgnoreCase)) return HashAlgorithmName.SHA384;
		if (uri.EndsWith("sha512", StringComparison.OrdinalIgnoreCase)) return HashAlgorithmName.SHA512;
		if (uri.EndsWith("sha1", StringComparison.OrdinalIgnoreCase)) return HashAlgorithmName.SHA1;
		throw new InvalidOperationException($"{uri} is not valid hashing algorithm");
	}

	/// <summary>
	/// Converts the 64-bit version number into a dot-quad string (Major.Minor.Build.Revision).
	/// </summary>
	private static string ParseVersion(ulong version)
	{
		ushort major = (ushort)((version & 0xFFFF000000000000) >> 48);
		ushort minor = (ushort)((version & 0x0000FFFF00000000) >> 32);
		ushort build = (ushort)((version & 0x00000000FFFF0000) >> 16);
		ushort revision = (ushort)(version & 0x000000000000FFFF);

		return $"{major}.{minor}.{build}.{revision}";
	}
}
