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
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using Microsoft.Win32.SafeHandles;

namespace AppControlManager;

internal unsafe static partial class NativeMethods
{

	// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontextw
	[LibraryImport("advapi32.dll", EntryPoint = "CryptAcquireContextW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptAcquireContext(
			out IntPtr hProv,
			string? pszContainer,
			string? pszProvider,
			uint dwProvType,
			uint dwFlags);


	// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-cryptcreatehash
	[LibraryImport("advapi32.dll", EntryPoint = "CryptCreateHash", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptCreateHash(
		 IntPtr hProv,
		 uint Algid,
		 IntPtr hKey,
		 uint dwFlags,
		 out IntPtr phHash);


	// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-crypthashdata
	[LibraryImport("advapi32.dll", EntryPoint = "CryptHashData", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptHashData(
		 IntPtr hHash,
		 [In] byte[] pbData,
		 uint dataLen,
		 uint dwFlags);


	// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-cryptgethashparam
	[LibraryImport("advapi32.dll", EntryPoint = "CryptGetHashParam", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptGetHashParam(
		 IntPtr hHash,
		 uint dwParam,
		 [Out] byte[]? pbData,
		 ref uint pdwDataLen,
		 uint dwFlags);


	// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-cryptdestroyhash
	[LibraryImport("advapi32.dll", EntryPoint = "CryptDestroyHash", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptDestroyHash(IntPtr hHash);


	// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-cryptreleasecontext
	[LibraryImport("advapi32.dll", EntryPoint = "CryptReleaseContext", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptReleaseContext(IntPtr hProv, uint dwFlags);


	// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-findfirstvolumew
	[LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16, EntryPoint = "FindFirstVolumeW")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr FindFirstVolume(
		[MarshalUsing(CountElementName = "cchBufferLength")][Out] char[] lpszVolumeName,
		uint cchBufferLength);


	// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-findnextvolumew
	[LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16, EntryPoint = "FindNextVolumeW")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool FindNextVolume(
		IntPtr hFindVolume,
		[MarshalUsing(CountElementName = "cchBufferLength")][Out] char[] lpszVolumeName,
		uint cchBufferLength);


	// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-querydosdevicew
	[LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16, EntryPoint = "QueryDosDeviceW")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint QueryDosDevice(
		string lpDeviceName,
		[MarshalUsing(CountElementName = "ucchMax")][Out] char[] lpTargetPath,
		int ucchMax);


	// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getvolumepathnamesforvolumenamew
	[LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16, EntryPoint = "GetVolumePathNamesForVolumeNameW")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool GetVolumePathNamesForVolumeNameW(
		[MarshalAs(UnmanagedType.LPWStr)] string lpszVolumeName,
		[MarshalUsing(CountElementName = "cchBuferLength")][Out] char[] lpszVolumeNamePaths,
		uint cchBuferLength,
		ref uint lpcchReturnLength);


	// https://learn.microsoft.com/windows/win32/api/mssip/nf-mssip-cryptsipretrievesubjectguid
	[LibraryImport("crypt32.dll", EntryPoint = "CryptSIPRetrieveSubjectGuid", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptSIPRetrieveSubjectGuid(
		string FileName,
		IntPtr hFileIn,
		out Guid pgActionID);


	// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilew
	[LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr CreateFileW(
		string lpFileName,
		uint dwDesiredAccess,
		uint dwShareMode,
		IntPtr lpSecurityAttributes,
		uint dwCreationDisposition,
		uint dwFlagsAndAttributes,
		IntPtr hTemplateFile);


	// https://learn.microsoft.com/windows/win32/api/handleapi/nf-handleapi-closehandle
	[LibraryImport("kernel32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CloseHandle(IntPtr hObject);


	// https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-createfilemappinga
	[LibraryImport("kernel32.dll", EntryPoint = "CreateFileMappingW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr CreateFileMapping(
		IntPtr hFile,
		IntPtr pFileMappingAttributes,
		uint flProtect,
		uint dwMaximumSizeHigh,
		uint dwMaximumSizeLow,
		string lpName);


	// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getfilesize
	[LibraryImport("kernel32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint GetFileSize(IntPtr hFile, ref uint lpFileSizeHigh);


	// https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile
	[LibraryImport("kernel32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr MapViewOfFile(
		IntPtr hFileMappingObject,
		uint dwDesiredAccess,
		uint dwFileOffsetHigh,
		uint dwFileOffsetLow,
		IntPtr dwNumberOfBytesToMap);


	// https://learn.microsoft.com/windows/win32/api/dbghelp/nf-dbghelp-imagedirectoryentrytodataex
	[LibraryImport("DbgHelp.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr ImageDirectoryEntryToDataEx(
		IntPtr Base,
		int MappedAsImage,
		ushort DirectoryEntry,
		ref uint Size,
		ref IntPtr FoundHeader);


	// https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-unmapviewoffile
	[LibraryImport("kernel32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int UnmapViewOfFile(IntPtr lpBaseAddress);


	// https://learn.microsoft.com/windows/win32/api/dbghelp/nf-dbghelp-imagentheader
	[LibraryImport("DbgHelp.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr ImageNtHeader(IntPtr ImageBase);


	// https://learn.microsoft.com/windows/win32/api/dbghelp/nf-dbghelp-imagervatova
	[LibraryImport("DbgHelp.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr ImageRvaToVa(
		IntPtr NtHeaders,
		IntPtr Base,
		uint Rva,
		IntPtr LastRvaSection);


	// https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation#system_codeintegrity_information
	[LibraryImport("ntdll.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int NtQuerySystemInformation(
	int SystemInformationClass,
	IntPtr SystemInformation,
	int SystemInformationLength,
	ref int ReturnLength
	);


	// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilew
	[LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial SafeFileHandle CreateFile(
	 string lpFileName,
	 uint dwDesiredAccess,
	 uint dwShareMode,
	 IntPtr lpSecurityAttributes,
	 uint dwCreationDisposition,
	 uint dwFlagsAndAttributes,
	 IntPtr hTemplateFile);


	// Importing external functions from Version.dll to work with file version info
	// https://learn.microsoft.com/he-il/windows/win32/api/winver/nf-winver-getfileversioninfosizeexa
	[LibraryImport("Version.dll", EntryPoint = "GetFileVersionInfoSizeExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int GetFileVersionInfoSizeEx(uint dwFlags, string filename, out int handle);


	// https://learn.microsoft.com/he-il/windows/win32/api/winver/nf-winver-verqueryvaluea
	[LibraryImport("Version.dll", EntryPoint = "VerQueryValueW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool VerQueryValue(IntPtr block, string subBlock, out IntPtr buffer, out int len);


	// https://learn.microsoft.com/he-il/windows/win32/api/winver/nf-winver-getfileversioninfoexa
	[LibraryImport("Version.dll", EntryPoint = "GetFileVersionInfoExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool GetFileVersionInfoEx(uint dwFlags, string filename, int handle, int len, [Out] byte[] data);


	// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-cryptdecodeobject
	[LibraryImport("crypt32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptDecodeObject(
		uint dwCertEncodingType,        // Specifies the encoding type used in the encoded message
		IntPtr lpszStructType,          // Pointer to a null-terminated ANSI string that identifies the type of the structure to be decoded
		[In] byte[] pbEncoded,          // Pointer to a buffer that contains the encoded structure
		uint cbEncoded,                 // Size, in bytes, of the pbEncoded buffer
		uint dwFlags,                   // Flags that modify the behavior of the function
		IntPtr pvStructInto,            // Pointer to a buffer that receives the decoded structure
		ref uint pcbStructInfo          // Pointer to a variable that specifies the size, in bytes, of the pvStructInfo buffer
	);


	// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-certgetnamestringw
	[LibraryImport("crypt32.dll", EntryPoint = "CertGetNameStringW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int CertGetNameString(
		IntPtr pCertContext, // The handle property of the certificate object
		int dwType,
		int dwFlags,
		IntPtr pvTypePara,
		[Out] char[] pszNameString,
		int cchNameString
	);


	// https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-openscmanagerw
	[LibraryImport("advapi32.dll", EntryPoint = "OpenSCManagerW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr OpenSCManager(
		   string? lpMachineName,
		   string? lpDatabaseName,
		   uint dwDesiredAccess
	);


	// https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-openservicew
	[LibraryImport("advapi32.dll", EntryPoint = "OpenServiceW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr OpenService(
		IntPtr hSCManager,
		string lpServiceName,
		uint dwDesiredAccess
	);


	// https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-changeserviceconfigw
	[LibraryImport("advapi32.dll", EntryPoint = "ChangeServiceConfigW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool ChangeServiceConfig(
		IntPtr hService,
		uint dwServiceType,
		uint dwStartType,
		uint dwErrorControl,
		string? lpBinaryPathName,
		string? lpLoadOrderGroup,
		IntPtr lpdwTagId,
		[In] string[]? lpDependencies,
		string? lpServiceStartName,
		string? lpPassword,
		string? lpDisplayName
	);


	// https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-closeservicehandle
	[LibraryImport("advapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CloseServiceHandle(
		IntPtr hSCObject
	);


	// https://learn.microsoft.com//windows/win32/api/winreg/nf-winreg-regnotifychangekeyvalue
	[LibraryImport("advapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int RegNotifyChangeKeyValue(
		SafeRegistryHandle hKey,
		[MarshalAs(UnmanagedType.Bool)] bool watchSubtree,
		Others.EventLogUtility.RegNotifyFilter notifyFilter,
		IntPtr hEvent,
		[MarshalAs(UnmanagedType.Bool)] bool asynchronous);


	[LibraryImport("crypt32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptSignMessage(
		IntPtr pSignPara,
		[MarshalAs(UnmanagedType.Bool)] bool fDetachedSignature,
		uint cToBeSigned,
		[In] IntPtr[] rgpbToBeSigned,
		[In] uint[] rgcbToBeSigned,
		IntPtr pbSignedBlob,
		ref uint pcbSignedBlob);


	[LibraryImport("Mssign32.dll", EntryPoint = "SignerSignEx3", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int SignerSignEx3(
	uint dwFlags,
	IntPtr pSubjectInfo,
	IntPtr pSigningCert,
	IntPtr pSignatureInfo,
	IntPtr pProviderInfo,
	uint dwTimestampFlags,
	[MarshalAs(UnmanagedType.LPStr)] string? pszTimestampAlgorithmOid,
	[MarshalAs(UnmanagedType.LPWStr)] string? pwszHttpTimeStamp,
	IntPtr psRequest,
	IntPtr pSipData,
	IntPtr ppSignerContext,
	IntPtr pCryptoPolicy,
	IntPtr pSignEx3Params,
	IntPtr ppReserved);


	[LibraryImport("Mssign32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int SignerFreeSignerContext(IntPtr pSignerContext);


	// P/Invoke declaration to import the 'BCryptOpenAlgorithmProvider' function from 'bcrypt.dll'.
	// https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider
	[LibraryImport("bcrypt.dll", EntryPoint = "BCryptOpenAlgorithmProvider", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BCryptOpenAlgorithmProvider(
	out IntPtr phAlgorithm, // Output parameter to receive the handle of the cryptographic algorithm.
	string pszAlgId, // The algorithm identifier (e.g., AES, SHA256, etc.).
	string? pszImplementation, // The implementation name (null for default).
	uint dwFlags); // Flags to control the function behavior.


	// P/Invoke declaration to import the 'BCryptCloseAlgorithmProvider' function from 'bcrypt.dll'.
	// Releases the algorithm handle acquired by 'BCryptOpenAlgorithmProvider'.
	// https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptclosealgorithmprovider
	[LibraryImport("bcrypt.dll", EntryPoint = "BCryptCloseAlgorithmProvider", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);


	// External method declaration for CryptMsgGetParam
	[LibraryImport("crypt32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-cryptmsggetparam
	internal static partial bool CryptMsgGetParam(
		IntPtr hCryptMsg,
		int dwParamType,
		int dwIndex,
		[Out] byte[]? pvData, // pvData is populated by CryptMsgGetParam with data from the cryptographic message
		ref int pcbData
	);


	#region This section is related to the MeowParser class operations

	// P/Invoke declaration to import the 'CryptCATOpen' function from WinTrust.dll
	// https://learn.microsoft.com/windows/win32/api/mscat/nf-mscat-cryptcatopen
	[LibraryImport("WinTrust.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr CryptCATOpen(
		[MarshalAs(UnmanagedType.LPWStr)] string FileName, // The name of the catalog file.
		uint OpenFlags, // Flags to control the function behavior.
		IntPtr MainCryptProviderHandle, // Handle to the cryptographic service provider.
		uint PublicVersion, // The public version number.
		uint EncodingType); // The encoding type.


	// P/Invoke declaration to import the 'CryptCATEnumerateMember' function from WinTrust.dll
	// https://learn.microsoft.com/windows/win32/api/mscat/nf-mscat-cryptcatenumeratemember
	[LibraryImport("WinTrust.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr CryptCATEnumerateMember(
		IntPtr MeowLogHandle, // Handle to the catalog context.
		IntPtr PrevCatalogMember); // Pointer to the previous catalog member.


	// P/Invoke declaration to import the 'CryptCATClose' function from WinTrust.dll
	// https://learn.microsoft.com/windows/win32/api/mscat/nf-mscat-cryptcatclose
	[LibraryImport("WinTrust.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr CryptCATClose(IntPtr MainCryptProviderHandle); // Closes the catalog context.

	#endregion


	#region necessary logics for Authenticode and First Page hash calculation

	// Acquire a handle to a catalog administrator context using a native function from WinTrust.dll
	[LibraryImport("WinTrust.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptCATAdminAcquireContext2(
		ref IntPtr hCatAdmin, // the first parameter: a reference to a pointer to store the handle
		IntPtr pgSubsystem, // the second parameter: a pointer to a GUID that identifies the subsystem
		string pwszHashAlgorithm, // the third parameter: a string that specifies the hash algorithm to use
		IntPtr pStrongHashPolicy, // the fourth parameter: a pointer to a structure that specifies the strong hash policy
		uint dwFlags // the fifth parameter: a flag value that controls the behavior of the function
	);


	// Release a handle to a catalog administrator context using a native function from WinTrust.dll
	[LibraryImport("WinTrust.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptCATAdminReleaseContext(
		IntPtr hCatAdmin, // the first parameter: a pointer to the handle to release
		uint dwFlags // the second parameter: a flag value that controls the behavior of the function
	);

	// Calculate the hash of a file using a native function from WinTrust.dll
	[LibraryImport("WinTrust.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptCATAdminCalcHashFromFileHandle3(
		IntPtr hCatAdmin, // the first parameter: a pointer to the handle of the catalog administrator context
		IntPtr hFile, // the second parameter: a pointer to the handle of the file to hash
		ref int pcbHash, // the third parameter: a reference to an integer that specifies the size of the hash buffer
		IntPtr pbHash, // the fourth parameter: a pointer to a buffer to store the hash value
		uint dwFlags // the fifth parameter: a flag value that controls the behavior of the function
	);

	#endregion


	#region This section is related to the PageHashCalculator class

	// Compute the hash of the first page of a file using a native function from Wintrust.dll
	[LibraryImport("Wintrust.dll", StringMarshalling = StringMarshalling.Utf16)] // an attribute to specify the DLL name and the character set
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int ComputeFirstPageHash( // the method signature
		string pszAlgId, // the first parameter: the name of the hash algorithm to use
		string filename, // the second parameter: the name of the file to hash
		IntPtr buffer, // the third parameter: a pointer to a buffer to store the hash value
		int bufferSize // the fourth parameter: the size of the buffer in bytes
	);

	#endregion

	/// <summary>
	/// Enum defining WinVerifyTrust results
	/// </summary>
	internal enum WinVerifyTrustResult : uint
	{
		Success = 0, // It's Success
		SubjectCertificateRevoked = 2148204812, // Subject's certificate was revoked. (CERT_E_REVOKED)
		SubjectNotTrusted = 2148204548, // Subject failed the specified verification action
		CertExpired = 2148204801, // This is checked for - Signer's certificate was expired. (CERT_E_EXPIRED)
		UntrustedRootCert = 2148204809, // A certification chain processed correctly but terminated in a root certificate that is not trusted by the trust provider. (CERT_E_UNTRUSTEDROOT)
		HashMismatch = 2148098064, // This is checked for (aka: SignatureOrFileCorrupt) - (TRUST_E_BAD_DIGEST)
		ProviderUnknown = 2148204545, // Trust provider is not recognized on this system
		ActionUnknown = 2148204546, // Trust provider does not support the specified action
		SubjectFormUnknown = 2148204547, // Trust provider does not support the subject's form
		FileNotSigned = 2148204800, // File is not signed. (TRUST_E_NOSIGNATURE)
		SubjectExplicitlyDistrusted = 2148204817, // Signer's certificate is in the Untrusted Publishers store
	}

	// https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-winverifytrust
	[LibraryImport("wintrust.dll", EntryPoint = "WinVerifyTrust")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	// Set to return a WinVerifyTrustResult enum
	internal static partial WinVerifyTrustResult WinVerifyTrust(
		IntPtr hwnd,
		ref Guid pgActionID,
		IntPtr pWVTData);


	// https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-wthelperprovdatafromstatedata
	[LibraryImport("wintrust.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);


	#region for WLDP - Windows Lockdown Policy

	/// <summary>
	/// Defines different types of secure setting values used in WLDP. Types include Boolean, Integer, None, String, and
	/// Flag.
	/// </summary>
	internal enum WLDP_SECURE_SETTING_VALUE_TYPE
	{
		WldpBoolean = 0,
		WldpInteger = 1,
		WldpNone = 2,
		WldpString = 3,
		WldpFlag = 4
	}

	/// <summary>
	/// Represents a Unicode string with a specified length and a pointer to the string's buffer. It includes fields for the
	/// string's current length and maximum length.
	/// </summary>
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	internal struct UNICODE_STRING
	{
		internal ushort Length;
		internal ushort MaximumLength;
		internal IntPtr Buffer;
	}

	/// <summary>
	/// Queries the security policy for a specified provider and key, returning the value type and size.
	/// Initializes a UNICODE_STRING structure from a given string.
	/// </summary>
	[LibraryImport("Wldp.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int WldpQuerySecurityPolicy(
	ref UNICODE_STRING Provider,
	ref UNICODE_STRING Key,
	ref UNICODE_STRING ValueName,
	out WLDP_SECURE_SETTING_VALUE_TYPE ValueType,
	IntPtr Value,
	ref uint ValueSize);

	internal static UNICODE_STRING InitUnicodeString(string s)
	{
		UNICODE_STRING us;
		us.Length = (ushort)(s.Length * 2);
		us.MaximumLength = (ushort)((s.Length * 2) + 2);
		us.Buffer = Marshal.StringToHGlobalUni(s);
		return us;
	}

	#endregion


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-setwindowdisplayaffinity
	/// </summary>
	/// <param name="hWnd"></param>
	/// <param name="dwAffinity"></param>
	/// <returns></returns>
	[LibraryImport("user32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool SetWindowDisplayAffinity(IntPtr hWnd, uint dwAffinity);


	/// <summary>
	/// Import GetLastError to get detailed error information
	/// </summary>
	/// <returns></returns>
	[LibraryImport("kernel32.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint GetLastError();


	// https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-getwindowplacement
	[LibraryImport("user32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool GetWindowPlacement(IntPtr hWnd, ref Others.Win32InteropInternal.WINDOWPLACEMENT lpwndpl);


	// https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptgetproperty
	[LibraryImport("bcrypt.dll", EntryPoint = "BCryptGetProperty", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BCryptGetProperty(
		IntPtr hObject,
		string pszProperty,
		IntPtr pbOutput,
		uint cbOutput,
		out uint pcbResult,
		uint dwFlags);


	// https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptcreatehash
	[LibraryImport("bcrypt.dll", EntryPoint = "BCryptCreateHash", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BCryptCreateHash(
		IntPtr hAlgorithm,
		out IntPtr phHash,
		IntPtr pbHashObject,
		uint cbHashObject,
		IntPtr pbSecret,
		uint cbSecret,
		uint dwFlags);


	// https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcrypthashdata
	[LibraryImport("bcrypt.dll", EntryPoint = "BCryptHashData", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BCryptHashData(
		IntPtr hHash,
		[In] byte[] pbInput,
		uint cbInput,
		uint dwFlags);


	// https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptfinishhash
	[LibraryImport("bcrypt.dll", EntryPoint = "BCryptFinishHash", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BCryptFinishHash(
		IntPtr hHash,
		IntPtr pbOutput,
		uint cbOutput,
		uint dwFlags);


	// https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptdestroyhash
	[LibraryImport("bcrypt.dll", EntryPoint = "BCryptDestroyHash", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BCryptDestroyHash(IntPtr hHash);


	[LibraryImport("user32.dll", EntryPoint = "SetWindowLongPtrW")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr SetWindowLongPtr(IntPtr hWnd, int nIndex, nint newProc);

	[LibraryImport("user32.dll", EntryPoint = "GetWindowLongPtrW")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr GetWindowLongPtr(IntPtr hWnd, int nIndex);

}
