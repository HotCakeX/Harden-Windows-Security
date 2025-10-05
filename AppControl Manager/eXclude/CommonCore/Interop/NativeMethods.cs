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

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using Microsoft.Win32.SafeHandles;

namespace CommonCore.Interop;

internal static unsafe partial class NativeMethods
{

	internal static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontextw
	/// </summary>
	[LibraryImport("ADVAPI32", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptAcquireContextW(
			out IntPtr hProv,
			string? pszContainer,
			string? pszProvider,
			uint dwProvType,
			uint dwFlags);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-cryptcreatehash
	/// </summary>
	[LibraryImport("ADVAPI32")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptCreateHash(
		 IntPtr hProv,
		 uint Algid,
		 IntPtr hKey,
		 uint dwFlags,
		 out IntPtr phHash);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-crypthashdata
	/// </summary>
	[LibraryImport("ADVAPI32")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptHashData(
		 IntPtr hHash,
		 [In] byte[] pbData,
		 uint dataLen,
		 uint dwFlags);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-cryptgethashparam
	/// </summary>
	[LibraryImport("ADVAPI32")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptGetHashParam(
		 IntPtr hHash,
		 uint dwParam,
		 [Out] byte[]? pbData,
		 ref uint pdwDataLen,
		 uint dwFlags);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-cryptdestroyhash
	/// </summary>
	[LibraryImport("ADVAPI32")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptDestroyHash(IntPtr hHash);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-cryptreleasecontext
	/// </summary>
	[LibraryImport("ADVAPI32")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptReleaseContext(IntPtr hProv, uint dwFlags);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-findfirstvolumew
	/// </summary>
	[LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr FindFirstVolumeW(
		[MarshalUsing(CountElementName = "cchBufferLength")][Out] char[] lpszVolumeName,
		uint cchBufferLength);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-findnextvolumew
	/// </summary>
	[LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool FindNextVolumeW(
		IntPtr hFindVolume,
		[MarshalUsing(CountElementName = "cchBufferLength")][Out] char[] lpszVolumeName,
		uint cchBufferLength);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-findvolumeclose
	/// </summary>
	[LibraryImport("kernel32.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool FindVolumeClose(IntPtr hFindVolume);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-querydosdevicew
	/// </summary>
	[LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint QueryDosDeviceW(
		string lpDeviceName,
		[MarshalUsing(CountElementName = "ucchMax")][Out] char[] lpTargetPath,
		int ucchMax);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getvolumepathnamesforvolumenamew
	/// </summary>
	[LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool GetVolumePathNamesForVolumeNameW(
		[MarshalAs(UnmanagedType.LPWStr)] string lpszVolumeName,
		[MarshalUsing(CountElementName = "cchBufferLength")][Out] char[] lpszVolumeNamePaths,
		uint cchBufferLength,
		ref uint lpcchReturnLength);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/mssip/nf-mssip-cryptsipretrievesubjectguid
	/// </summary>
	[LibraryImport("crypt32.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptSIPRetrieveSubjectGuid(
		string FileName,
		IntPtr hFileIn,
		out Guid pgActionID);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilew
	/// </summary>
	[LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr CreateFileW(
		string lpFileName,
		uint dwDesiredAccess,
		uint dwShareMode,
		IntPtr lpSecurityAttributes,
		uint dwCreationDisposition,
		uint dwFlagsAndAttributes,
		IntPtr hTemplateFile);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/handleapi/nf-handleapi-closehandle
	/// </summary>
	[LibraryImport("kernel32.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CloseHandle(IntPtr hObject);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-createfilemappinga
	/// </summary>
	[LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr CreateFileMappingW(
		IntPtr hFile,
		IntPtr pFileMappingAttributes,
		uint flProtect,
		uint dwMaximumSizeHigh,
		uint dwMaximumSizeLow,
		string lpName);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getfilesize
	/// </summary>
	[LibraryImport("kernel32.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint GetFileSize(IntPtr hFile, ref uint lpFileSizeHigh);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile
	/// </summary>
	[LibraryImport("kernel32.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr MapViewOfFile(
		IntPtr hFileMappingObject,
		uint dwDesiredAccess,
		uint dwFileOffsetHigh,
		uint dwFileOffsetLow,
		IntPtr dwNumberOfBytesToMap);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/dbghelp/nf-dbghelp-imagedirectoryentrytodataex
	/// </summary>
	[LibraryImport("DbgHelp.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr ImageDirectoryEntryToDataEx(
		IntPtr Base,
		int MappedAsImage,
		ushort DirectoryEntry,
		ref uint Size,
		ref IntPtr FoundHeader);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-unmapviewoffile
	/// </summary>
	[LibraryImport("kernel32.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int UnmapViewOfFile(IntPtr lpBaseAddress);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/dbghelp/nf-dbghelp-imagentheader
	/// </summary>
	[LibraryImport("DbgHelp.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr ImageNtHeader(IntPtr ImageBase);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/dbghelp/nf-dbghelp-imagervatova
	/// </summary>
	[LibraryImport("DbgHelp.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr ImageRvaToVa(
		IntPtr NtHeaders,
		IntPtr Base,
		uint Rva,
		IntPtr LastRvaSection);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation#system_codeintegrity_information
	/// </summary>
	[LibraryImport("ntdll.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int NtQuerySystemInformation(
	int SystemInformationClass,
	IntPtr SystemInformation,
	int SystemInformationLength,
	ref int ReturnLength
	);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilew
	/// </summary>
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


	/// <summary>
	/// https://learn.microsoft.com/he-il/windows/win32/api/winver/nf-winver-getfileversioninfosizeexa
	/// </summary>
	[LibraryImport("Version.dll", EntryPoint = "GetFileVersionInfoSizeExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int GetFileVersionInfoSizeEx(uint dwFlags, string filename, out int handle);


	/// <summary>
	/// https://learn.microsoft.com/he-il/windows/win32/api/winver/nf-winver-verqueryvaluea
	/// </summary>
	[LibraryImport("Version.dll", EntryPoint = "VerQueryValueW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool VerQueryValue(IntPtr block, string subBlock, out IntPtr buffer, out int len);


	/// <summary>
	/// https://learn.microsoft.com/he-il/windows/win32/api/winver/nf-winver-getfileversioninfoexa
	/// </summary>
	[LibraryImport("Version.dll", EntryPoint = "GetFileVersionInfoExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool GetFileVersionInfoEx(uint dwFlags, string filename, int handle, int len, [Out] byte[] data);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-cryptdecodeobject
	/// </summary>
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


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-certgetnamestringw
	/// </summary>
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


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-openscmanagerw
	/// </summary>
	[LibraryImport("ADVAPI32", EntryPoint = "OpenSCManagerW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr OpenSCManager(
		   string? lpMachineName,
		   string? lpDatabaseName,
		   uint dwDesiredAccess
	);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-openservicew
	/// </summary>
	[LibraryImport("ADVAPI32", EntryPoint = "OpenServiceW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr OpenService(
		IntPtr hSCManager,
		string lpServiceName,
		uint dwDesiredAccess
	);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-changeserviceconfigw
	/// </summary>
	[LibraryImport("ADVAPI32", EntryPoint = "ChangeServiceConfigW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
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


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-closeservicehandle
	/// </summary>
	[LibraryImport("ADVAPI32", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CloseServiceHandle(
		IntPtr hSCObject
	);


	/// <summary>
	/// https://learn.microsoft.com//windows/win32/api/winreg/nf-winreg-regnotifychangekeyvalue
	/// </summary>
	[LibraryImport("ADVAPI32", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int RegNotifyChangeKeyValue(
		SafeRegistryHandle hKey,
		[MarshalAs(UnmanagedType.Bool)] bool watchSubtree,
		RegNotifyFilter notifyFilter,
		IntPtr hEvent,
		[MarshalAs(UnmanagedType.Bool)] bool asynchronous);


	/// <summary> 
	/// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-cryptsignmessage
	/// </summary>
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


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/seccrypto/signersignex3
	/// </summary>
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


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/seccrypto/signerfreesignercontext
	/// </summary>
	[LibraryImport("Mssign32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int SignerFreeSignerContext(IntPtr pSignerContext);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider
	/// </summary>
	[LibraryImport("bcrypt.dll", EntryPoint = "BCryptOpenAlgorithmProvider", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BCryptOpenAlgorithmProvider(
	out IntPtr phAlgorithm, // Output parameter to receive the handle of the cryptographic algorithm.
	string pszAlgId, // The algorithm identifier (e.g., AES, SHA256, etc.).
	string? pszImplementation, // The implementation name (null for default).
	uint dwFlags); // Flags to control the function behavior.


	/// <summary>
	/// Releases the algorithm handle acquired by 'BCryptOpenAlgorithmProvider'.
	/// https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptclosealgorithmprovider
	/// </summary>
	[LibraryImport("bcrypt.dll", EntryPoint = "BCryptCloseAlgorithmProvider", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-cryptmsggetparam
	/// </summary>
	[LibraryImport("crypt32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptMsgGetParam(
		IntPtr hCryptMsg,
		int dwParamType,
		int dwIndex,
		[Out] byte[]? pvData, // pvData is populated by CryptMsgGetParam with data from the cryptographic message
		ref int pcbData
	);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/mscat/nf-mscat-cryptcatopen
	/// </summary>
	[LibraryImport("WinTrust.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr CryptCATOpen(
		[MarshalAs(UnmanagedType.LPWStr)] string FileName, // The name of the catalog file.
		uint OpenFlags, // Flags to control the function behavior.
		IntPtr MainCryptProviderHandle, // Handle to the cryptographic service provider.
		uint PublicVersion, // The public version number.
		uint EncodingType); // The encoding type.


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/mscat/nf-mscat-cryptcatenumeratemember
	/// </summary>
	[LibraryImport("WinTrust.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr CryptCATEnumerateMember(
		IntPtr MeowLogHandle, // Handle to the catalog context.
		IntPtr PrevCatalogMember); // Pointer to the previous catalog member.


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/mscat/nf-mscat-cryptcatclose
	/// </summary>
	[LibraryImport("WinTrust.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr CryptCATClose(IntPtr MainCryptProviderHandle); // Closes the catalog context.


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/mscat/nf-mscat-cryptcatadminacquirecontext2
	/// </summary>
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


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/mscat/nf-mscat-cryptcatadminreleasecontext
	/// </summary>
	[LibraryImport("WinTrust.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CryptCATAdminReleaseContext(
		IntPtr hCatAdmin, // the first parameter: a pointer to the handle to release
		uint dwFlags // the second parameter: a flag value that controls the behavior of the function
	);


	/// <summary>
	/// Calculate the hash of a file using a native function from WinTrust.dll
	/// </summary>
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


	/// <summary>
	/// Compute the hash of the first page of a file using a native function from Wintrust.dll
	/// </summary>
	[LibraryImport("Wintrust.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int ComputeFirstPageHash( // the method signature
		string pszAlgId, // the first parameter: the name of the hash algorithm to use
		string filename, // the second parameter: the name of the file to hash
		IntPtr buffer, // the third parameter: a pointer to a buffer to store the hash value
		int bufferSize // the fourth parameter: the size of the buffer in bytes
	);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-winverifytrust
	/// </summary>
	[LibraryImport("wintrust.dll", EntryPoint = "WinVerifyTrust")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial WinVerifyTrustResult WinVerifyTrust(
		IntPtr hwnd,
		ref Guid pgActionID,
		IntPtr pWVTData);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-wthelperprovdatafromstatedata
	/// </summary>
	[LibraryImport("wintrust.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);


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

	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-setwindowdisplayaffinity
	/// </summary>
	[LibraryImport("USER32", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool SetWindowDisplayAffinity(IntPtr hWnd, uint dwAffinity);

	[LibraryImport("USER32", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool GetWindowDisplayAffinity(IntPtr hwnd, out uint affinity);

	/// <summary>
	/// Import GetLastError to get detailed error information. A replacement for "Marshal.GetLastWin32Error()" method that relies on Runtime Marshaling.
	/// Should be called immediately after the native P/Invoke method call. Shouldn't be called part of a "string.format" or anything else. Its output must be immedaitely saved in a local variable.
	/// </summary>
	/// <returns></returns>
	[LibraryImport("kernel32.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint GetLastError();


	/// <summary>
	/// Import GetLastError to get detailed error information. A replacement for "Marshal.GetLastWin32Error()" method that relies on Runtime Marshaling.
	/// Should be called immediately after the native P/Invoke method call. Shouldn't be called part of a "string.format" or anything else. Its output must be immedaitely saved in a local variable.
	/// </summary>
	/// <returns></returns>
	[LibraryImport("kernel32.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint GetLastError();


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-getwindowplacement
	/// </summary>
	[LibraryImport("USER32", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool GetWindowPlacement(IntPtr hWnd, ref WINDOWPLACEMENT lpwndpl);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptgetproperty
	/// </summary>
	[LibraryImport("bcrypt.dll", EntryPoint = "BCryptGetProperty", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BCryptGetProperty(
		IntPtr hObject,
		string pszProperty,
		IntPtr pbOutput,
		uint cbOutput,
		out uint pcbResult,
		uint dwFlags);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptcreatehash
	/// </summary>
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


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcrypthashdata
	/// </summary>
	[LibraryImport("bcrypt.dll", EntryPoint = "BCryptHashData", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BCryptHashData(
		IntPtr hHash,
		[In] byte[] pbInput,
		uint cbInput,
		uint dwFlags);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptfinishhash
	/// </summary>
	[LibraryImport("bcrypt.dll", EntryPoint = "BCryptFinishHash", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BCryptFinishHash(
		IntPtr hHash,
		IntPtr pbOutput,
		uint cbOutput,
		uint dwFlags);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptdestroyhash
	/// </summary>
	[LibraryImport("bcrypt.dll", EntryPoint = "BCryptDestroyHash", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BCryptDestroyHash(IntPtr hHash);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-setwindowlongptrw
	/// </summary>
	[LibraryImport("USER32", EntryPoint = "SetWindowLongPtrW")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr SetWindowLongPtr(IntPtr hWnd, int nIndex, nint newProc);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-getwindowlongptrw
	/// </summary>
	[LibraryImport("USER32", EntryPoint = "GetWindowLongPtrW")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr GetWindowLongPtr(IntPtr hWnd, int nIndex);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/dwmapi/nf-dwmapi-dwmsetwindowattribute
	/// </summary>
	[LibraryImport("dwmapi.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int DwmSetWindowAttribute(IntPtr hwnd, int dwAttribute, ref uint pvAttribute, int cbAttribute);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-getphysicallyinstalledsystemmemory
	/// </summary>
	[LibraryImport("kernel32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool GetPhysicallyInstalledSystemMemory(out ulong totalMemoryKilobytes);



	[LibraryImport("kernel32.dll", EntryPoint = "K32GetProcessMemoryInfo", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool K32GetProcessMemoryInfo_Native(IntPtr hProcess, ref PROCESS_MEMORY_COUNTERS_EX2 counters, uint size);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
	/// </summary>
	[LibraryImport("kernel32.dll", EntryPoint = "GetCurrentProcess")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr GetCurrentProcess_Pseudo();


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/iphlpapi/nf-iphlpapi-getbestinterface
	/// </summary>
	/// <returns>Returns NO_ERROR (0) on success</returns>
	[LibraryImport("Iphlpapi.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint GetBestInterface(uint dwDestAddr, out uint pdwBestIfIndex);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/iphlpapi/nf-iphlpapi-getifentry
	/// </summary>
	/// <returns>NO_ERROR (0) on success</returns>
	[LibraryImport("Iphlpapi.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint GetIfEntry(ref MIB_IFROW pIfRow);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath
	/// </summary>
	[LibraryImport("shell32.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int SHGetKnownFolderPath(
	ref Guid rfid, uint dwFlags, IntPtr hToken, out IntPtr ppszPath);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/userenv/nf-userenv-refreshpolicyex
	/// </summary>
	[LibraryImport("userenv.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool RefreshPolicyEx([MarshalAs(UnmanagedType.Bool)] bool bMachine, uint dwOptions);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/lmaccess/nf-lmaccess-netusermodalsget
	/// </summary>
	[LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint NetUserModalsGet(
		string? servername,
		int level,
		out IntPtr bufptr
	);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/lmaccess/nf-lmaccess-netusermodalsset
	/// </summary>
	[LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint NetUserModalsSet(
		string? servername,
		int level,
		IntPtr bufptr,
		out uint parm_err
	);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/lmapibuf/nf-lmapibuf-netapibufferfree
	/// </summary>
	[LibraryImport("netapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int NetApiBufferFree(IntPtr Buffer);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/lmapibuf/nf-lmapibuf-netapibufferallocate
	/// </summary>
	[LibraryImport("netapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint NetApiBufferAllocate(
		uint ByteCount,
		out IntPtr Buffer
	);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-lsaopenpolicy
	/// </summary>
	[LibraryImport("ADVAPI32", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint LsaOpenPolicy(
		ref LSA_UNICODE_STRING SystemName,
		ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
		int DesiredAccess,
		out IntPtr PolicyHandle
	);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-lsaenumerateaccountswithuserright
	/// </summary>
	[LibraryImport("ADVAPI32", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint LsaEnumerateAccountsWithUserRight(
		IntPtr PolicyHandle,
		ref LSA_UNICODE_STRING UserRight,
		out IntPtr EnumerationBuffer,
		out int CountReturned
	);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-lsaclose
	/// </summary>
	[LibraryImport("ADVAPI32", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int LsaClose(IntPtr PolicyHandle);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-lsafreememory
	/// </summary>
	[LibraryImport("ADVAPI32", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int LsaFreeMemory(IntPtr Buffer);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-lsaqueryinformationpolicy
	/// </summary>
	[LibraryImport("ADVAPI32", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint LsaQueryInformationPolicy(
		IntPtr PolicyHandle,
		int InformationClass,
		out IntPtr Buffer
	);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditenumeratecategories
	/// </summary>
	[LibraryImport("ADVAPI32", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool AuditEnumerateCategories(
		out IntPtr ppAuditCategoriesArray,
		out uint pCountReturned
	);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditenumeratesubcategories
	/// </summary>
	[LibraryImport("ADVAPI32", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool AuditEnumerateSubCategories(
		IntPtr pAuditCategoryGuid,
		[MarshalAs(UnmanagedType.Bool)] bool bRetrieveAllSubCategories,
		out IntPtr ppAuditSubCategoriesArray,
		out uint pCountReturned
	);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy
	/// </summary>
	[LibraryImport("ADVAPI32", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool AuditQuerySystemPolicy(
		IntPtr pSubCategoryGuids,
		uint PolicyCount,
		out IntPtr ppAuditPolicy
	);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditfree
	/// </summary>
	[LibraryImport("ADVAPI32", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial void AuditFree(IntPtr Buffer);


	[LibraryImport("samlib.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint SamConnect(
		ref LSA_UNICODE_STRING ServerName,
		out IntPtr ServerHandle,
		uint DesiredAccess,
		IntPtr ObjectAttributes
	);


	[LibraryImport("samlib.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint SamOpenDomain(
		IntPtr ServerHandle,
		uint DesiredAccess,
		IntPtr DomainId,
		out IntPtr DomainHandle
	);


	[LibraryImport("samlib.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint SamQueryInformationDomain(
		IntPtr DomainHandle,
		int DomainInformationClass,
		out IntPtr Buffer
	);


	[LibraryImport("samlib.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint SamCloseHandle(IntPtr SamHandle);


	[LibraryImport("samlib.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint SamFreeMemory(IntPtr Buffer);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/lmaccess/nf-lmaccess-netusergetinfo
	/// </summary>
	[LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint NetUserGetInfo(
		string? servername,
		string username,
		uint level,
		out IntPtr bufptr
	);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-lsalookupauthenticationpackage
	/// </summary>
	[LibraryImport("secur32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint LsaLookupAuthenticationPackage(
		IntPtr LsaHandle,
		ref LSA_STRING PackageName,
		out uint AuthenticationPackage
	);


	[LibraryImport("samlib.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint SamOpenUser(
	IntPtr DomainHandle,
	uint DesiredAccess,
	uint UserId,
	out IntPtr UserHandle
	);


	[LibraryImport("samlib.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint SamQueryInformationUser(
		IntPtr UserHandle,
		int UserInformationClass,
		out IntPtr Buffer
	);


	[LibraryImport("bcd.dll", EntryPoint = "BcdOpenSystemStore", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BcdOpenSystemStore(out IntPtr storeHandle);


	[LibraryImport("bcd.dll", EntryPoint = "BcdCloseStore", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BcdCloseStore(IntPtr storeHandle);


	[LibraryImport("bcd.dll", EntryPoint = "BcdOpenObject", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BcdOpenObject(IntPtr storeHandle, ref Guid identifier, out IntPtr objectHandle);


	[LibraryImport("bcd.dll", EntryPoint = "BcdCloseObject", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BcdCloseObject(IntPtr objectHandle);


	[LibraryImport("bcd.dll", EntryPoint = "BcdSetElementDataWithFlags", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BcdSetElementDataWithFlags(
		IntPtr objectHandle,
		uint elementType,
		uint flags,
		IntPtr data,
		uint dataSize);


	[LibraryImport("bcd.dll", EntryPoint = "BcdGetElementDataWithFlags", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int BcdGetElementDataWithFlags(
		IntPtr objectHandle,
		uint elementType,
		uint flags,
		IntPtr data,
		ref uint dataSize);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-rtlntstatustodoserror
	/// </summary>
	[LibraryImport("ntdll.dll", EntryPoint = "RtlNtStatusToDosErrorW")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int RtlNtStatusToDosError(int ntStatus);


	[LibraryImport("ntdll.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int RtlQueryImageMitigationPolicy(
	string? imagePath,
	IMAGE_MITIGATION_POLICY policy,
	uint Flags,
	IntPtr buffer,
	uint bufferSize);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/debug/rtlsetimagemitigationpolicy-function
	/// </summary>
	[LibraryImport("ntdll.dll", EntryPoint = "RtlSetImageMitigationPolicy", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int RtlSetImageMitigationPolicy(
	  string? imagePath,
	  IMAGE_MITIGATION_POLICY policy,
	  uint Flags,
	  IntPtr buffer,
	  uint bufferSize);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
	/// </summary>
	[LibraryImport("kernel32.dll", EntryPoint = "CreateProcessW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CreateProcess(
		string? lpApplicationName,
		string lpCommandLine,
		IntPtr lpProcessAttributes,
		IntPtr lpThreadAttributes,
		[MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
		uint dwCreationFlags,
		IntPtr lpEnvironment,
		string? lpCurrentDirectory,
		ref STARTUPINFO lpStartupInfo,
		out PROCESS_INFORMATION lpProcessInformation);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess
	/// </summary>
	[LibraryImport("kernel32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool TerminateProcess(IntPtr hProcess, uint uExitCode);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
	/// </summary>
	[LibraryImport("kernel32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw
	/// </summary>
	[LibraryImport("kernel32.dll", EntryPoint = "LoadLibraryExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr LoadLibraryExW(string lpFileName, IntPtr hFile, uint dwFlags);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
	/// Get the address of a procedure (function) from a loaded library
	/// Windows uses ANSI encoding for exported function names so we cannot use Unicode for GetProcAddress.
	/// Raw unmanaged signature using byte* to avoid any need for runtime string marshalling.
	/// </summary>
	[LibraryImport("kernel32.dll", EntryPoint = "GetProcAddress")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	private static unsafe partial IntPtr GetProcAddress(IntPtr hModule, byte* lpProcName);

	/// <summary>
	/// Safe wrapper around GetProcAddress that takes a string and does necessary validation and conversion.
	/// </summary>
	internal static IntPtr GetProcAddress(IntPtr hModule, string procName)
	{
		if (hModule == IntPtr.Zero)
		{
			throw new ArgumentException("Module handle cannot be zero.", nameof(hModule));
		}

		ReadOnlySpan<char> nameSpan = procName.AsSpan();
		int len = nameSpan.Length;

		// Export names are strictly in the ASCII subset; validate and convert.
		// Stackalloc for typical short names to avoid allocation.
		Span<byte> buffer = len <= 64 ? stackalloc byte[len + 1] : new byte[len + 1];

		for (int i = 0; i < len; i++)
		{
			char c = nameSpan[i];
			if (c > 0x7F)
			{
				throw new ArgumentException("Export (procedure) names must be ASCII.", nameof(procName));
			}
			buffer[i] = (byte)c;
		}

		// Null-terminate
		buffer[len] = 0;

		unsafe
		{
			fixed (byte* pName = buffer)
			{
				IntPtr addr = GetProcAddress(hModule, pName);
				return addr;
			}
		}
	}


	/// <summary>
	/// Delegate for the function signature of 'MpQueryFileTrustByHandle2'
	/// </summary>
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	internal unsafe delegate long MpQueryFileTrustByHandle2Delegate(
	IntPtr hFile,
	IntPtr a2,
	IntPtr a3,
	Params* pParams,
	ulong* pExtraInfoCount,
	IntPtr* pExtraInfo);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/psapi/nf-psapi-getperformanceinfo
	/// </summary>
	[LibraryImport("psapi.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial bool GetPerformanceInfo(ref PerformanceInformation pPerformanceInformation, int size);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex
	/// </summary>
	[LibraryImport("ole32.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int CoInitializeEx(IntPtr pvReserved, uint dwCoInit);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/combaseapi/nf-combaseapi-couninitialize
	/// </summary>
	[LibraryImport("ole32.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial void CoUninitialize();


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance
	/// </summary>
	[LibraryImport("ole32.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int CoCreateInstance(
		in Guid rclsid,
		IntPtr pUnkOuter,
		uint dwClsContext,
		in Guid riid,
		out IntPtr ppv);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-lsaaddaccountrights
	/// </summary>
	[LibraryImport("ADVAPI32", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint LsaAddAccountRights(
	IntPtr PolicyHandle,
	IntPtr AccountSid,
	ref LSA_UNICODE_STRING UserRights,
	uint CountOfRights
	);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-lsaremoveaccountrights
	/// </summary>
	[LibraryImport("ADVAPI32", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial uint LsaRemoveAccountRights(
		IntPtr PolicyHandle,
		IntPtr AccountSid,
		[MarshalAs(UnmanagedType.Bool)] bool AllRights,
		ref LSA_UNICODE_STRING UserRights,
		uint CountOfRights
	);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditsetsystempolicy
	/// </summary>
	[LibraryImport("ADVAPI32", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool AuditSetSystemPolicy(
	IntPtr pAuditPolicy,
	uint PolicyCount
	);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditlookupsubcategorynamew
	/// </summary>
	[LibraryImport("ADVAPI32", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool AuditLookupSubCategoryNameW(
		IntPtr pAuditSubCategoryGuid,
		out IntPtr ppszSubCategoryName
	);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/ntsecapi/nf-ntsecapi-auditlookupcategorynamew
	/// </summary>
	[LibraryImport("ADVAPI32", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool AuditLookupCategoryNameW(
		IntPtr pAuditCategoryGuid,
		out IntPtr ppszCategoryName
	);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
	/// </summary>
	[LibraryImport("ADVAPI32", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew
	/// </summary>
	[LibraryImport("ADVAPI32", SetLastError = true, EntryPoint = "LookupPrivilegeValueW", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool LookupPrivilegeValue(string? lpSystemName, string lpName, out LUID lpLuid);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
	/// </summary>
	[LibraryImport("ADVAPI32", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool AdjustTokenPrivileges(IntPtr TokenHandle, [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
		ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/fdi/nf-fdi-fdicreate
	/// </summary>
	[LibraryImport("cabinet.dll")]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr FDICreate(IntPtr pfnalloc, IntPtr pfnfree, IntPtr pfnopen, IntPtr pfnread, IntPtr pfnwrite, IntPtr pfnclose, IntPtr pfnseek, int cpuType, IntPtr perf);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/fdi/nf-fdi-fdidestroy
	/// </summary>
	[LibraryImport("cabinet.dll")]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
	[return: MarshalAs(UnmanagedType.Bool)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial bool FDIDestroy(IntPtr hdfi);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/fdi/nf-fdi-fdicopy
	/// </summary>
	[LibraryImport("cabinet.dll", StringMarshalling = StringMarshalling.Utf16)]
	[UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
	[return: MarshalAs(UnmanagedType.Bool)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial bool FDICopy(IntPtr hdfi, string pszCabinet, string pszCabPath, int flags, IntPtr fnNotify, IntPtr fnDecrypt, IntPtr userData);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-startservicew
	/// </summary>
	[LibraryImport("advapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool StartServiceW(IntPtr hService, uint dwNumServiceArgs, IntPtr lpServiceArgVectors);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex
	/// </summary>
	[LibraryImport("advapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool QueryServiceStatusEx(
		IntPtr hService,
		int InfoLevel,
		IntPtr lpBuffer,
		uint cbBufSize,
		out uint pcbBytesNeeded);


	// https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_status_process
	internal const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
	internal const uint SERVICE_ACCEPT_STOP = 0x00000001;
	internal const uint SERVICE_ACCEPT_SHUTDOWN = 0x00000004;

	// https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-controlservice
	internal const uint SERVICE_CONTROL_STOP = 0x00000001;

	// https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Services/constant.SERVICE_CONTROL_SHUTDOWN.html
	internal const uint SERVICE_CONTROL_SHUTDOWN = 0x00000005;


	[UnmanagedFunctionPointer(CallingConvention.Winapi)]
	internal delegate void ServiceMainFunction(uint dwNumServicesArgs, IntPtr lpServiceArgVectors); // LPWSTR* marshalled as IntPtr


	[UnmanagedFunctionPointer(CallingConvention.Winapi)]
	internal delegate uint HandlerEx(uint dwControl, uint dwEventType, IntPtr lpEventData, IntPtr lpContext);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-startservicectrldispatcherw
	/// </summary>
	[LibraryImport("advapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool StartServiceCtrlDispatcherW([In] SERVICE_TABLE_ENTRY[] lpServiceStartTable);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-registerservicectrlhandlerexw
	/// </summary>
	[LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr RegisterServiceCtrlHandlerExW(string lpServiceName, HandlerEx lpHandlerProc, IntPtr lpContext);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-setservicestatus
	/// </summary>
	[LibraryImport("advapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool SetServiceStatus(IntPtr hServiceStatus, ref SERVICE_STATUS lpServiceStatus);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-registereventsourcew
	/// </summary>
	[LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr RegisterEventSourceW(string? lpUNCServerName, string lpSourceName);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-deregistereventsource
	/// </summary>
	[LibraryImport("advapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool DeregisterEventSource(IntPtr hEventLog);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-reporteventw
	/// </summary>
	[LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool ReportEventW(
		IntPtr hEventLog,
		ushort wType,
		ushort wCategory,
		uint dwEventID,
		IntPtr lpUserSid,
		ushort wNumStrings,
		uint dwDataSize,
		[In, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr)] string[] lpStrings,
		IntPtr lpRawData);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winreg/nf-winreg-regcreatekeyexw
	/// </summary>
	[LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int RegCreateKeyExW(
		IntPtr hKey,
		string lpSubKey,
		uint Reserved,
		string? lpClass,
		uint dwOptions,
		uint samDesired,
		IntPtr lpSecurityAttributes,
		out IntPtr phkResult,
		out uint lpdwDisposition);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winreg/nf-winreg-regsetvalueexw
	/// </summary>
	[LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int RegSetValueExW(
		IntPtr hKey,
		[MarshalAs(UnmanagedType.LPWStr)] string lpValueName,
		uint Reserved,
		uint dwType,
		[In] byte[] lpData,
		uint cbData);


	[LibraryImport("advapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial int RegCloseKey(IntPtr hKey);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information
	/// </summary>
	internal const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;


	[LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string? lpName);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/jobapi2/nf-jobapi2-setinformationjobobject
	/// </summary>
	[LibraryImport("kernel32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool SetInformationJobObject(
		IntPtr hJob,
		JOBOBJECTINFOCLASS JobObjectInformationClass,
		ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION lpJobObjectInformation,
		uint cbJobObjectInformationLength);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject
	/// </summary>
	[LibraryImport("kernel32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
	/// </summary>
	[LibraryImport("kernel32.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static partial IntPtr GetCurrentProcess();


	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-checktokenmembership
	/// </summary>
	[LibraryImport("advapi32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static partial bool CheckTokenMembership(IntPtr TokenHandle, IntPtr SidToCheck, [MarshalAs(UnmanagedType.Bool)] out bool IsMember);

}
