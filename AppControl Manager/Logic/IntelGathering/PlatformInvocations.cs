using System;
using System.Runtime.InteropServices;

namespace WDACConfig.IntelGathering
{
    internal static partial class PlatformInvocations
    {

        // https://learn.microsoft.com/en-us/windows/win32/api/mssip/nf-mssip-cryptsipretrievesubjectguid
        [LibraryImport("crypt32.dll", EntryPoint = "CryptSIPRetrieveSubjectGuid", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool CryptSIPRetrieveSubjectGuid(
            string FileName,
            IntPtr hFileIn,
            out Guid pgActionID);

        // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
        [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        internal static partial IntPtr CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        // https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool CloseHandle(IntPtr hObject);

        // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga
        [LibraryImport("kernel32.dll", EntryPoint = "CreateFileMappingW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        internal static partial IntPtr CreateFileMapping(
            IntPtr hFile,
            IntPtr pFileMappingAttributes,
            uint flProtect,
            uint dwMaximumSizeHigh,
            uint dwMaximumSizeLow,
            string lpName);

        // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfilesize
        [LibraryImport("kernel32.dll", SetLastError = true)]
        internal static partial uint GetFileSize(IntPtr hFile, ref uint lpFileSizeHigh);

        // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile
        [LibraryImport("kernel32.dll", SetLastError = true)]
        internal static partial IntPtr MapViewOfFile(
            IntPtr hFileMappingObject,
            uint dwDesiredAccess,
            uint dwFileOffsetHigh,
            uint dwFileOffsetLow,
            IntPtr dwNumberOfBytesToMap);

        // https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-imagedirectoryentrytodataex
        [LibraryImport("DbgHelp.dll", SetLastError = true)]
        internal static partial IntPtr ImageDirectoryEntryToDataEx(
            IntPtr Base,
            int MappedAsImage,
            ushort DirectoryEntry,
            ref uint Size,
            ref IntPtr FoundHeader);

        // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-unmapviewoffile
        [LibraryImport("kernel32.dll", SetLastError = true)]
        internal static partial int UnmapViewOfFile(IntPtr lpBaseAddress);

        // https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-imagentheader
        [LibraryImport("DbgHelp.dll", SetLastError = true)]
        internal static partial IntPtr ImageNtHeader(IntPtr ImageBase);

        // https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-imagervatova
        [LibraryImport("DbgHelp.dll", SetLastError = true)]
        internal static partial IntPtr ImageRvaToVa(
            IntPtr NtHeaders,
            IntPtr Base,
            uint Rva,
            IntPtr LastRvaSection);

    }
}
