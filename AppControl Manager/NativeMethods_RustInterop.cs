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
using AppControlManager.Others;

namespace AppControlManager;

#pragma warning disable CA5393

internal unsafe static partial class NativeMethods
{
	[LibraryImport("RustInterop/RustInterop.dll", StringMarshalling = StringMarshalling.Utf8)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
	internal static partial IntPtr show_file_picker(
		[MarshalAs(UnmanagedType.LPUTF8Str)] string filter,
		[MarshalAs(UnmanagedType.LPUTF8Str)] string? initialDir,
		out int lastError);

	[LibraryImport("RustInterop/RustInterop.dll", StringMarshalling = StringMarshalling.Utf8)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
	internal static partial FileDialogHelper.StringArray show_files_picker(
		[MarshalAs(UnmanagedType.LPUTF8Str)] string filter,
		[MarshalAs(UnmanagedType.LPUTF8Str)] string? initialDir,
		out int lastError);

	[LibraryImport("RustInterop/RustInterop.dll", StringMarshalling = StringMarshalling.Utf8)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
	internal static partial IntPtr show_folder_picker(
		[MarshalAs(UnmanagedType.LPUTF8Str)] string? initialDir,
		out int lastError);

	[LibraryImport("RustInterop/RustInterop.dll", StringMarshalling = StringMarshalling.Utf8)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
	internal static partial FileDialogHelper.StringArray show_folders_picker(
		[MarshalAs(UnmanagedType.LPUTF8Str)] string? initialDir,
		out int lastError);

	[LibraryImport("RustInterop/RustInterop.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
	internal static partial void free_string(IntPtr s);

	[LibraryImport("RustInterop/RustInterop.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
	internal static partial void free_string_array(FileDialogHelper.StringArray arr);

	[LibraryImport("RustInterop/RustInterop.dll", StringMarshalling = StringMarshalling.Utf16)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
	internal static partial int relaunch_app_elevated(
		[MarshalAs(UnmanagedType.LPWStr)] string aumid,
		[MarshalAs(UnmanagedType.LPWStr)] string? arguments,
		uint* processId);

	[LibraryImport("RustInterop/RustInterop.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
	internal static partial int update_taskbar_progress(
		IntPtr hwnd,
		ulong completed,
		ulong total,
		out int lastError);
}
