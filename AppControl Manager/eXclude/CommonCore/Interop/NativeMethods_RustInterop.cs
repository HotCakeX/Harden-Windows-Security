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

using System.Runtime.InteropServices;

namespace CommonCore.Interop;

#pragma warning disable CA5392, CA5393 // Don't need to define it, we're using Direct P/Invoke

internal static unsafe partial class NativeMethods
{

#if DEBUG
	[LibraryImport("RustInterop/rust_interop.dll", StringMarshalling = StringMarshalling.Utf8)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
#endif
#if !DEBUG
	[LibraryImport("rust_interop", StringMarshalling = StringMarshalling.Utf8)]
#endif
	internal static partial nint show_file_picker(
					[MarshalAs(UnmanagedType.LPUTF8Str)] string filter,
					[MarshalAs(UnmanagedType.LPUTF8Str)] string? initialDir,
					out int lastError);

#if DEBUG
	[LibraryImport("RustInterop/rust_interop.dll", StringMarshalling = StringMarshalling.Utf8)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
#endif
#if !DEBUG
	[LibraryImport("rust_interop", StringMarshalling = StringMarshalling.Utf8)]
#endif
	internal static partial StringArrayForFileDialogHelper show_files_picker(
			[MarshalAs(UnmanagedType.LPUTF8Str)] string filter,
			[MarshalAs(UnmanagedType.LPUTF8Str)] string? initialDir,
			out int lastError);

#if DEBUG
	[LibraryImport("RustInterop/rust_interop.dll", StringMarshalling = StringMarshalling.Utf8)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
#endif
#if !DEBUG
	[LibraryImport("rust_interop", StringMarshalling = StringMarshalling.Utf8)]
#endif
	internal static partial nint show_folder_picker(
			[MarshalAs(UnmanagedType.LPUTF8Str)] string? initialDir,
			out int lastError);

#if DEBUG
	[LibraryImport("RustInterop/rust_interop.dll", StringMarshalling = StringMarshalling.Utf8)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
#endif
#if !DEBUG
	[LibraryImport("rust_interop", StringMarshalling = StringMarshalling.Utf8)]
#endif
	internal static partial StringArrayForFileDialogHelper show_folders_picker(
			[MarshalAs(UnmanagedType.LPUTF8Str)] string? initialDir,
			out int lastError);

#if DEBUG
	[LibraryImport("RustInterop/rust_interop.dll", StringMarshalling = StringMarshalling.Utf8)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
#endif
#if !DEBUG
	[LibraryImport("rust_interop", StringMarshalling = StringMarshalling.Utf8)]
#endif
	internal static partial void free_string(nint s);

#if DEBUG
	[LibraryImport("RustInterop/rust_interop.dll", StringMarshalling = StringMarshalling.Utf8)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
#endif
#if !DEBUG
	[LibraryImport("rust_interop", StringMarshalling = StringMarshalling.Utf8)]
#endif
	internal static partial void free_string_array(StringArrayForFileDialogHelper arr);

#if DEBUG
	[LibraryImport("RustInterop/rust_interop.dll", StringMarshalling = StringMarshalling.Utf8)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
#endif
#if !DEBUG
	[LibraryImport("rust_interop", StringMarshalling = StringMarshalling.Utf8)]
#endif
	internal static partial int relaunch_app_elevated(
			[MarshalAs(UnmanagedType.LPWStr)] string aumid,
			[MarshalAs(UnmanagedType.LPWStr)] string? arguments,
			uint* processId);

#if DEBUG
	[LibraryImport("RustInterop/rust_interop.dll", StringMarshalling = StringMarshalling.Utf8)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
#endif
#if !DEBUG
	[LibraryImport("rust_interop", StringMarshalling = StringMarshalling.Utf8)]
#endif
	internal static partial int update_taskbar_progress(
			nint hwnd,
			ulong completed,
			ulong total,
			out int lastError);


#if DEBUG
	[LibraryImport("RustInterop/rust_interop.dll", StringMarshalling = StringMarshalling.Utf8)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
#endif
#if !DEBUG
	[LibraryImport("rust_interop", StringMarshalling = StringMarshalling.Utf8)]
#endif
	internal static partial nint show_save_file_dialog(
			[MarshalAs(UnmanagedType.LPUTF8Str)] string filter,
			[MarshalAs(UnmanagedType.LPUTF8Str)] string? initialDir,
			[MarshalAs(UnmanagedType.LPUTF8Str)] string? defaultFilename,
			out int lastError);

#if DEBUG
	[LibraryImport("RustInterop/rust_interop.dll", StringMarshalling = StringMarshalling.Utf8)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
#endif
#if !DEBUG
	[LibraryImport("rust_interop", StringMarshalling = StringMarshalling.Utf8)]
#endif
	internal static partial nint scan_directory_via_interop(string directoryPath);


#if DEBUG
	[LibraryImport("RustInterop/rust_interop.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
#endif
#if !DEBUG
	[LibraryImport("rust_interop")]
#endif
	internal static partial void release_analysis_results(nint results);


#if DEBUG
	[LibraryImport("RustInterop/rust_interop.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
#endif
#if !DEBUG
	[LibraryImport("rust_interop")]
#endif
	internal static partial nint detect_system_gpus();

#if DEBUG
	[LibraryImport("RustInterop/rust_interop.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
#endif
#if !DEBUG
	[LibraryImport("rust_interop")]
#endif
	internal static partial void release_gpu_information(nint results);

}
