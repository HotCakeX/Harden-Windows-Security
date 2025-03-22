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

namespace AppControlManager.Others;

/// <summary>
/// https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/91755632-4b0d-44ca-89a9-9699afbbd268
/// Rust implementation: https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/WinTrust/struct.SPC_SP_OPUS_INFO.html
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct OpusInfoObj
{
	[MarshalAs(UnmanagedType.LPWStr)]
	internal string CertOemID = string.Empty;

	internal IntPtr PublisherInfo = IntPtr.Zero;

	/// <summary>
	/// not always present
	/// </summary>
	internal IntPtr MoreInfo = IntPtr.Zero;

	public OpusInfoObj()
	{
		CertOemID = string.Empty;
		PublisherInfo = IntPtr.Zero;
		MoreInfo = IntPtr.Zero;
	}
}
