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
using System.Runtime.InteropServices.Marshalling;

namespace CipPreviewHandler;

// The Windows preview host (prevhost.exe) runs at Low Integrity Level and prefers to initialize handlers with a
// stream. Implementing IInitializeWithStream is what allows the host to actually activate and render this handler,
// so these definitions live alongside the other COM interfaces of the DLL.

/// <summary>
/// A minimal projection of IStream. Only the Read method is declared because the preview host only ever needs to
/// hand us the file bytes. The vtable order is preserved (Read is the first ISequentialStream method, i.e. the
/// first slot after IUnknown), so calling Read through this interface is binary compatible with a real IStream.
/// </summary>
[GeneratedComInterface]
[Guid("0000000c-0000-0000-C000-000000000046")]
internal partial interface IStream
{
	// HRESULT Read(void* pv, ULONG cb, ULONG* pcbRead). Returns S_OK while data remains, S_FALSE at end of stream.
	[PreserveSig]
	int Read(nint pv, uint cb, out uint pcbRead);
}

/// <summary>
/// IInitializeWithStream. The preferred initialization contract for preview handlers, required by the low integrity
/// level preview host. The host passes the file content as a stream, which we read fully and cache for rendering.
/// </summary>
[GeneratedComInterface]
[Guid("B824B49D-22AC-4161-AC8A-9916E8FA3F7F")]
internal partial interface IInitializeWithStream
{
	[PreserveSig]
	int Initialize(IStream pstream, uint grfMode);
}
