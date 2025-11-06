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

namespace CommonCore;

internal static partial class CIManager
{

	internal static unsafe void Add(byte[] bytes)
	{
		// ManageCI's upsert takes a 32-bit size
		if ((ulong)bytes.Length > uint.MaxValue)
		{
			throw new InvalidOperationException($"Policy is too large: {bytes.Length} bytes");
		}

		// Pinning the managed byte[] to obtain a stable unmanaged pointer for native calls.
		fixed (byte* pBytes = bytes)
		{
			// Pre-parse validation
			// ManageCI_ParsePolicy validates the blob and extracts IDs.
			// We discard the friendly-name pointer here because we will derive the friendly name
			// directly from the SiPolicyView returned by the non-prefixed ParsePolicy.
			int hrParse = NativeMethods.ManageCI_ParsePolicy(
				pBytes,
				bytes.Length,
				out Guid parsedPolicyId,
				out Guid parsedBasePolicyId,
				out _);

			if (hrParse != 0)
			{
				throw new InvalidOperationException($"ManageCI_ParsePolicy failed with 0x{hrParse:X8}");
			}

			// Start sets up internal state, telemetry, and in-memory sets for the transaction.
			NativeMethods.ManageCI_Start();

			// Keep SiPolicyView pointer available for post-End manual teardown.
			void* siPolicyView = null;

			try
			{
				// BeginTransaction creates the upsert/delete sets and starts telemetry.
				NativeMethods.ManageCI_BeginTransaction();

				// Obtain the management "this" pointer
				// Calling CodeIntegrity::Management::ParsePolicy(&view, bytes, len) to build a SiPolicyView,
				// Then passing *(CodeIntegrity::Management**)view as the first argument ("this") to BeginUpsertCIPolicy.
				long parseStatus = NativeMethods.ParsePolicy(out siPolicyView, pBytes, (nuint)bytes.Length);

				if (siPolicyView == null)
				{
					TryRollback();
					throw new InvalidOperationException("ParsePolicy did not return a valid SiPolicyView pointer.");
				}

				// Read the first pointer-sized field from SiPolicyView as the CodeIntegrity::Management* "this".
				void* managementThis = *(void**)siPolicyView;
				if (managementThis == null)
				{
					TryRollback();
					throw new InvalidOperationException("SiPolicyView did not contain a valid management context pointer.");
				}

				// Resolve the friendly name from the SiPolicyView itself.
				// - If *((ulong*)view + 6) > 7, the string buffer pointer is at (view + 24)
				// - Else the string is inlined starting at (view + 24)
				// We bound the scan with a reasonable limit to avoid runaway if memory is corrupted.
				string friendlyName = GetFriendlyNameFromSiPolicyView(siPolicyView);

				Logger.Write("Details of the policy being deployed:");
				Logger.Write($"Policy ID: {parsedPolicyId.ToString("D")}");
				Logger.Write($"Base Policy ID: {parsedBasePolicyId.ToString("D")}");
				Logger.Write($"Friendly Name: {friendlyName}");

				// Queue the upsert using the prefixed wrapper that takes the management "this":
				// ManageCI_BeginUpsertCIPolicy(CodeIntegrity::Management* a1, BYTE* a2, unsigned int a3)
				//
				// Internally this:
				// - Builds a temporary SiPolicyView over the blob.
				// - Enforces secure "non-modifiable" checks (v14) and ownership checks (this vs view).
				// - Calls SIPolicyPmUpdatePolicyBegin to get a transaction handle.
				// - Enqueues the handle in the SiPolicy upsert set and instruments telemetry.
				int hrUpsert = NativeMethods.ManageCI_BeginUpsertCIPolicy(managementThis, pBytes, checked((uint)bytes.Length));
				if (hrUpsert != 0)
				{
					TryRollback();
					throw new InvalidOperationException($"ManageCI_BeginUpsertCIPolicy failed with 0x{hrUpsert:X8}");
				}

				// Commit applies all queued operations and triggers the kernel notification:
				// NtSetSystemInformation(SystemContextSwitchInformation|0x80, ...etc.)
				int hrCommit = NativeMethods.ManageCI_Commit();
				if (hrCommit != 0)
				{
					TryRollback();
					throw new InvalidOperationException($"ManageCI_Commit failed with 0x{hrCommit:X8}");
				}

				// We obviously cant destroy/free the SiPolicyView* like CiTool does because no exported destructor is available.
				// CiTool frees it internally by defining the dctor:
				// void __fastcall CodeIntegrity::Management::SiPolicyView::~SiPolicyView(CodeIntegrity::Management::SiPolicyView *this)
				// which it calls at the end of the following function: void __fastcall UpsertPolicy(_QWORD *a1)
				// ManageCI DLL is not responsible for freeing a SiPolicyView that we create with the unprefixed ParsePolicy.
				// There is no exported free or such.
				// Prefixed ParsePolicy exists which doesn't require us to free anything, but it's not used by CiTool.
				Logger.Write("Operation Successful");
			}
			catch
			{
				TryRollback();
				throw;
			}
			finally
			{
				// End tears down the ManageCI session and telemetry scope.
				NativeMethods.ManageCI_End();

				// Manual destructor for SiPolicyView to release its owned allocations and the object itself.
				// It's invoked after End() as CiTool does.
				if (siPolicyView != null)
				{
					FreeSiPolicyView(siPolicyView);
				}
			}
		}
	}

	// Manual teardown that emulates CiTool's SiPolicyView destructor.
	// It frees:
	// - Secondary buffer triple [15..17] (start,current,end)
	// - Primary buffer triple   [12..14]
	// - std::vector<unsigned int> buffer at +72 (begin..capacity)
	// - std::wstring heap buffer at +24 when heap-backed
	// - Two side allocations at indices [1] and [0] (each ~0x10 bytes)
	// - Finally the SiPolicyView object itself (0x90 bytes)
	private static unsafe void FreeSiPolicyView(void* view)
	{
		IntPtr heap = NativeMethods.GetProcessHeap();
		if (heap == IntPtr.Zero)
		{
			Logger.Write("Heap acquisition failed; skipping SiPolicyView free.");
			return;
		}

		byte* basePtr = (byte*)view;
		ulong* qwords = (ulong*)view;

		// Frees a contiguous [start, end) allocation, applying large-allocation header adjustment when needed.
		static void FreeRange(IntPtr heapHandle, byte* start, byte* end)
		{
			if (start == null || end == null || start >= end)
			{
				return;
			}

			ulong size = (ulong)(end - start);
			byte* actualStart = start;

			if (size >= 0x1000)
			{
				// Large allocation heuristic used by MSVC allocators: header QWORD one slot before user pointer.
				ulong* headerPtr = (ulong*)(start - sizeof(ulong));
				byte* headerBase = (byte*)*headerPtr;
				nuint delta = (nuint)(start - headerBase);
				// Sanity: (delta - sizeof(ulong)) <= 0x1F
				if (delta < sizeof(ulong) || (delta - sizeof(ulong)) > 0x1F)
				{
					return; // Avoid freeing if header math looks wrong.
				}
				actualStart = headerBase;
				size += 39UL; // Sized delete adjustment.
			}

			// query heap size when available.
			nuint reported = NativeMethods.HeapSize(heapHandle, 0u, (IntPtr)actualStart);
			if (reported != nuint.MaxValue)
			{
				Logger.Write($"FreeRange: block size={reported} bytes");
			}

			bool freed = NativeMethods.HeapFree(heapHandle, 0u, (IntPtr)actualStart);
			if (!freed)
			{
				Logger.Write("FreeRange: HeapFree failed; block left allocated.");
			}
		}

		// Secondary buffer triple [15..17]
		byte* secondStart = (byte*)qwords[15];
		byte* secondEnd = (byte*)qwords[17];
		if (secondStart != null)
		{
			Logger.Write("Freeing secondary buffer triple [15..17]...");
			FreeRange(heap, secondStart, secondEnd);
			qwords[15] = 0;
			qwords[16] = 0;
			qwords[17] = 0;
		}

		// Primary buffer triple [12..14]
		byte* firstStart = (byte*)qwords[12];
		byte* firstEnd = (byte*)qwords[14];
		if (firstStart != null)
		{
			Logger.Write("Freeing primary buffer triple [12..14]...");
			FreeRange(heap, firstStart, firstEnd);
			qwords[12] = 0;
			qwords[13] = 0;
			qwords[14] = 0;
		}

		// std::vector<unsigned int> at +72: [begin, end, capacity]
		byte* vectorBegin = *(byte**)(basePtr + 72);
		byte* vectorEnd = *(byte**)(basePtr + 80);
		byte* vectorCap = *(byte**)(basePtr + 88);
		if (vectorBegin != null)
		{
			if (vectorBegin <= vectorEnd && vectorEnd <= vectorCap)
			{
				Logger.Write("Freeing vector buffer (begin..capacity)...");
				FreeRange(heap, vectorBegin, vectorCap);
			}
			else
			{
				Logger.Write("Vector pointer sanity check failed; skipping vector free.");
			}
			*(ulong*)(basePtr + 72) = 0;
			*(ulong*)(basePtr + 80) = 0;
			*(ulong*)(basePtr + 88) = 0;
		}

		// std::wstring at +24 (heap-backed only)
		// Using the existing discriminator pattern already used to read the friendly name.
		ulong discriminator = qwords[6];
		if (discriminator > 7)
		{
			void* wstrBuf = *(void**)(basePtr + 24);
			if (wstrBuf != null)
			{
				Logger.Write("Freeing heap-backed wstring buffer (friendly name)...");
				nuint wSize = NativeMethods.HeapSize(heap, 0u, (IntPtr)wstrBuf);
				if (wSize != nuint.MaxValue)
				{
					Logger.Write($"wstring block size={wSize} bytes");
				}
				bool freed = NativeMethods.HeapFree(heap, 0u, (IntPtr)wstrBuf);
				if (!freed)
				{
					Logger.Write("HeapFree failed for wstring buffer; left allocated.");
				}
				*(ulong*)(basePtr + 24) = 0;
			}
		}

		// Side allocations at indices [1] and [0] (each ~0x10)
		void* side1 = (void*)qwords[1];
		if (side1 != null)
		{
			Logger.Write("Freeing side allocation [1] (expected ~0x10 bytes)...");
			nuint s1Size = NativeMethods.HeapSize(heap, 0u, (IntPtr)side1);
			if (s1Size != nuint.MaxValue)
			{
				Logger.Write($"side[1] block size={s1Size} bytes");
			}
			bool freed = NativeMethods.HeapFree(heap, 0u, (IntPtr)side1);
			if (!freed)
			{
				Logger.Write("HeapFree failed for side[1]; left allocated.");
			}
			qwords[1] = 0;
		}

		void* side0 = (void*)qwords[0];
		if (side0 != null)
		{
			Logger.Write("Freeing side allocation [0] (expected ~0x10 bytes)...");
			nuint s0Size = NativeMethods.HeapSize(heap, 0u, (IntPtr)side0);
			if (s0Size != nuint.MaxValue)
			{
				Logger.Write($"side[0] block size={s0Size} bytes");
			}
			bool freed = NativeMethods.HeapFree(heap, 0u, (IntPtr)side0);
			if (!freed)
			{
				Logger.Write("HeapFree failed for side[0]; left allocated.");
			}
			qwords[0] = 0;
		}

		// Finally free the SiPolicyView object itself.
		IntPtr viewPtr = (IntPtr)view;
		nuint topSize = NativeMethods.HeapSize(heap, 0u, viewPtr);
		if (topSize != nuint.MaxValue)
		{
			Logger.Write($"Freeing SiPolicyView object (size={topSize} bytes)...");
		}
		bool topFreed = NativeMethods.HeapFree(heap, 0u, viewPtr);
		if (!topFreed)
		{
			Logger.Write("HeapFree failed for SiPolicyView object; block left allocated.");
		}
		else
		{
			Logger.Write("SiPolicyView object freed.");
		}
	}

	// Resolve Friendly Name directly from the SiPolicyView (std::wstring SSO handling).
	// - First pointer-sized field: CodeIntegrity::Management* (owner/"this")
	// - At offset +24: std::wstring's small-buffer (inline) or pointer to heap buffer
	// - At *((ulong*)view + 6): discriminator (> 7 -> heap buffer at +24; else inline at +24)
	// We scan for the UTF-16 NUL terminator with a sane upper bound to be defensive.
	private static unsafe string GetFriendlyNameFromSiPolicyView(void* siPolicyView)
	{
		if (siPolicyView == null)
		{
			return string.Empty;
		}

		byte* basePtr = (byte*)siPolicyView;

		// Discriminator at index 6 (8th QWORD) controls SSO vs heap.
		ulong discriminator = *(((ulong*)siPolicyView) + 6);

		char* namePtr;
		if (discriminator > 7)
		{
			// Heap-backed: (char*)*(void**)(base+24)
			void* heapBuf = *(void**)(basePtr + 24);
			if (heapBuf == null)
			{
				return string.Empty;
			}
			namePtr = (char*)heapBuf;
		}
		else
		{
			// Small-string inlined at base+24
			namePtr = (char*)(basePtr + 24);
		}

		if (namePtr == null)
		{
			return string.Empty;
		}

		// Defensive max to avoid runaway scans in case of memory corruption.
		// Friendly names are usually small, 4096 UTF-16 chars is a good upper bound.
		const int MaxChars = 4096;
		int len = 0;
		for (; len < MaxChars; len++)
		{
			if (namePtr[len] == '\0')
			{
				break;
			}
		}

		if (len <= 0)
		{
			return string.Empty;
		}

		return new string(namePtr, 0, len);
	}

	private static bool TryParseGuidFlexible(string text, out Guid guid)
	{
		if (Guid.TryParseExact(text, "D", out guid))
		{
			return true;
		}
		if (Guid.TryParseExact(text, "N", out guid))
		{
			return true;
		}
		if (Guid.TryParseExact(text, "B", out guid))
		{
			return true;
		}
		if (Guid.TryParseExact(text, "P", out guid))
		{
			return true;
		}
		return Guid.TryParse(text, out guid);
	}

	/// <summary>
	/// ManageCI_Rollback corresponds to CodeIntegrity::Management::Rollback and clears any queued ops.
	/// </summary>
	private static void TryRollback()
	{
		int hr = NativeMethods.ManageCI_Rollback();
		if (hr != 0)
		{
			throw new InvalidOperationException($"ManageCI_Rollback returned 0x{hr:X8}");
		}
	}

	private static void RemovePolicy(Guid policyId)
	{
		// It initializes internal state, the in-memory policy sets and gets ManageCI ready for transactions.
		NativeMethods.ManageCI_Start();
		try
		{
			// Pre-check like CiTool's effective policy protection check:
			//
			// ManageCI_ShouldIgnoreRemoval(policyId, 1, out shouldIgnore) reads SiPolicyView and returns
			// whether the policy is protected (i.e., removal should be ignored/denied).
			// this ultimately tests a byte flag at offset +0x40 on the view (via ManageCI_GetPolicyInformation),
			// and returns E_INVALIDARG if the 'kind' parameter isn't 1.
			//
			// CiTool's RemovePolicy() doesn't explicitly call this wrapper,
			// instead, CodeIntegrity::Management::BeginRemoveCIPolicy throws E_ACCESSDENIED when the view marks the
			// policy as protected (v13[93] check).
			//
			// Using ShouldIgnoreRemoval makes the denial explicit and earlier.
			byte shouldIgnore = 0;

			unsafe
			{
				// Copying the Guid struct to a stack buffer and passing its pointer.
				byte* guidBuf = stackalloc byte[sizeof(Guid)];
				*(Guid*)guidBuf = policyId;

				// A 1-byte stack buffer for the out flag.
				byte* shouldIgnorePtr = stackalloc byte[sizeof(byte)];
				*shouldIgnorePtr = 0;

				int hrIgnore = NativeMethods.ManageCI_ShouldIgnoreRemoval((Guid*)guidBuf, 1, shouldIgnorePtr);
				if (hrIgnore != 0)
				{
					throw new InvalidOperationException($"ManageCI_ShouldIgnoreRemoval failed with 0x{hrIgnore:X8}");
				}

				shouldIgnore = *shouldIgnorePtr;
			}

			if (shouldIgnore != 0)
			{
				throw new InvalidOperationException("Access is denied. This policy cannot be removed.");
			}

			// Begin a transaction scope:
			//
			// ManageCI_BeginTransaction maps to CodeIntegrity::Management::BeginTransaction.
			// Internally it creates four transaction sets:
			//   - SiPolicy upserts   (qword_18003D010)
			//   - SiPolicy deletes   (qword_18003D020)
			//   - Token upserts      (qword_18003CF18)
			//   - Token deletes      (qword_18003D018)
			// and starts a telemetry ManageCITransaction activity.
			NativeMethods.ManageCI_BeginTransaction();

			// Enqueue the policy deletion:
			//
			// ManageCI_BeginRemoveCIPolicy(policyId) equals CodeIntegrity::Management::BeginRemoveCIPolicy.
			// Internally it:
			// - Finds the SiPolicyView for 'policyId' in the in-memory tree (qword_18003D008).
			// - If the view indicates protected (v13[93] != 0), throws E_ACCESSDENIED (same as our pre-check).
			// - Calls SIPolicyPmDeletePolicyBegin(...) to get a transaction handle for the deletion.
			// - Inserts a delete-transaction node into the delete set (qword_18003D020).
			// - Instruments telemetry (InstrumentRemoveCIPolicy).
			int hrBeginRemove;
			unsafe
			{
				byte* guidBuf2 = stackalloc byte[sizeof(Guid)];
				*(Guid*)guidBuf2 = policyId;

				hrBeginRemove = NativeMethods.ManageCI_BeginRemoveCIPolicy((Guid*)guidBuf2);
			}

			if (hrBeginRemove != 0)
			{
				TryRollback();
				throw new InvalidOperationException($"ManageCI_BeginRemoveCIPolicy failed with 0x{hrBeginRemove:X8}");
			}

			// Commit the transaction:
			//
			// ManageCI_Commit() mirrors CodeIntegrity::Management::Commit:
			//  - Iterates each transaction set (policy upserts, policy deletes, token upserts, token deletes),
			//    committing each queued operation via their stored 'TransactionHandle::commit' functions.
			//  - For each commit, instruments telemetry (InstrumentCommitCiPolicy / InstrumentCommitSbcpToken).
			//  - If any set had items, calls NtSetSystemInformation(SystemContextSwitchInformation|0x80, ...)
			//    — the same kernel notification CiTool uses to apply the changes.
			//  - Clears the transaction sets and stops the telemetry activity.
			int hrCommit = NativeMethods.ManageCI_Commit();
			if (hrCommit != 0)
			{
				TryRollback();
				throw new InvalidOperationException($"ManageCI_Commit failed with 0x{hrCommit:X8}");
			}

			Logger.Write("Operation Successful");
		}
		catch (Exception ex)
		{
			// Attempt rollback to leave the transaction system in a clean state.
			TryRollback();
			throw new InvalidOperationException($"Unexpected error: {ex.Message} - {Marshal.GetHRForException(ex)}");
		}
		finally
		{
			// ManageCI_End: mirrors CodeIntegrity::Management::End;
			// it clears the active ManageCITransaction unique_ptr and releases internal state.
			NativeMethods.ManageCI_End();
		}
	}

	internal static void RemovePolicyByID(string PolicyIdText)
	{
		if (!TryParseGuidFlexible(PolicyIdText, out Guid policyId))
		{
			throw new InvalidOperationException($"Invalid policy GUID: {PolicyIdText}");
		}

		// Perform the removal sequence
		RemovePolicy(policyId);
	}

	private static unsafe partial class NativeMethods
	{
		/// <summary>
		/// Session lifecycle, wraps CodeIntegrity::Management::Start
		/// </summary>
		[LibraryImport("ManageCI")]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		internal static partial void ManageCI_Start();


		/// <summary>
		/// Session lifecycle, wraps CodeIntegrity::Management::End
		/// </summary>
		[LibraryImport("ManageCI")]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		internal static partial void ManageCI_End();


		/// <summary>
		/// Transaction control, wraps CodeIntegrity::Management::BeginTransaction
		/// </summary>
		[LibraryImport("ManageCI")]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		internal static partial void ManageCI_BeginTransaction();


		/// <summary>
		/// Transaction control, wraps CodeIntegrity::Management::Commit
		/// </summary>
		[LibraryImport("ManageCI")]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		internal static partial int ManageCI_Commit();


		/// <summary>
		/// Transaction control, wraps CodeIntegrity::Management::Rollback
		/// </summary>
		[LibraryImport("ManageCI")]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		internal static partial int ManageCI_Rollback();


		/// <summary>
		/// Upsert (add/update) via prefixed wrapper that takes the management 'this' pointer.
		/// Native signature: __int64 __fastcall ManageCI_BeginUpsertCIPolicy(CodeIntegrity::Management* a1, BYTE* a2, unsigned int a3)
		/// </summary>
		/// <param name="managementThis"></param>
		/// <param name="policyBytes"></param>
		/// <param name="size"></param>
		/// <returns></returns>
		[LibraryImport("ManageCI")]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		internal static partial int ManageCI_BeginUpsertCIPolicy(void* managementThis, void* policyBytes, uint size);


		/// <summary>
		/// Pre-parse validation (fast-fail)
		/// </summary>
		[LibraryImport("ManageCI")]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		internal static partial int ManageCI_ParsePolicy(void* policyBytes, int policySize, out Guid policyId, out Guid basePolicyId, out void* friendlyNamePtr);


		/// <summary>
		/// Non‑prefixed ParsePolicy export (ordinal 19)
		/// Produces a SiPolicyView* to mine the management "this" pointer.
		/// </summary>
		[LibraryImport("ManageCI")]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		internal static partial long ParsePolicy(out void* siPolicyView, void* policyBytes, nuint policySize);


		/// <summary>
		/// Removal queue.
		/// Wraps CodeIntegrity::Management::BeginRemoveCIPolicy -> SIPolicyPmDeletePolicyBegin
		/// </summary>
		[LibraryImport("ManageCI.dll")]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		internal static partial int ManageCI_BeginRemoveCIPolicy(Guid* policyId);


		/// <summary>
		/// Pre-check whether removal should be ignored/denied for this policy.
		/// </summary>
		/// <param name="kind">Must be 1 (else E_INVALIDARG)</param>
		/// <param name="shouldIgnore">Receives nonzero if removal should be denied (maps to E_ACCESSDENIED for callers).</param>
		[LibraryImport("ManageCI.dll")]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		internal static partial int ManageCI_ShouldIgnoreRemoval(Guid* policyId, int kind, byte* shouldIgnore);


		[LibraryImport("kernel32.dll")]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		internal static partial IntPtr GetProcessHeap();


		[LibraryImport("kernel32.dll", SetLastError = true)]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		internal static partial nuint HeapSize(IntPtr hHeap, uint dwFlags, IntPtr lpMem);


		[LibraryImport("kernel32.dll", SetLastError = true)]
		[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static partial bool HeapFree(IntPtr hHeap, uint dwFlags, IntPtr lpMem);

	}

}
