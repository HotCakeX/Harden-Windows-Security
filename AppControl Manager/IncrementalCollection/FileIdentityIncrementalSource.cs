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
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.IntelGathering;
using CommunityToolkit.Common.Collections;

#pragma warning disable CS1998

namespace AppControlManager.IncrementalCollection;

/// <summary>
/// Incremental source that pages over a pre-materialized List.
/// Data flow:
/// - The controller maintains a full in-memory list.
/// - The GenericIncrementalCollection wraps this source to present a paged ObservableCollection to the UI.
/// - As the ListView requests more data (scrolling), the incremental collection calls GetPagedItemsAsync with increasing pageIndex.
/// - We return a slice (page) from the underlying list without additional async I/O.
/// </summary>
internal sealed class FileIdentityIncrementalSource(List<FileIdentity> sourceData) : IIncrementalSource<FileIdentity>
{
	// Exposes the underlying backing list so upstream code can inspect/replace if needed.
	internal List<FileIdentity> SourceData => sourceData;

	/// <summary>
	/// Returns a page (pageSize items) from SourceData starting at pageIndex * pageSize.
	/// Notes:
	/// - This method is async to conform to IIncrementalSource, but currently performs no awaits (in-memory only).
	/// - If startingIndex is beyond the end of the list, we return an empty sequence to indicate completion.
	/// </summary>
	public async Task<IEnumerable<FileIdentity>> GetPagedItemsAsync(int pageIndex, int pageSize, CancellationToken cancellationToken = default)
	{
		int startingIndex = pageIndex * pageSize;
		if (startingIndex >= SourceData.Count)
			return [];

		// Take the requested slice. This is O(pageSize) and does not allocate beyond the resulting iterator/materialization by caller.
		return SourceData.Skip(startingIndex).Take(pageSize);
	}
}
