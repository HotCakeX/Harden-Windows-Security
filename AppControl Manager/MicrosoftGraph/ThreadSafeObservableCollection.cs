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
using System.Collections.ObjectModel;
using System.Threading;

namespace AppControlManager.MicrosoftGraph;

internal sealed class ThreadSafeObservableCollection<T> : ObservableCollection<T>, IDisposable
{
	private readonly ReaderWriterLockSlim _lock = new();

	protected override void InsertItem(int index, T item)
	{
		_lock.EnterWriteLock();
		try
		{
			base.InsertItem(index, item);
		}
		finally
		{
			_lock.ExitWriteLock();
		}
	}

	protected override void RemoveItem(int index)
	{
		_lock.EnterWriteLock();
		try
		{
			base.RemoveItem(index);
		}
		finally
		{
			_lock.ExitWriteLock();
		}
	}

	protected override void SetItem(int index, T item)
	{
		_lock.EnterWriteLock();
		try
		{
			base.SetItem(index, item);
		}
		finally
		{
			_lock.ExitWriteLock();
		}
	}

	protected override void ClearItems()
	{
		_lock.EnterWriteLock();
		try
		{
			base.ClearItems();
		}
		finally
		{
			_lock.ExitWriteLock();
		}
	}

	// Override GetEnumerator to ensure thread-safe enumeration.
	internal new IEnumerator<T> GetEnumerator()
	{
		_lock.EnterReadLock();
		try
		{
			// Create a snapshot of the items to iterate over.
			var items = new T[Items.Count];
			Items.CopyTo(items, 0);
			foreach (var item in items)
			{
				yield return item;
			}
		}
		finally
		{
			_lock.ExitReadLock();
		}
	}

	public void Dispose()
	{
		_lock.Dispose();
	}
}
