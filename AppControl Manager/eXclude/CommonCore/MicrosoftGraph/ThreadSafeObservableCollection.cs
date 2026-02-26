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

using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Threading;
using Microsoft.UI.Dispatching;

namespace CommonCore.MicrosoftGraph;

internal sealed class ThreadSafeObservableCollection<T> : ObservableCollection<T>, IEnumerable<T>, IDisposable
{
	// SupportsRecursion is critical here to prevent LockRecursionException if the UI thread 
	// tries to read the collection while a write lock is held.
	private readonly ReaderWriterLockSlim _lock = new(LockRecursionPolicy.SupportsRecursion);

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

	protected override void MoveItem(int oldIndex, int newIndex)
	{
		_lock.EnterWriteLock();
		try
		{
			base.MoveItem(oldIndex, newIndex);
		}
		finally
		{
			_lock.ExitWriteLock();
		}
	}

	// Ensure CollectionChanged is marshalled to the UI thread.
	protected override void OnCollectionChanged(NotifyCollectionChangedEventArgs e)
	{
		if (!GlobalVars.AppDispatcher.HasThreadAccess)
		{
			_ = GlobalVars.AppDispatcher.TryEnqueue(() => base.OnCollectionChanged(e));
		}
		else
		{
			base.OnCollectionChanged(e);
		}
	}

	// Ensure PropertyChanged is marshalled to the UI thread.
	protected override void OnPropertyChanged(PropertyChangedEventArgs e)
	{
		if (GlobalVars.AppDispatcher.HasThreadAccess)
		{
			_ = GlobalVars.AppDispatcher.TryEnqueue(() => base.OnPropertyChanged(e));
		}
		else
		{
			base.OnPropertyChanged(e);
		}
	}

	public new IEnumerator<T> GetEnumerator()
	{
		T[] items;
		_lock.EnterReadLock();
		try
		{
			items = new T[Items.Count];
			Items.CopyTo(items, 0);
		}
		finally
		{
			_lock.ExitReadLock();
		}

		// By returning an enumerator over the snapshotted array outside the lock, we don't hold the lock during iteration.
		return ((IEnumerable<T>)items).GetEnumerator();
	}

	// Overriding standard interface enumerators to ensure thread-safety when cast to IEnumerable or used by LINQ.
	IEnumerator<T> IEnumerable<T>.GetEnumerator() => GetEnumerator();

	IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

	public void Dispose() => _lock.Dispose();

}
