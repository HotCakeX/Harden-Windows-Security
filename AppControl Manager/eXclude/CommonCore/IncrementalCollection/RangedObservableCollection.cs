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
using System.Collections.Specialized;
using System.ComponentModel;

namespace CommonCore.IncrementalCollection;

internal sealed class RangedObservableCollection<T> : ObservableCollection<T>
{
	internal RangedObservableCollection() : base() { }

	internal RangedObservableCollection(IEnumerable<T> collection) : base(collection) { }

	/// <summary>
	/// Adds a range of items to the collection and fires notification events only once at the end.
	/// </summary>
	internal void AddRange(IEnumerable<T> collection)
	{
		// Ensure we aren't modifying the collection while an event is already processing.
		CheckReentrancy();

		int startCount = Items.Count;

		// Accessing the protected Items property directly which bypasses the ObservableCollection.InsertItem implementation when we .Add to it.
		// Effectively suppressing OnCollectionChanged and OnPropertyChanged for individual items.
		foreach (T item in collection)
		{
			Items.Add(item);
		}

		// Fire the events exactly only once if data was added.
		if (Items.Count > startCount)
		{
			// UI controls listen to Count and the Indexer
			OnPropertyChanged(new PropertyChangedEventArgs("Count"));
			OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));

			// Tell the view to Reload everything because the changes are too complex or numerous to list individually.
			// This is used for Sort and Search, both of workflows normally first Clear the collection and then use AddRange.
			OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
		}
	}
}
