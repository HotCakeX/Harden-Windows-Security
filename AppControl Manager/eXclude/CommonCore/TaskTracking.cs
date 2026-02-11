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

using System.Threading;
using AppControlManager.ViewModels;

namespace CommonCore;

internal static class TaskTracking
{
	/// <summary>
	/// The backing counter for active operations.
	/// </summary>
	private static int _activeOperationsCount;

	/// <summary>
	/// Returns true if there is at least one active operation.
	/// </summary>
	internal static bool AppNeedsCloseConfirmation => AppNeedsCloseConfirmationVerdict();

	private static bool AppNeedsCloseConfirmationVerdict()
	{
#if APP_CONTROL_MANAGER
		// If there are any active operations or there are policies in the Sidebar library and Persistent library option is not enabled meaning app restart will cause all in-memory policies in the library to be lost.
		return Volatile.Read(ref _activeOperationsCount) > 0 || (ViewModelProvider.MainWindowVM.SidebarPoliciesLibrary.Count > 0 && !GlobalVars.Settings.PersistentPoliciesLibrary);
#else
		return Volatile.Read(ref _activeOperationsCount) > 0;
#endif
	}

	/// <summary>
	/// Registers a new operation and returns a disposable object.
	/// When the 'using' block ends, the operation is automatically unregistered.
	/// </summary>
	internal static IDisposable RegisterOperation() => new OperationGuard();

	/// <summary>
	/// Struct to handle the start/end of operations.
	/// </summary>
	private readonly struct OperationGuard : IDisposable
	{
		public OperationGuard()
		{
			// Increment when created
			_ = Interlocked.Increment(ref _activeOperationsCount);

			// Set the active badge
			Taskbar.Badge.SetBadgeAsActive();
		}

		public void Dispose()
		{
			// Decrement when disposed
			if (Interlocked.Decrement(ref _activeOperationsCount) == 0)
			{
				// Clear the active badge if no more active operations
				Taskbar.Badge.ClearBadge();
			}
		}
	}
}
