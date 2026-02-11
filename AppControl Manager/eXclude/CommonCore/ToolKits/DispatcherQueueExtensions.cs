// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// Source: https://github.com/CommunityToolkit/Windows/blob/main/components/Extensions/src/Dispatcher/DispatcherQueueExtensions.cs
// License: https://github.com/CommunityToolkit/Windows/blob/main/License.md
// It's been modified to meet the Harden Windows Security repository's requirements.

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

using System.Threading.Tasks;
using Microsoft.UI.Dispatching;

namespace CommonCore.ToolKits;

/// <summary>
/// Helpers for executing code in a <see cref="DispatcherQueue"/>.
/// </summary>
internal static class DispatcherQueueExtensions
{
	/// <summary>
	/// Invokes a given function on the target <see cref="DispatcherQueue"/> and returns a
	/// <see cref="Task"/> that completes when the invocation of the function is completed.
	/// </summary>
	/// <param name="dispatcher">The target <see cref="DispatcherQueue"/> to invoke the code on.</param>
	/// <param name="function">The <see cref="Action"/> to invoke.</param>
	/// <param name="priority">The priority level for the function to invoke.</param>
	/// <returns>A <see cref="Task"/> that completes when the invocation of <paramref name="function"/> is over.</returns>
	/// <remarks>If the current thread has access to <paramref name="dispatcher"/>, <paramref name="function"/> will be invoked directly.</remarks>
	internal static Task EnqueueAsync(this DispatcherQueue dispatcher, Action function, DispatcherQueuePriority priority = DispatcherQueuePriority.Normal)
	{
		// Run the function directly when we have thread access.
		// Also reuse Task.CompletedTask in case of success,
		// to skip an unnecessary heap allocation for every invocation.
		if (dispatcher.HasThreadAccess)
		{
			try
			{
				function();

				return Task.CompletedTask;
			}
			catch (Exception e)
			{
				return Task.FromException(e);
			}
		}

		static Task TryEnqueueAsync(DispatcherQueue dispatcher, Action function, DispatcherQueuePriority priority)
		{
			TaskCompletionSource<object?> taskCompletionSource = new();

			if (!dispatcher.TryEnqueue(priority, () =>
			{
				try
				{
					function();

					taskCompletionSource.SetResult(null);
				}
				catch (Exception e)
				{
					taskCompletionSource.SetException(e);
				}
			}))
			{
				taskCompletionSource.SetException(new InvalidOperationException("Failed to enqueue the operation"));
			}

			return taskCompletionSource.Task;
		}

		return TryEnqueueAsync(dispatcher, function, priority);
	}

	/// <summary>
	/// Invokes a given function on the target <see cref="DispatcherQueue"/> and returns a
	/// <see cref="Task{TResult}"/> that completes when the invocation of the function is completed.
	/// </summary>
	/// <typeparam name="T">The return type of <paramref name="function"/> to relay through the returned <see cref="Task{TResult}"/>.</typeparam>
	/// <param name="dispatcher">The target <see cref="DispatcherQueue"/> to invoke the code on.</param>
	/// <param name="function">The <see cref="Func{TResult}"/> to invoke.</param>
	/// <param name="priority">The priority level for the function to invoke.</param>
	/// <returns>A <see cref="Task"/> that completes when the invocation of <paramref name="function"/> is over.</returns>
	/// <remarks>If the current thread has access to <paramref name="dispatcher"/>, <paramref name="function"/> will be invoked directly.</remarks>
	internal static Task<T> EnqueueAsync<T>(this DispatcherQueue dispatcher, Func<T> function, DispatcherQueuePriority priority = DispatcherQueuePriority.Normal)
	{
		if (dispatcher.HasThreadAccess)
		{
			try
			{
				return Task.FromResult(function());
			}
			catch (Exception e)
			{
				return Task.FromException<T>(e);
			}
		}

		static Task<T> TryEnqueueAsync(DispatcherQueue dispatcher, Func<T> function, DispatcherQueuePriority priority)
		{
			TaskCompletionSource<T> taskCompletionSource = new();

			if (!dispatcher.TryEnqueue(priority, () =>
			{
				try
				{
					taskCompletionSource.SetResult(function());
				}
				catch (Exception e)
				{
					taskCompletionSource.SetException(e);
				}
			}))
			{
				taskCompletionSource.SetException(new InvalidOperationException("Failed to enqueue the operation"));
			}

			return taskCompletionSource.Task;
		}

		return TryEnqueueAsync(dispatcher, function, priority);
	}

	/// <summary>
	/// Invokes a given function on the target <see cref="DispatcherQueue"/> and returns a
	/// <see cref="Task"/> that acts as a proxy for the one returned by the given function.
	/// </summary>
	/// <param name="dispatcher">The target <see cref="DispatcherQueue"/> to invoke the code on.</param>
	/// <param name="function">The <see cref="Func{TResult}"/> to invoke.</param>
	/// <param name="priority">The priority level for the function to invoke.</param>
	/// <returns>A <see cref="Task"/> that acts as a proxy for the one returned by <paramref name="function"/>.</returns>
	/// <remarks>If the current thread has access to <paramref name="dispatcher"/>, <paramref name="function"/> will be invoked directly.</remarks>
	internal static Task EnqueueAsync(this DispatcherQueue dispatcher, Func<Task> function, DispatcherQueuePriority priority = DispatcherQueuePriority.Normal)
	{
		// If we have thread access, we can retrieve the task directly.
		// We don't use ConfigureAwait(false) in this case, in order
		// to let the caller continue its execution on the same thread
		// after awaiting the task returned by this function.
		if (dispatcher.HasThreadAccess)
		{
			try
			{
				if (function() is Task awaitableResult)
				{
					return awaitableResult;
				}

				return Task.FromException(new InvalidOperationException("The Task returned by function cannot be null."));
			}
			catch (Exception e)
			{
				return Task.FromException(e);
			}
		}

		static Task TryEnqueueAsync(DispatcherQueue dispatcher, Func<Task> function, DispatcherQueuePriority priority)
		{
			TaskCompletionSource<object?> taskCompletionSource = new();

			if (!dispatcher.TryEnqueue(priority, async () =>
			{
				try
				{
					if (function() is Task awaitableResult)
					{
						await awaitableResult.ConfigureAwait(false);

						taskCompletionSource.SetResult(null);
					}
					else
					{
						taskCompletionSource.SetException(new InvalidOperationException("The Task returned by function cannot be null."));
					}
				}
				catch (Exception e)
				{
					taskCompletionSource.SetException(e);
				}
			}))
			{
				taskCompletionSource.SetException(new InvalidOperationException("Failed to enqueue the operation"));
			}

			return taskCompletionSource.Task;
		}

		return TryEnqueueAsync(dispatcher, function, priority);
	}

	/// <summary>
	/// Invokes a given function on the target <see cref="DispatcherQueue"/> and returns a
	/// <see cref="Task{TResult}"/> that acts as a proxy for the one returned by the given function.
	/// </summary>
	/// <typeparam name="T">The return type of <paramref name="function"/> to relay through the returned <see cref="Task{TResult}"/>.</typeparam>
	/// <param name="dispatcher">The target <see cref="DispatcherQueue"/> to invoke the code on.</param>
	/// <param name="function">The <see cref="Func{TResult}"/> to invoke.</param>
	/// <param name="priority">The priority level for the function to invoke.</param>
	/// <returns>A <see cref="Task{TResult}"/> that relays the one returned by <paramref name="function"/>.</returns>
	/// <remarks>If the current thread has access to <paramref name="dispatcher"/>, <paramref name="function"/> will be invoked directly.</remarks>
	internal static Task<T> EnqueueAsync<T>(this DispatcherQueue dispatcher, Func<Task<T>> function, DispatcherQueuePriority priority = DispatcherQueuePriority.Normal)
	{
		if (dispatcher.HasThreadAccess)
		{
			try
			{
				if (function() is Task<T> awaitableResult)
				{
					return awaitableResult;
				}

				return Task.FromException<T>(new InvalidOperationException("The Task returned by function cannot be null."));
			}
			catch (Exception e)
			{
				return Task.FromException<T>(e);
			}
		}

		static Task<T> TryEnqueueAsync(DispatcherQueue dispatcher, Func<Task<T>> function, DispatcherQueuePriority priority)
		{
			TaskCompletionSource<T> taskCompletionSource = new();

			if (!dispatcher.TryEnqueue(priority, async () =>
			{
				try
				{
					if (function() is Task<T> awaitableResult)
					{
						var result = await awaitableResult.ConfigureAwait(false);

						taskCompletionSource.SetResult(result);
					}
					else
					{
						taskCompletionSource.SetException(new InvalidOperationException("The Task returned by function cannot be null."));
					}
				}
				catch (Exception e)
				{
					taskCompletionSource.SetException(e);
				}
			}))
			{
				taskCompletionSource.SetException(new InvalidOperationException("Failed to enqueue the operation"));
			}

			return taskCompletionSource.Task;
		}

		return TryEnqueueAsync(dispatcher, function, priority);
	}
}
