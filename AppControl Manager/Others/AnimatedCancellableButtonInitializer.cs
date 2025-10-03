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
using System.Threading.Tasks;
using AppControlManager.ViewModels;

namespace AppControlManager.Others;

/// <summary>
/// Creates the necessary backing fields for XAML compiled bindings to store the animated cancellable button's states
/// in the View Model so that it won't rely on the navigation cache to remember its important properties' values.
/// </summary>
/// <param name="buttonContent"></param>
internal sealed partial class AnimatedCancellableButtonInitializer(string buttonContent) : ViewModelBase
{

	internal bool wasCancelled;

	internal CancellationTokenSource? Cts { get; set; }

	internal Func<Task> Cancel => async () =>
	{
		try
		{
			// Set the cancelling state when cancel is requested
			InternalIsCancellingState = true;

			if (Cts is not null)
			{
				await Cts.CancelAsync();
			}
		}
		catch
		{
		}
	};

	internal bool IsOperationInProgress { get; set => SP(ref field, value); }

	internal bool IsCancelState { get; set => SP(ref field, value); }

	internal bool IsCancellingState { get; set => SP(ref field, value); }

	internal bool IsAnimating { get; set => SP(ref field, value); }

	internal string ButtonContent { get; set => SP(ref field, value); } = buttonContent;

	internal string OriginalText { get; set => SP(ref field, value); } = buttonContent;

	internal bool InternalIsCancelState { get; set => SP(ref field, value); }

	internal bool InternalIsCancellingState { get; set => SP(ref field, value); }

	internal bool InternalIsAnimating { get; set => SP(ref field, value); }

	internal bool InternalIsOperationInProgress { get; set => SP(ref field, value); }

	internal bool InternalSuppressExternalClick { get; set => SP(ref field, value); }

	internal bool ShadowAnimationRunning { get; set => SP(ref field, value); }

	internal bool OperationStarted { get; set => SP(ref field, value); }


	internal void Begin()
	{
		wasCancelled = false;

		// Create and assign cancellation token source for this operation
		Cts?.Dispose();
		Cts = new CancellationTokenSource();

		IsOperationInProgress = true;
		IsCancelState = true;
		IsCancellingState = false;
		IsAnimating = false;
		InternalIsOperationInProgress = true;
		InternalIsCancelState = true;
		InternalIsCancellingState = false;
		InternalIsAnimating = false;
		InternalSuppressExternalClick = false;
		ShadowAnimationRunning = true;
		OperationStarted = true;
	}

	internal void End()
	{
		// Clean up the cancellation token source
		Cts?.Dispose();
		Cts = null;

		IsOperationInProgress = false;
		IsCancelState = false;
		IsCancellingState = false;
		IsAnimating = false;
		InternalIsOperationInProgress = false;
		InternalIsCancelState = false;
		InternalIsCancellingState = false;
		InternalIsAnimating = false;
		InternalSuppressExternalClick = false;
		ShadowAnimationRunning = false;
		OperationStarted = false;
	}

}
