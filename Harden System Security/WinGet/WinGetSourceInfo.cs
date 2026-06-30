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

using Microsoft.Management.Deployment;
using Microsoft.UI.Xaml;
using Windows.Foundation;

namespace HardenSystemSecurity.WinGet;

internal sealed partial class WinGetSourceInfo : ViewModelBase
{
	internal required PackageCatalogReference CatalogReference { get; set; }

	internal string Name { get; set => SP(ref field, value); } = string.Empty;
	internal string Type { get; set => SP(ref field, value); } = string.Empty;
	internal string Argument { get; set => SP(ref field, value); } = string.Empty;
	internal string Origin { get; set => SP(ref field, value); } = string.Empty;
	internal string TrustLevel { get; set => SP(ref field, value); } = string.Empty;
	internal string Status { get; set => SP(ref field, value); } = string.Empty;
	internal IAsyncInfo? SourceOperation { get; private set; }
	internal bool IsOperationCancellationRequested { get; private set; }

	internal bool IsOperationRunning
	{
		get; set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(IsActionEnabled));
				OnPropertyChanged(nameof(IsOperationCancellationAvailable));
				OnPropertyChanged(nameof(OperationCancelButtonVisibility));
			}
		}
	}

	internal bool IsActionEnabled => !IsOperationRunning && !string.IsNullOrWhiteSpace(Name);
	internal bool IsOperationCancellationAvailable => IsOperationRunning && SourceOperation is not null;
	internal Visibility OperationCancelButtonVisibility => IsOperationCancellationAvailable ? Visibility.Visible : Visibility.Collapsed;

	internal void BeginOperation(IAsyncInfo sourceOperation)
	{
		IsOperationCancellationRequested = false;
		SourceOperation = sourceOperation;
		OnPropertyChanged(nameof(IsOperationCancellationAvailable));
		OnPropertyChanged(nameof(OperationCancelButtonVisibility));
	}

	internal void CancelOperation()
	{
		IAsyncInfo? sourceOperation = SourceOperation;
		if (sourceOperation is null)
		{
			return;
		}

		IsOperationCancellationRequested = true;
		Status = "Canceling source operation.";

		try
		{
			sourceOperation.Cancel();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	internal void EndOperation()
	{
		SourceOperation = null;
		IsOperationCancellationRequested = false;
		OnPropertyChanged(nameof(IsOperationCancellationAvailable));
		OnPropertyChanged(nameof(OperationCancelButtonVisibility));
	}
}
