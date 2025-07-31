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

using System;
using System.Threading.Tasks;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using HardenWindowsSecurity.Helpers;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenWindowsSecurity.ViewModels;

internal sealed partial class FileReputationVM : ViewModelBase
{

	internal FileReputationVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			null, null);

	}

	/// <summary>
	/// The main InfoBar for this VM.
	/// </summary>
	internal readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	internal Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool ElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ProgressBarVisibility = field ? Visibility.Collapsed : Visibility.Visible;
			}
		}
	} = true;

	// UI Bound text box properties
	internal string? ReputationText { get; set => SP(ref field, value); }
	internal string? SourceText { get; set => SP(ref field, value); }
	internal string? DurationText { get; set => SP(ref field, value); }
	internal string? HandleText { get; set => SP(ref field, value); }

	/// <summary>
	/// Event handler for the browse button
	/// </summary>
	internal async void BrowseForFile()
	{

		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.AnyFilePickerFilter);

		if (string.IsNullOrEmpty(selectedFile))
		{
			return;
		}

		try
		{

			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			FileTrustChecker.FileTrustResult? result = await Task.Run(() => FileTrustChecker.CheckFileTrust(selectedFile));

			ReputationText = result?.Reputation;
			SourceText = result?.Source.ToString();
			DurationText = result?.Duration;
			HandleText = result?.Handle;

		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	// Event handlers for the copy buttons
	internal void CopyReputationToClipboard() => ClipboardManagement.CopyText(ReputationText);
	internal void CopySourceToClipboard() => ClipboardManagement.CopyText(SourceText);
	internal void CopyDurationToClipboard() => ClipboardManagement.CopyText(DurationText);
	internal void CopyHandleToClipboard() => ClipboardManagement.CopyText(HandleText);

}
