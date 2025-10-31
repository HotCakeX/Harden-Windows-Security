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
using System.Threading.Tasks;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using HardenSystemSecurity.Helpers;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class FileReputationVM : ViewModelBase
{

	internal FileReputationVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

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
	/// Handles when files are dragged over the page.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void OnDragOver(object sender, DragEventArgs e)
	{
		if (e.DataView.Contains(StandardDataFormats.StorageItems))
		{
			e.AcceptedOperation = DataPackageOperation.Copy;
			e.DragUIOverride.Caption = GlobalVars.GetStr("DragAndDropHintFileReputationCaption");
			e.DragUIOverride.IsCaptionVisible = true;
			e.DragUIOverride.IsContentVisible = true;
		}
		else
		{
			e.AcceptedOperation = DataPackageOperation.None;
		}
	}

	/// <summary>
	/// Handles when files are dropped on the page.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal async void OnDrop(object sender, DragEventArgs e)
	{
		if (e.DataView.Contains(StandardDataFormats.StorageItems))
		{
			try
			{
				IReadOnlyList<IStorageItem> items = await e.DataView.GetStorageItemsAsync();

				if (items.Count > 0 && items[0] is StorageFile file)
				{
					await ProcessFile(file.Path);
				}
			}
			catch (Exception ex)
			{
				MainInfoBar.WriteError(ex);
			}
		}
	}

	/// <summary>
	/// Processes the selected file.
	/// </summary>
	/// <param name="filePath">Path to the file to process</param>
	private async Task ProcessFile(string filePath)
	{
		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			FileTrustChecker.FileTrustResult? result = await Task.Run(() => FileTrustChecker.CheckFileTrust(filePath));

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

	/// <summary>
	/// Event handler for the browse button.
	/// </summary>
	internal async void BrowseForFile()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.AnyFilePickerFilter);

		if (string.IsNullOrEmpty(selectedFile))
		{
			return;
		}

		await ProcessFile(selectedFile);
	}

	// Event handlers for the copy buttons
	internal void CopyReputationToClipboard() => ClipboardManagement.CopyText(ReputationText);
	internal void CopySourceToClipboard() => ClipboardManagement.CopyText(SourceText);
	internal void CopyDurationToClipboard() => ClipboardManagement.CopyText(DurationText);
	internal void CopyHandleToClipboard() => ClipboardManagement.CopyText(HandleText);

}
