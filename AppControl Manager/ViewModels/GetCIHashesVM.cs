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
using System.Threading.Tasks;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.Pages;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;

namespace AppControlManager.ViewModels;

internal sealed partial class GetCIHashesVM : ViewModelBase
{
	internal GetCIHashesVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		InitializeHashItems();
	}

	private readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	#region UI-Bound Properties

	internal bool ElementsAreEnabled { get; set => SP(ref field, value); } = true;

	internal ObservableCollection<HashCardItem> HashItems { get; } = [];

	internal HashCardItem? SelectedHashItem { get; set => SP(ref field, value); }

	#endregion

	internal string? selectedFile { get; set => SP(ref field, value); }

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
			e.DragUIOverride.Caption = GlobalVars.GetStr("DragAndDropHintGetHashesCaption");
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
					selectedFile = file.Path;
					await Calculate();
				}
			}
			catch (Exception ex)
			{
				MainInfoBar.WriteError(ex);
			}
		}
	}

	private void InitializeHashItems()
	{
		HashItems.Add(new HashCardItem
		{
			DisplayName = "SHA1-160-Page",
			AlgorithmName = "SHA1",
			HashTypeName = " 160-Page",
			HashType = "Header Page",
			HashKey = "Sha1Page",
			KeySize = "160",
			HashValue = string.Empty,
			ProgressRingVisibility = Visibility.Collapsed
		});
		HashItems.Add(new HashCardItem
		{
			DisplayName = "SHA2-256-Page",
			AlgorithmName = "SHA2",
			HashTypeName = " 256-Page",
			HashType = "Header Page",
			HashKey = "Sha256Page",
			KeySize = "256",
			HashValue = string.Empty,
			ProgressRingVisibility = Visibility.Collapsed
		});
		HashItems.Add(new HashCardItem
		{
			DisplayName = "SHA1-160-Authenticode",
			AlgorithmName = "SHA1",
			HashTypeName = " 160-Authenticode",
			HashType = "Authenticode",
			HashKey = "Sha1Authenticode",
			KeySize = "160",
			HashValue = string.Empty,
			ProgressRingVisibility = Visibility.Collapsed
		});
		HashItems.Add(new HashCardItem
		{
			DisplayName = "SHA2-256-Authenticode",
			AlgorithmName = "SHA2",
			HashTypeName = " 256-Authenticode",
			HashType = "Authenticode",
			HashKey = "Sha256Authenticode",
			KeySize = "256",
			HashValue = string.Empty,
			ProgressRingVisibility = Visibility.Collapsed
		});
		HashItems.Add(new HashCardItem
		{
			DisplayName = "SHA2-384-Authenticode",
			AlgorithmName = "SHA2",
			HashTypeName = " 384-Authenticode",
			HashType = "Authenticode",
			HashKey = "Sha384Authenticode",
			KeySize = "384",
			HashValue = string.Empty,
			ProgressRingVisibility = Visibility.Collapsed
		});
		HashItems.Add(new HashCardItem
		{
			DisplayName = "SHA2-512-Authenticode",
			AlgorithmName = "SHA2",
			HashTypeName = " 512-Authenticode",
			HashType = "Authenticode",
			HashKey = "Sha512Authenticode",
			KeySize = "512",
			HashValue = string.Empty,
			ProgressRingVisibility = Visibility.Collapsed
		});
		HashItems.Add(new HashCardItem
		{
			DisplayName = "SHA3-256-Authenticode",
			AlgorithmName = "SHA3",
			HashTypeName = " 256-Authenticode",
			HashType = "Authenticode",
			HashKey = "Sha3_256Authenticode",
			KeySize = "256",
			HashValue = string.Empty,
			ProgressRingVisibility = Visibility.Collapsed
		});
		HashItems.Add(new HashCardItem
		{
			DisplayName = "SHA3-384-Authenticode",
			AlgorithmName = "SHA3",
			HashTypeName = " 384-Authenticode",
			HashType = "Authenticode",
			HashKey = "Sha3_384Authenticode",
			KeySize = "384",
			HashValue = string.Empty,
			ProgressRingVisibility = Visibility.Collapsed
		});
		HashItems.Add(new HashCardItem
		{
			DisplayName = "SHA3-512-Authenticode",
			AlgorithmName = "SHA3",
			HashTypeName = " 512-Authenticode",
			HashType = "Authenticode",
			HashKey = "Sha3_512Authenticode",
			KeySize = "512",
			HashValue = string.Empty,
			ProgressRingVisibility = Visibility.Collapsed
		});
		HashItems.Add(new HashCardItem
		{
			DisplayName = "SHA3-384-Flat",
			AlgorithmName = "SHA3",
			HashTypeName = " 384-Flat",
			HashType = "Flat",
			HashKey = "SHA3384FlatHash",
			KeySize = "384",
			HashValue = string.Empty,
			ProgressRingVisibility = Visibility.Collapsed
		});
		HashItems.Add(new HashCardItem
		{
			DisplayName = "SHA3-512-Flat",
			AlgorithmName = "SHA3",
			HashTypeName = " 512-Flat",
			HashType = "Flat",
			HashKey = "SHA3512FlatHash",
			KeySize = "512",
			HashValue = string.Empty,
			ProgressRingVisibility = Visibility.Collapsed
		});
	}

	private async Task Calculate()
	{
		try
		{
			ElementsAreEnabled = false;

			if (string.IsNullOrWhiteSpace(selectedFile))
			{
				return;
			}

			ClearHashValues();
			ManageProgressRingVisibility(Visibility.Visible);

			CodeIntegrityHashesV2 hashes = await Task.Run(() => CiFileHash.GetCiFileHashesV2(selectedFile));

			HashItems[0].HashValue = hashes.SHA1Page ?? string.Empty;
			HashItems[1].HashValue = hashes.SHA256Page ?? string.Empty;
			HashItems[2].HashValue = hashes.SHA1Authenticode ?? string.Empty;
			HashItems[3].HashValue = hashes.SHA256Authenticode ?? string.Empty;
			HashItems[4].HashValue = hashes.SHA384Authenticode ?? string.Empty;
			HashItems[5].HashValue = hashes.SHA512Authenticode ?? string.Empty;
			HashItems[6].HashValue = hashes.SHA3_256Authenticode ?? string.Empty;
			HashItems[7].HashValue = hashes.SHA3_384Authenticode ?? string.Empty;
			HashItems[8].HashValue = hashes.SHA3_512Authenticode ?? string.Empty;
			HashItems[9].HashValue = hashes.SHA3_384_Flat ?? string.Empty;
			HashItems[10].HashValue = hashes.SHA3_512_Flat ?? string.Empty;

			await PublishUserActivityAsync(
				LaunchProtocolActions.FileHashes,
				selectedFile,
				GlobalVars.GetStr("UserActivityNameForFileHashes"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ManageProgressRingVisibility(Visibility.Collapsed);
			ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Event handler for the browse button
	/// </summary>
	internal async void PickFile_Click()
	{
		try
		{
			selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.AnyFilePickerFilter);
			await Calculate();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Event handler for the clear button
	/// </summary>
	internal void Clear_Click()
	{
		ClearHashValues();
		ManageProgressRingVisibility(Visibility.Collapsed);
		selectedFile = null;
		SelectedHashItem = null;
	}

	/// <summary>
	/// The method used to open the <see cref="GetCIHashes"/> page from other parts of the application.
	/// </summary>
	/// <param name="filePath"></param>
	/// <returns></returns>
	internal async Task OpenInGetCIHashes(string? filePath)
	{
		try
		{
			ViewModelProvider.NavigationService.Navigate(typeof(GetCIHashes), null);
			selectedFile = filePath;
			await Calculate();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Clear all hash values
	/// </summary>
	private void ClearHashValues()
	{
		foreach (HashCardItem item in HashItems)
		{
			item.HashValue = string.Empty;
		}
	}

	private void ManageProgressRingVisibility(Visibility visibility)
	{
		foreach (HashCardItem item in HashItems)
		{
			item.ProgressRingVisibility = visibility;
		}
	}

	internal void CopyButton_Click()
	{
		if (SelectedHashItem != null && !string.IsNullOrEmpty(SelectedHashItem.HashValue))
		{
			ClipboardManagement.CopyText(SelectedHashItem.HashValue);

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("HashCopiedToClipboard"));
		}
	}

	internal void ClearSelectedFilePath() => selectedFile = null;
}
