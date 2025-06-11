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
using AppControlManager.Main;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

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
			null, null);
	}

	private readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	#region UI-Bound Properties

	internal bool PickFileButtonIsEnabled
	{
		get; set => SP(ref field, value);
	} = true;

	internal string? Sha1Page { get; set => SP(ref field, value); }

	internal Visibility Sha1PageProgressRingVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	internal string? Sha256Page { get; set => SP(ref field, value); }

	internal Visibility Sha256PageProgressRingVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	internal string? Sha1Authenticode { get; set => SP(ref field, value); }

	internal Visibility Sha1AuthenticodeProgressRingVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	internal string? Sha256Authenticode { get; set => SP(ref field, value); }

	internal Visibility Sha256AuthenticodeProgressRingVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	internal string? Sha384Authenticode { get; set => SP(ref field, value); }

	internal Visibility Sha384AuthenticodeProgressRingVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	internal string? Sha512Authenticode { get; set => SP(ref field, value); }

	internal Visibility Sha512AuthenticodeProgressRingVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	internal string? Sha3_256Authenticode { get; set => SP(ref field, value); }

	internal Visibility Sha3_256AuthenticodeProgressRingVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	internal string? Sha3_384Authenticode { get; set => SP(ref field, value); }

	internal Visibility Sha3_384AuthenticodeProgressRingVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	internal string? Sha3_512Authenticode { get; set => SP(ref field, value); }

	internal Visibility Sha3_512AuthenticodeProgressRingVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	internal string? SHA3384FlatHash { get; set => SP(ref field, value); }

	internal Visibility SHA3384FlatHashProgressRingVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	internal string? SHA3512FlatHash { get; set => SP(ref field, value); }

	internal Visibility SHA3512FlatHashProgressRingVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	#endregion

	private string? selectedFile;

	private async Task Calculate()
	{
		try
		{
			PickFileButtonIsEnabled = false;

			if (string.IsNullOrWhiteSpace(selectedFile))
			{
				return;
			}

			ClearTextBoxes();

			ManageProgressRingVisibility(Visibility.Visible);

			CodeIntegrityHashesV2 hashes = await Task.Run(() => CiFileHash.GetCiFileHashesV2(selectedFile));

			// Display the hashes in the UI
			Sha1Page = hashes.SHA1Page;
			Sha256Page = hashes.SHA256Page;
			Sha1Authenticode = hashes.SHa1Authenticode;
			Sha256Authenticode = hashes.SHA256Authenticode;
			Sha384Authenticode = hashes.SHA384Authenticode;
			Sha512Authenticode = hashes.SHA512Authenticode;
			Sha3_256Authenticode = hashes.SHA3_256Authenticode;
			Sha3_384Authenticode = hashes.SHA3_384Authenticode;
			Sha3_512Authenticode = hashes.SHA3_512Authenticode;
			SHA3384FlatHash = hashes.SHA3_384_Flat;
			SHA3512FlatHash = hashes.SHA3_512_Flat;

			await PublishUserActivityAsync(LaunchProtocolActions.FileHashes,
				selectedFile,
				GlobalVars.Rizz.GetString("UserActivityNameForFileHashes"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ManageProgressRingVisibility(Visibility.Collapsed);
			PickFileButtonIsEnabled = true;
		}
	}

	/// <summary>
	/// Event handler for the browse button
	/// </summary>
	internal async void PickFile_Click()
	{
		selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.AnyFilePickerFilter);

		await Calculate();
	}

	/// <summary>
	/// Event handler for the clear button
	/// </summary>
	internal void Clear_Click()
	{
		ClearTextBoxes();

		// Ensure all progress rings are hidden
		ManageProgressRingVisibility(Visibility.Collapsed);

		// Clear the selected file
		selectedFile = null;
	}

	/// <summary>
	/// The method used to open the GetCIHashes page from other parts of the application.
	/// </summary>
	/// <param name="filePath"></param>
	/// <returns></returns>
	internal async Task OpenInGetCIHashes(string filePath)
	{
		try
		{
			// Navigate to the Get CI Hashes page
			App._nav.Navigate(typeof(Pages.GetCIHashes), null);

			selectedFile = filePath;

			await Calculate();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Clear all hash text boxes
	/// </summary>
	private void ClearTextBoxes()
	{
		Sha1Page = null;
		Sha256Page = null;
		Sha1Authenticode = null;
		Sha256Authenticode = null;
		Sha384Authenticode = null;
		Sha512Authenticode = null;
		Sha3_256Authenticode = null;
		Sha3_384Authenticode = null;
		Sha3_512Authenticode = null;
		SHA3384FlatHash = null;
		SHA3512FlatHash = null;
	}

	private void ManageProgressRingVisibility(Visibility visibility)
	{
		Sha1PageProgressRingVisibility = visibility;
		Sha256PageProgressRingVisibility = visibility;
		Sha1AuthenticodeProgressRingVisibility = visibility;
		Sha256AuthenticodeProgressRingVisibility = visibility;
		Sha384AuthenticodeProgressRingVisibility = visibility;
		Sha512AuthenticodeProgressRingVisibility = visibility;
		Sha3_256AuthenticodeProgressRingVisibility = visibility;
		Sha3_384AuthenticodeProgressRingVisibility = visibility;
		Sha3_512AuthenticodeProgressRingVisibility = visibility;
		SHA3384FlatHashProgressRingVisibility = visibility;
		SHA3512FlatHashProgressRingVisibility = visibility;
	}
}
