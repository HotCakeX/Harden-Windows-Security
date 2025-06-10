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
using System.IO;
using System.Security.Cryptography;
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

			// Clear the UI text boxes
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

			Sha1PageProgressRingVisibility = Visibility.Visible;
			Sha256PageProgressRingVisibility = Visibility.Visible;
			Sha1AuthenticodeProgressRingVisibility = Visibility.Visible;
			Sha256AuthenticodeProgressRingVisibility = Visibility.Visible;
			Sha384AuthenticodeProgressRingVisibility = Visibility.Visible;
			Sha512AuthenticodeProgressRingVisibility = Visibility.Visible;
			Sha3_256AuthenticodeProgressRingVisibility = Visibility.Visible;
			Sha3_384AuthenticodeProgressRingVisibility = Visibility.Visible;
			Sha3_512AuthenticodeProgressRingVisibility = Visibility.Visible;

			CodeIntegrityHashesV2 hashes = await Task.Run(() => CiFileHash.GetCiFileHashesV2(selectedFile));

			// Display the hashes in the UI
			Sha1Page = hashes.SHA1Page ?? "N/A";
			Sha256Page = hashes.SHA256Page ?? "N/A";
			Sha1Authenticode = hashes.SHa1Authenticode ?? "N/A";
			Sha256Authenticode = hashes.SHA256Authenticode ?? "N/A";
			Sha384Authenticode = hashes.SHA384Authenticode ?? "N/A";
			Sha512Authenticode = hashes.SHA512Authenticode ?? "N/A";
			Sha3_256Authenticode = hashes.SHA3_256Authenticode ?? "N/A";
			Sha3_384Authenticode = hashes.SHA3_384Authenticode ?? "N/A";
			Sha3_512Authenticode = hashes.SHA3_512Authenticode ?? "N/A";

			Sha1PageProgressRingVisibility = Visibility.Collapsed;
			Sha256PageProgressRingVisibility = Visibility.Collapsed;
			Sha1AuthenticodeProgressRingVisibility = Visibility.Collapsed;
			Sha256AuthenticodeProgressRingVisibility = Visibility.Collapsed;
			Sha384AuthenticodeProgressRingVisibility = Visibility.Collapsed;
			Sha512AuthenticodeProgressRingVisibility = Visibility.Collapsed;
			Sha3_256AuthenticodeProgressRingVisibility = Visibility.Collapsed;
			Sha3_384AuthenticodeProgressRingVisibility = Visibility.Collapsed;
			Sha3_512AuthenticodeProgressRingVisibility = Visibility.Collapsed;

			string? SHA3_512Hash = null;
			string? SHA3_384Hash = null;

			if (GlobalVars.IsOlderThan24H2)
			{
				SHA3_512Hash = "Requires Windows 11 24H2 or later";
				SHA3_384Hash = "Requires Windows 11 24H2 or later";
			}
			else
			{
				SHA3384FlatHashProgressRingVisibility = Visibility.Visible;
				SHA3512FlatHashProgressRingVisibility = Visibility.Visible;

				await Task.Run(() =>
				{

					// Initializing the hash algorithms for SHA3-512 and SHA3-384
					using SHA3_512 sha3_512 = SHA3_512.Create();
					using SHA3_384 sha3_384 = SHA3_384.Create();

					// Opening the file as a stream to read it in chunks, this way we can handle large files
					using (FileStream fs = new(selectedFile, FileMode.Open, FileAccess.Read))
					{
						// Defining a buffer size of 4MB to read the file in manageable chunks
						byte[] buffer = new byte[4 * 1024 * 1024];

						int bytesRead;

						// Read the file in chunks and update the hash algorithms with the chunk data
						while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
						{
							// Update SHA3-512 hash with the current chunk
							_ = sha3_512.TransformBlock(buffer, 0, bytesRead, null, 0);

							// Update SHA3-384 hash with the current chunk
							_ = sha3_384.TransformBlock(buffer, 0, bytesRead, null, 0);
						}

						// Finalize the SHA3-512 hash computation
						_ = sha3_512.TransformFinalBlock([], 0, 0);

						// Finalize the SHA3-384 hash computation
						_ = sha3_384.TransformFinalBlock([], 0, 0);
					}

					if (sha3_512.Hash is not null)

					{   // Convert the SHA3-512 hash bytes to a hexadecimal string
						SHA3_512Hash = Convert.ToHexString(sha3_512.Hash);
					}

					if (sha3_384.Hash is not null)
					{
						// Convert the SHA3-384 hash bytes to a hexadecimal string
						SHA3_384Hash = Convert.ToHexString(sha3_384.Hash);
					}

				});

				SHA3384FlatHashProgressRingVisibility = Visibility.Collapsed;
				SHA3512FlatHashProgressRingVisibility = Visibility.Collapsed;
			}

			// Display the rest of the hashes in the UI
			SHA3384FlatHash = SHA3_384Hash ?? "N/A";
			SHA3512FlatHash = SHA3_512Hash ?? "N/A";

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
}
