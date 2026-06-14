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
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using AppControlManager.Main;
using AppControlManager.Others;
using Microsoft.UI.Xaml;

namespace AppControlManager.ViewModels;

internal sealed partial class BuildNewCertificateVM : ViewModelBase
{
	internal readonly InfoBarSettings MainInfoBar = new();

	/// <summary>
	/// To save the generated certificate's thumb print
	/// </summary>
	internal string? generatedCertThumbPrint { get; set => SP(ref field, value); }

	/// <summary>
	/// Gets or sets the visibility state of the progress ring.
	/// </summary>
	internal Visibility ProgressRingVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	/// <summary>
	/// Gets or sets the visibility of the "Copy to Clipboard" button in the information bar.
	/// </summary>
	internal Visibility CopyInfoBarToClipboardButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	/// <summary>
	/// Enables/Disables the UI elements during an ongoing operation.
	/// </summary>
	internal bool ElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				MainInfoBar.IsClosable = field;
				ProgressRingVisibility = field ? Visibility.Collapsed : Visibility.Visible;
			}
		}
	} = true;

	private enum HashAlgorithm
	{
		SHA2_256 = 0,
		SHA2_384 = 1,
		SHA2_512 = 2,
		SHA3_256 = 3,
		SHA3_384 = 4,
		SHA3_512 = 5
	}

	private readonly Dictionary<HashAlgorithm, HashAlgorithmName> AlgoCorrelation = new() {
		{ HashAlgorithm.SHA2_256, HashAlgorithmName.SHA256 },
		{ HashAlgorithm.SHA2_384, HashAlgorithmName.SHA384 },
		{ HashAlgorithm.SHA2_512, HashAlgorithmName.SHA512 },
		{ HashAlgorithm.SHA3_256, HashAlgorithmName.SHA3_256 },
		{ HashAlgorithm.SHA3_384, HashAlgorithmName.SHA3_384 },
		{ HashAlgorithm.SHA3_512, HashAlgorithmName.SHA3_512 }
	};

	internal string? CommonName { get; set => SPT(ref field, value); }
	internal string? Password { get; set => SPT(ref field, value); }
	internal string KeySizeComboBoxSelectedItem { get; set => SP(ref field, value); } = "4096";
	internal double Validity { get; set => SP(ref field, value); } = 100;
	internal int SelectedHashAlgorithm
	{
		get; set
		{
			if (SP(ref field, value))
			{
				if (field > 2)
				{
					MainInfoBar.WriteWarning(Atlas.GetStr("AlgoNotSupportedByCIWarning"));
				}
				else
				{
					MainInfoBar.IsOpen = false;
				}
			}
		}
	} = 2;

	/// <summary>
	/// Event handler for the main build button
	/// </summary>
	internal async void BuildCertificateButton_Click()
	{
		CopyInfoBarToClipboardButtonVisibility = Visibility.Collapsed;

		if (string.IsNullOrEmpty(CommonName) || string.IsNullOrEmpty(Password))
		{
			MainInfoBar.WriteWarning(Atlas.GetStr("ProvideCNOrPassErrorMsg"),
				Atlas.GetStr("ProvideCNOrPassErrorTitle"));
			return;
		}

		// Track whether errors occurred
		bool ErrorsOccurred = false;

		try
		{
			generatedCertThumbPrint = null;

			ElementsAreEnabled = false;

			MainInfoBar.WriteInfo(Atlas.GetStr("BuildingCertificate"),
				Atlas.GetStr("ProcessingTitle"));

			await Task.Run(() =>
			{
				using X509Certificate2 generatedCert = CertificateGenerator.BuildAppControlCertificate(
					 CommonName,
					 Password,
					 (int)Validity,
					 int.Parse(KeySizeComboBoxSelectedItem),
					 AlgoCorrelation[(HashAlgorithm)SelectedHashAlgorithm]
					 );

				generatedCertThumbPrint = generatedCert.Thumbprint;

				SigningCertificateCNToUseForSigning = CommonName;
			});
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, Atlas.GetStr("CertificateBuildError"),
				Atlas.GetStr("ErrorTitle"));
			ErrorsOccurred = true;
		}
		finally
		{
			ElementsAreEnabled = true;

			if (!ErrorsOccurred)
			{
				MainInfoBar.WriteSuccess(Atlas.GetStr("CertificateBuildSuccess") + generatedCertThumbPrint + "'",
					Atlas.GetStr("SuccessText"));

				CopyInfoBarToClipboardButtonVisibility = Visibility.Visible;
			}
		}
	}

	/// <summary>
	/// Copies the thumbprint of the generated certificate to the clipboard.
	/// </summary>
	internal void CopyInfoBarToClipboardButton_Click() => ClipboardManagement.CopyText(generatedCertThumbPrint);

	#region Signing

	// Paths of files to be signed.
	internal readonly UniqueStringObservableCollection SelectedFilesToSign = [];

	// Paths of folders where files will be signed.
	internal readonly UniqueStringObservableCollection SelectedFoldersToSign = [];

	internal string? SigningCertificateCNToUseForSigning { get; set => SP(ref field, value); }

	internal string? SigningTimestampUrl { get; set => SP(ref field, value); }
	internal bool EnablePageHashing { get; set => SP(ref field, value); }

	internal void Clear_SelectedFilesToSign() => SelectedFilesToSign.Clear();
	internal void Clear_SelectedFoldersToSign() => SelectedFoldersToSign.Clear();

	internal void BrowseForScriptFilesButton_Click()
	{
		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(Atlas.AnyFilePickerFilter);

		foreach (string file in CollectionsMarshal.AsSpan(selectedFiles))
		{
			SelectedFilesToSign.Add(file);
		}
	}

	internal void BrowseForScriptFoldersButton_Click()
	{
		List<string> selectedFolders = FileDialogHelper.ShowMultipleDirectoryPickerDialog();

		foreach (string folder in CollectionsMarshal.AsSpan(selectedFolders))
		{
			SelectedFoldersToSign.Add(folder);
		}
	}

	internal void CommonNameTextBox_Loaded()
	{
		if (string.IsNullOrWhiteSpace(SigningCertificateCNToUseForSigning))
		{
			UserConfiguration configuration = UserConfiguration.Get();
			SigningCertificateCNToUseForSigning = configuration.CertificateCommonName;
		}
	}

	/// <summary>
	/// Signs the selected files.
	/// </summary>
	internal async void SignFilesButton_Click()
	{
		try
		{
			CopyInfoBarToClipboardButtonVisibility = Visibility.Collapsed;
			ElementsAreEnabled = false;

			await Task.Run(() =>
			{
				// Validate the TimeStamp URl
				string? timestampUrl = string.IsNullOrWhiteSpace(SigningTimestampUrl) ? null : SigningTimestampUrl;

				(IEnumerable<string>, int) files = FileUtility.GetFilesFast(
					directories: SelectedFoldersToSign.UniqueItems,
					files: SelectedFilesToSign.UniqueItems,
					extensionsToFilterBy: [".sys", ".exe", ".com", ".dll", ".msi", ".js", ".ps1", ".psm1", ".psd1"]);

				if (files.Item2 == 0)
				{
					throw new InvalidOperationException("No valid files were found to sign.");
				}

				MainInfoBar.WriteInfo($"Signing {files.Item2} files...");

				CommonCore.Signing.Main.SignPEs(
					FilePaths: files.Item1.ToList(),
					Cert: null,
					CertCN: SigningCertificateCNToUseForSigning,
					timestampUrl: timestampUrl,
					EnablePageHashing: EnablePageHashing);

				MainInfoBar.WriteSuccess("Signing process completed.");
			});
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	#endregion

}
