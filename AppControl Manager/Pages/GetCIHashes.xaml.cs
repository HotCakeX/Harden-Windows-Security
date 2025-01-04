using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

public sealed partial class GetCIHashes : Page
{

	// Using P/Invoke because when running as Admin, WinAppSDK's file picker doesn't work.
	// https://learn.microsoft.com/en-us/uwp/api/windows.storage.pickers.filesavepicker?view=winrt-26100#in-a-desktop-app-that-requires-elevation

	public GetCIHashes()
	{
		this.InitializeComponent();
		this.NavigationCacheMode = NavigationCacheMode.Enabled;
	}

	/// <summary>
	/// Event handler for the browse button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void PickFile_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			PickFileButton.IsEnabled = false;

			string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.AnyFilePickerFilter);

			if (string.IsNullOrWhiteSpace(selectedFile))
			{
				return;
			}

			CodeIntegrityHashes hashes = await Task.Run(() => CiFileHash.GetCiFileHashes(selectedFile));

			string? SHA3_512Hash = null;
			string? SHA3_384Hash = null;

			if (GlobalVars.IsOlderThan24H2)
			{
				SHA3_512Hash = "Requires Windows 11 24H2 or later";
				SHA3_384Hash = "Requires Windows 11 24H2 or later";
			}
			else
			{

				await Task.Run(() =>
				{

					// Read the file as a byte array - This way we can get hashes of a file in use by another process
					byte[] Bytes = File.ReadAllBytes(selectedFile);

					// Compute the hash of the byte array
					Byte[] SHA3_512HashBytes = SHA3_512.HashData(Bytes);

					// Convert the hash bytes to a hexadecimal string to make it look like the output of the Get-FileHash which produces hexadecimals (0-9 and A-F)
					// If System.Convert.ToBase64String was used, it'd return the hash in base64 format, which uses 64 symbols (A-Z, a-z, 0-9, + and /) to represent each byte
					String HashString_SHA3_512 = BitConverter.ToString(SHA3_512HashBytes);

					// Remove the dashes from the hexadecimal string
					SHA3_512Hash = HashString_SHA3_512.Replace("-", "", StringComparison.OrdinalIgnoreCase);


					Byte[] SHA3_384HashBytes = SHA3_384.HashData(Bytes);
					String HashString_SHA3_384 = BitConverter.ToString(SHA3_384HashBytes);
					SHA3_384Hash = HashString_SHA3_384.Replace("-", "", StringComparison.OrdinalIgnoreCase);
				});
			}

			// Display the hashes in the UI
			Sha1PageTextBox.Text = hashes.SHA1Page ?? "N/A";
			Sha256PageTextBox.Text = hashes.SHA256Page ?? "N/A";
			Sha1AuthenticodeTextBox.Text = hashes.SHa1Authenticode ?? "N/A";
			Sha256AuthenticodeTextBox.Text = hashes.SHA256Authenticode ?? "N/A";
			SHA3384FlatHash.Text = SHA3_384Hash ?? "N/A";
			SHA3512FlatHash.Text = SHA3_512Hash ?? "N/A";
		}
		finally
		{
			PickFileButton.IsEnabled = true;
		}
	}

}
