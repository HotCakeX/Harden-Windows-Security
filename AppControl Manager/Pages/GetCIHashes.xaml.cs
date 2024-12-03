using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages
{
    public sealed partial class GetCIHashes : Page
    {

        // Using P/Invoke because when running as Admin, WinAppSDK's file picker doesn't work.
        // https://learn.microsoft.com/en-us/uwp/api/windows.storage.pickers.filesavepicker?view=winrt-26100#in-a-desktop-app-that-requires-elevation

        public GetCIHashes()
        {
            this.InitializeComponent();
            this.NavigationCacheMode = NavigationCacheMode.Enabled;
        }

        private void PickFile_Click(object sender, RoutedEventArgs e)
        {
            string filter = "Any file (*.*)|*.*";

            string? selectedFile = FileDialogHelper.ShowFilePickerDialog(filter);

            if (!string.IsNullOrEmpty(selectedFile))
            {
                // Call the method that generates the hashes
                CodeIntegrityHashes hashes = CiFileHash.GetCiFileHashes(selectedFile);

                // Display the hashes in the UI
                UpdateUIWithHashes(hashes);
            }
        }

        private void UpdateUIWithHashes(CodeIntegrityHashes hashes)
        {
            Sha1PageTextBox.Text = hashes.SHA1Page ?? "N/A";
            Sha256PageTextBox.Text = hashes.SHA256Page ?? "N/A";
            Sha1AuthenticodeTextBox.Text = hashes.SHa1Authenticode ?? "N/A";
            Sha256AuthenticodeTextBox.Text = hashes.SHA256Authenticode ?? "N/A";
        }
    }
}
