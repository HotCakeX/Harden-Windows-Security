using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage.Pickers;
using Windows.Storage;
using System;
using System.Threading.Tasks;

namespace WDACConfig.Pages
{
    public sealed partial class GetCIHashes : Page
    {
        public GetCIHashes()
        {
            this.InitializeComponent();

            // Make sure navigating to/from this page maintains its state
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Enabled;
        }

        // Event handler for the file picker button when clicked
        private async void PickFile_Click(object sender, RoutedEventArgs e)
        {
            StorageFile? file = await PickFileAsync();
            if (file != null)
            {
                // Call the method that generates the hashes
                CodeIntegrityHashes hashes = CiFileHash.GetCiFileHashes(file.Path);

                // Display the hashes in the UI
                UpdateUIWithHashes(hashes);
            }
        }

        // Method to open the file picker and return the selected file
        private static async Task<StorageFile?> PickFileAsync()
        {
            FileOpenPicker picker = new()
            {
                SuggestedStartLocation = PickerLocationId.DocumentsLibrary
            };

            // Allow any file type
            picker.FileTypeFilter.Add("*");

            // WinUI 3 specific way to initialize picker for desktop apps
            var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(App.MainWindow);
            WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);

            return await picker.PickSingleFileAsync();
        }

        // Method to update the UI with the CodeIntegrityHashes object
        private void UpdateUIWithHashes(CodeIntegrityHashes hashes)
        {
            Sha1PageTextBox.Text = hashes.SHA1Page ?? "N/A";
            Sha256PageTextBox.Text = hashes.SHA256Page ?? "N/A";
            Sha1AuthenticodeTextBox.Text = hashes.SHa1Authenticode ?? "N/A";
            Sha256AuthenticodeTextBox.Text = hashes.SHA256Authenticode ?? "N/A";
        }

    }
}
