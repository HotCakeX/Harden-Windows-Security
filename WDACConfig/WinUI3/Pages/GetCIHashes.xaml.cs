using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

#pragma warning disable CA1401

namespace WDACConfig.Pages
{
    public sealed partial class GetCIHashes : Page
    {

        // Using P/Invoke because when running as Admin, WinAppSDK's file picker doesn't work.
        // https://learn.microsoft.com/en-us/uwp/api/windows.storage.pickers.filesavepicker?view=winrt-26100#in-a-desktop-app-that-requires-elevation

        /*

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct OPENFILENAME
        {
            public int lStructSize;
            public IntPtr hwndOwner;
            public IntPtr hInstance;
            public string lpstrFilter;
            public string lpstrCustomFilter;
            public int nMaxCustFilter;
            public int nFilterIndex;
            public string lpstrFile;
            public int nMaxFile;
            public string lpstrFileTitle;
            public int nMaxFileTitle;
            public string lpstrInitialDir;
            public string lpstrTitle;
            public int Flags;
            public ushort nFileOffset;
            public ushort nFileExtension;
            public string lpstrDefExt;
            public IntPtr lCustData;
            public IntPtr lpfnHook;
            public string lpTemplateName;
            public IntPtr pvReserved;
            public int dwReserved;
            public int FlagsEx;
        }

        private const int OFN_EXPLORER = 0x00080000;
        private const int OFN_FILEMUSTEXIST = 0x00001000;
        private const int OFN_PATHMUSTEXIST = 0x00000800;
        // private const int OFN_ALLOWMULTISELECT = 0x00000200;

        private const int MAX_PATH = 260;

        [DllImport("comdlg32.dll", CharSet = CharSet.Auto)]
        public static extern bool GetOpenFileName(ref OPENFILENAME ofn);

        */

        public GetCIHashes()
        {
            this.InitializeComponent();
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Enabled;
        }

        private void PickFile_Click(object sender, RoutedEventArgs e)
        {
            string? selectedFile = WDACConfig.FilePicker.ShowFilePicker();
            if (!string.IsNullOrEmpty(selectedFile))
            {
                // Call the method that generates the hashes
                CodeIntegrityHashes hashes = CiFileHash.GetCiFileHashes(selectedFile);

                // Display the hashes in the UI
                UpdateUIWithHashes(hashes);
            }
        }

        /*

        private static string? OpenFileDialog()
        {
            OPENFILENAME ofn = new()
            {
                lStructSize = Marshal.SizeOf(typeof(OPENFILENAME)),
                hwndOwner = IntPtr.Zero,
                lpstrFilter = "All Files (*.*)\0*.*\0",
                lpstrFile = new string('\0', MAX_PATH),
                nMaxFile = MAX_PATH,
                lpstrTitle = "Select a file",
                Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST
            };

            if (GetOpenFileName(ref ofn))
            {
                return ofn.lpstrFile;
            }
            return null;
        }

        */

        private void UpdateUIWithHashes(CodeIntegrityHashes hashes)
        {
            Sha1PageTextBox.Text = hashes.SHA1Page ?? "N/A";
            Sha256PageTextBox.Text = hashes.SHA256Page ?? "N/A";
            Sha1AuthenticodeTextBox.Text = hashes.SHa1Authenticode ?? "N/A";
            Sha256AuthenticodeTextBox.Text = hashes.SHA256Authenticode ?? "N/A";
        }
    }
}
