using System;
using System.Globalization;
using System.Runtime.InteropServices;

#nullable enable

namespace WDACConfig
{
    public class ExFileInfo
    {
        // Constants used for encoding fallback and error handling
        private const string UnicodeFallbackCode = "04B0";
        private const string Cp1252FallbackCode = "04E4";
        public const int FILE_VER_GET_NEUTRAL = 2;
        public const int HR_ERROR_RESOURCE_TYPE_NOT_FOUND = -2147023083;

        // Properties to hold file information
        public string? OriginalFileName { get; private set; }
        public string? InternalName { get; private set; }
        public string? ProductName { get; private set; }
        public Version? Version { get; private set; }
        public string? FileDescription { get; private set; }

        // Importing external functions from Version.dll to work with file version info
        // https://learn.microsoft.com/he-il/windows/win32/api/winver/nf-winver-getfileversioninfosizeexa
        [DllImport("Version.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int GetFileVersionInfoSizeEx(uint dwFlags, string filename, out int handle);

        // https://learn.microsoft.com/he-il/windows/win32/api/winver/nf-winver-verqueryvaluea
        [DllImport("Version.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool VerQueryValue(IntPtr block, string subBlock, out IntPtr buffer, out int len);

        // https://learn.microsoft.com/he-il/windows/win32/api/winver/nf-winver-getfileversioninfoexa
        [DllImport("Version.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetFileVersionInfoEx(uint dwFlags, string filename, int handle, int len, byte[] data);

        // Private constructor to prevent direct instantiation
        private ExFileInfo() { }

        // Static method to get extended file info
        public static ExFileInfo GetExtendedFileInfo(string filePath)
        {
            var ExFileInfo = new ExFileInfo();

            // Get the size of the version information block
            int versionInfoSize = GetFileVersionInfoSizeEx(FILE_VER_GET_NEUTRAL, filePath, out int handle);
            if (versionInfoSize == 0) return ExFileInfo;

            // Allocate array for version data and retrieve it
            var versionData = new byte[versionInfoSize];
            if (!GetFileVersionInfoEx(FILE_VER_GET_NEUTRAL, filePath, handle, versionInfoSize, versionData))
                return ExFileInfo;

            try
            {
                var spanData = new Span<byte>(versionData);

                // Extract version from the version data
                if (!TryGetVersion(spanData, out var version))
                    throw Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error())!;

                ExFileInfo.Version = version; // Set the Version property

                // Extract locale and encoding information
                if (!TryGetLocaleAndEncoding(spanData, out var locale, out var encoding))
                    throw Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error())!;

                // Retrieve various file information based on locale and encoding
                ExFileInfo.OriginalFileName = CheckAndSetNull(GetLocalizedResource(spanData, encoding!, locale!, "\\OriginalFileName"));
                ExFileInfo.InternalName = CheckAndSetNull(GetLocalizedResource(spanData, encoding!, locale!, "\\InternalName"));
                ExFileInfo.FileDescription = CheckAndSetNull(GetLocalizedResource(spanData, encoding!, locale!, "\\FileDescription"));
                ExFileInfo.ProductName = CheckAndSetNull(GetLocalizedResource(spanData, encoding!, locale!, "\\ProductName"));
            }
            catch
            {
                // In case of an error, set all properties to null
                ExFileInfo.Version = null;
                ExFileInfo.OriginalFileName = null;
                ExFileInfo.InternalName = null;
                ExFileInfo.FileDescription = null;
                ExFileInfo.ProductName = null;
            }
            return ExFileInfo;
        }

        // Extract the version from the data
        private static bool TryGetVersion(Span<byte> data, out Version? version)
        {
            version = null;
            // Query the root block for version info
            if (!VerQueryValue(Marshal.UnsafeAddrOfPinnedArrayElement(data.ToArray(), 0), "\\", out var buffer, out _))
                return false;

            // Marshal the version info structure
            var fileInfo = Marshal.PtrToStructure<FileVersionInfo>(buffer);

            // Construct Version object from version info
            version = new Version(
                (int)(fileInfo.dwFileVersionMS >> 16),
                (int)(fileInfo.dwFileVersionMS & ushort.MaxValue),
                (int)(fileInfo.dwFileVersionLS >> 16),
                (int)(fileInfo.dwFileVersionLS & ushort.MaxValue)
            );
            return true;
        }

        // Extract locale and encoding information from the data
        private static bool TryGetLocaleAndEncoding(Span<byte> data, out string? locale, out string? encoding)
        {
            locale = null;
            encoding = null;
            // Query the translation block for locale and encoding
            if (!VerQueryValue(Marshal.UnsafeAddrOfPinnedArrayElement(data.ToArray(), 0), "\\VarFileInfo\\Translation", out var buffer, out _))
                return false;

            // Copy the translation values
            short[] translations = new short[2];
            Marshal.Copy(buffer, translations, 0, 2);

            // Convert the translation values to hex strings
            locale = translations[0].ToString("X4", CultureInfo.InvariantCulture);
            encoding = translations[1].ToString("X4", CultureInfo.InvariantCulture);
            return true;
        }

        // Get localized resource string based on encoding and locale
        private static string? GetLocalizedResource(Span<byte> versionBlock, string encoding, string locale, string resource)
        {
            var encodings = new[] { encoding, Cp1252FallbackCode, UnicodeFallbackCode };
            foreach (var enc in encodings)
            {
                var subBlock = $"StringFileInfo\\{locale}{enc}{resource}";
                if (VerQueryValue(Marshal.UnsafeAddrOfPinnedArrayElement(versionBlock.ToArray(), 0), subBlock, out var buffer, out _))
                    return Marshal.PtrToStringAuto(buffer);

                // If error is not resource type not found, throw the error
                if (Marshal.GetHRForLastWin32Error() != HR_ERROR_RESOURCE_TYPE_NOT_FOUND)
                    throw Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error())!;
            }
            return null;
        }

        // Check if a string is null or whitespace and return null if it is
        private static string? CheckAndSetNull(string? value)
        {
            return string.IsNullOrWhiteSpace(value) ? null : value;
        }

        // Structure to hold file version information
        [StructLayout(LayoutKind.Sequential)]
        private struct FileVersionInfo
        {
            public uint dwSignature;
            public uint dwStrucVersion;
            public uint dwFileVersionMS;
            public uint dwFileVersionLS;
            public uint dwProductVersionMS;
            public uint dwProductVersionLS;
            public uint dwFileFlagsMask;
            public uint dwFileFlags;
            public uint dwFileOS;
            public uint dwFileType;
            public uint dwFileSubtype;
            public uint dwFileDateMS;
            public uint dwFileDateLS;
        }
    }
}
