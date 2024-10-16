#nullable enable

namespace HardenWindowsSecurity
{
    // a class to hold the properties of the current culture
    public sealed class CultureInfoProperties
    {
        public string? Parent { get; set; }
        public int LCID { get; set; }
        public int KeyboardLayoutId { get; set; }
        public required string Name { get; set; }
        public string? IetfLanguageTag { get; set; }
        public string? DisplayName { get; set; }
        public string? NativeName { get; set; }
        public string? EnglishName { get; set; }
        public string? TwoLetterISOLanguageName { get; set; }
        public string? ThreeLetterISOLanguageName { get; set; }
        public string? ThreeLetterWindowsLanguageName { get; set; }
        public string? CompareInfo { get; set; }
        public string? TextInfo { get; set; }
        public bool IsNeutralCulture { get; set; }
        public string? CultureTypes { get; set; }
        public object? NumberFormat { get; set; }
        public object? DateTimeFormat { get; set; }
        public string? Calendar { get; set; }
        public string? OptionalCalendars { get; set; }
        public bool UseUserOverride { get; set; }
        public bool IsReadOnly { get; set; }
    }
}
