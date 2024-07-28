using System;
using System.Globalization;

namespace HardeningModule
{
    // a class to hold the properties of the current culture
    public class CultureInfoProperties
    {
        public string Parent { get; set; }
        public int LCID { get; set; }
        public int KeyboardLayoutId { get; set; }
        public string Name { get; set; }
        public string IetfLanguageTag { get; set; }
        public string DisplayName { get; set; }
        public string NativeName { get; set; }
        public string EnglishName { get; set; }
        public string TwoLetterISOLanguageName { get; set; }
        public string ThreeLetterISOLanguageName { get; set; }
        public string ThreeLetterWindowsLanguageName { get; set; }
        public string CompareInfo { get; set; }
        public string TextInfo { get; set; }
        public bool IsNeutralCulture { get; set; }
        public string CultureTypes { get; set; }
        public object NumberFormat { get; set; }
        public object DateTimeFormat { get; set; }
        public string Calendar { get; set; }
        public string OptionalCalendars { get; set; }
        public bool UseUserOverride { get; set; }
        public bool IsReadOnly { get; set; }
    }

    public static class CultureInfoHelper
    {
        /// <summary>
        /// Get the current culture information just like PowerShell's Get-Culture cmdlet
        /// </summary>
        public static CultureInfoProperties Get()
        {
            // Get the current culture information
            CultureInfo cultureInfo = CultureInfo.CurrentCulture;

            // Create a new CultureInfoProperties object and populate it with the current culture information
            CultureInfoProperties cultureProperties = new CultureInfoProperties
            {
                Parent = cultureInfo.Parent.Name,
                LCID = cultureInfo.LCID,
                KeyboardLayoutId = cultureInfo.KeyboardLayoutId,
                Name = cultureInfo.Name,
                IetfLanguageTag = cultureInfo.IetfLanguageTag,
                DisplayName = cultureInfo.DisplayName,
                NativeName = cultureInfo.NativeName,
                EnglishName = cultureInfo.EnglishName,
                TwoLetterISOLanguageName = cultureInfo.TwoLetterISOLanguageName,
                ThreeLetterISOLanguageName = cultureInfo.ThreeLetterISOLanguageName,
                ThreeLetterWindowsLanguageName = cultureInfo.ThreeLetterWindowsLanguageName,
                CompareInfo = cultureInfo.CompareInfo.Name,
                TextInfo = cultureInfo.TextInfo.CultureName,
                IsNeutralCulture = cultureInfo.IsNeutralCulture,
                CultureTypes = cultureInfo.CultureTypes.ToString(),
                NumberFormat = cultureInfo.NumberFormat,
                DateTimeFormat = cultureInfo.DateTimeFormat,
                Calendar = cultureInfo.Calendar.ToString(),
                OptionalCalendars = string.Join(", ", Array.ConvertAll(cultureInfo.OptionalCalendars, c => c.ToString())),
                UseUserOverride = cultureInfo.UseUserOverride,
                IsReadOnly = cultureInfo.IsReadOnly
            };

            return cultureProperties;
        }
    }
}
