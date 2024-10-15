using System;
using System.Globalization;

#nullable enable

namespace HardenWindowsSecurity
{
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
            CultureInfoProperties cultureProperties = new()
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
