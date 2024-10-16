using System.Globalization;
using System.Linq;

#nullable enable

namespace HardenWindowsSecurity
{
    internal static class HelperMethods
    {
        // Helper method to convert object to string array
        internal static string[]? ConvertToStringArray(object input)
        {
            if (input is string[] stringArray)
            {
                return stringArray;
            }
            if (input is byte[] byteArray)
            {
                return byteArray.Select(b => b.ToString(CultureInfo.InvariantCulture)).ToArray();
            }
            return null;
        }
    }
}
