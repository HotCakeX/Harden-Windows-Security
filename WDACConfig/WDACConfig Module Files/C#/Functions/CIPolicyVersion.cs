using System;

#nullable enable

namespace WDACConfig
{
    public static class CIPolicyVersion
    {
        /// <summary>
        /// Converts a 64-bit unsigned integer into a version type, used for converting the numbers from CiTool.exe output to proper versions.
        /// </summary>
        /// <param name="number">The 64-bit unsigned integer as a string.</param>
        /// <returns>The version string in the format 'part1.part2.part3.part4'.</returns>
        public static string Measure(string number)
        {
            try
            {
                // Validate input
                if (string.IsNullOrEmpty(number))
                {
                    throw new ArgumentException("Input number cannot be null or empty.");
                }

                // Convert the string to a 64-bit integer
                if (!ulong.TryParse(number, out ulong num))
                {
                    throw new FormatException("Input string is not a valid 64-bit unsigned integer.");
                }

                // Extract the version parts by splitting the 64-bit integer into four 16-bit segments and convert each segment to its respective part of the version number
                ushort part1 = (ushort)((num & 0xFFFF000000000000) >> 48); // mask isolates the highest 16 bits of a 64-bit number.
                ushort part2 = (ushort)((num & 0x0000FFFF00000000) >> 32); // mask isolates the next 16 bits.
                ushort part3 = (ushort)((num & 0x00000000FFFF0000) >> 16); // mask isolates the third set of 16 bits.
                ushort part4 = (ushort)(num & 0x000000000000FFFF); // mask isolates the lowest 16 bits.

                // Form the version string
                return $"{part1}.{part2}.{part3}.{part4}";
            }
            catch (Exception ex)
            {
                WDACConfig.VerboseLogger.Write($"Error converting number to version: {ex.Message}");
                return number;
            }
        }
    }
}
