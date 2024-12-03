using System;
using System.Collections.Generic;

namespace AppControlManager
{
    /// <summary>
    /// A custom equality comparer for the FileAttrib class.
    /// This comparer is used to determine the uniqueness of FileAttrib instances
    /// based on specific properties.
    /// </summary>
    public sealed class FileAttribComparer : IEqualityComparer<FileAttrib>
    {
        /// <summary>
        /// Determines whether two FileAttrib instances are equal.
        /// The instances are considered equal if all six specified properties are the same.
        ///
        /// Both FileAttrib Instances Are Null:
        /// Result: Equal (true).
        ///
        /// One Instance Is Null:
        /// Result: Not equal (false).
        ///
        /// Both Instances Are Not Null, with Some Properties Null:
        /// If a property is null in both instances, that property is considered equal.
        /// If a property is null in one instance but has a value in the other, that property is considered not equal.
        /// If all specified properties are equal (including handling of nulls), the instances are equal; otherwise, they are not.
        /// </summary>
        /// <param name="x">The first FileAttrib instance to compare.</param>
        /// <param name="y">The second FileAttrib instance to compare.</param>
        /// <returns>true if the instances are equal; otherwise, false.</returns>
        public bool Equals(FileAttrib? x, FileAttrib? y)
        {
            // If both are null, they are considered equal
            if (x is null && y is null)
                return true;

            // If one is null and the other is not, they are not equal
            if (x is null || y is null)
                return false;

            // Compare the specified properties for equality using string comparison
            return string.Equals(x.MinimumFileVersion, y.MinimumFileVersion, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(x.FileDescription, y.FileDescription, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(x.FileName, y.FileName, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(x.InternalName, y.InternalName, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(x.FilePath, y.FilePath, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(x.ProductName, y.ProductName, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Returns a hash code for the given FileAttrib instance.
        /// The hash code is computed based on the six specified properties.
        /// </summary>
        /// <param name="obj">The FileAttrib instance for which to get the hash code.</param>
        /// <returns>A hash code for the given FileAttrib instance.</returns>
        public int GetHashCode(FileAttrib? obj)
        {
            // Return a default hash code (0) if obj is null to avoid exceptions
            if (obj is null) return 0;

            // Initialize a hash variable
            int hash = 17;

            // Combine hash codes of the specified properties using a common technique
            // unchecked allows overflow but does not decrease accuracy of the HashSet.
            // When implementing GetHashCode, the important aspect is that the same input will always yield the same output.
            // Even if that output results in a wrapped value due to overflow, it will consistently represent that specific object.

            unchecked
            {
                hash = hash * 31 + (obj.MinimumFileVersion?.GetHashCode(StringComparison.OrdinalIgnoreCase) ?? 0);
                hash = hash * 31 + (obj.FileDescription?.GetHashCode(StringComparison.OrdinalIgnoreCase) ?? 0);
                hash = hash * 31 + (obj.FileName?.GetHashCode(StringComparison.OrdinalIgnoreCase) ?? 0);
                hash = hash * 31 + (obj.InternalName?.GetHashCode(StringComparison.OrdinalIgnoreCase) ?? 0);
                hash = hash * 31 + (obj.FilePath?.GetHashCode(StringComparison.OrdinalIgnoreCase) ?? 0);
                hash = hash * 31 + (obj.ProductName?.GetHashCode(StringComparison.OrdinalIgnoreCase) ?? 0);
            }

            // Return the computed hash code
            return hash;
        }
    }
}
