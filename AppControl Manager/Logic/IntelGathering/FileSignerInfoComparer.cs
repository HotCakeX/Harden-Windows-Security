using System;
using System.Collections.Generic;

namespace WDACConfig.IntelGathering
{
    /// <summary>
    /// A custom equality comparer for the FileSignerInfo class.
    /// This comparer is used to determine the uniqueness of FileSignerInfo instances
    /// based on PublisherTBSHash and IssuerTBSHash properties.
    /// </summary>
    public sealed class FileSignerInfoComparer : IEqualityComparer<FileSignerInfo>
    {
        /// <summary>
        /// Determines whether two FileSignerInfo instances are equal.
        /// The instances are considered equal if both the PublisherTBSHash
        /// and IssuerTBSHash properties are equal.
        /// </summary>
        /// <param name="x">The first FileSignerInfo instance to compare.</param>
        /// <param name="y">The second FileSignerInfo instance to compare.</param>
        /// <returns>true if the instances are equal; otherwise, false.</returns>
        public bool Equals(FileSignerInfo? x, FileSignerInfo? y)
        {
            // If both are null, they are considered equal
            if (x is null && y is null)
                return true;

            // If either instance is null, they are not considered equal
            if (x is null || y is null)
                return false;

            // Compare the PublisherTBSHash and IssuerTBSHash properties for equality
            return x.PublisherTBSHash == y.PublisherTBSHash && x.IssuerTBSHash == y.IssuerTBSHash;
        }

        /// <summary>
        /// Returns a hash code for the given FileSignerInfo instance.
        /// The hash code is computed based on the PublisherTBSHash and IssuerTBSHash properties.
        /// </summary>
        /// <param name="obj">The FileSignerInfo instance for which to get the hash code.</param>
        /// <returns>A hash code for the given FileSignerInfo instance.</returns>
        public int GetHashCode(FileSignerInfo obj)
        {

            int hashPublisher;
            int hashIssuer;

            // Get hash codes for both properties, using case-insensitive comparison for strings
            // Using unchecked to avoid exceptions from overflow
            unchecked
            {
                hashPublisher = obj.PublisherTBSHash?.GetHashCode(StringComparison.OrdinalIgnoreCase) ?? 0;
                hashIssuer = obj.IssuerTBSHash?.GetHashCode(StringComparison.OrdinalIgnoreCase) ?? 0;
            }

            // Combine the hash codes using XOR to produce a single hash code for the instance
            // Reducing collisions by using 397 prime number
            return unchecked((hashPublisher * 397) ^ hashIssuer);
        }
    }
}
