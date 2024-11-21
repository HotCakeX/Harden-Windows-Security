﻿using System.Collections.Generic;

namespace WDACConfig.IntelGathering
{
    /// <summary>
    /// A custom collection that manages a set of FileIdentity objects,
    /// prioritizing newer FileIdentity items over older ones when adding items
    /// with identical properties, based on the custom equality comparer.
    /// Used by event logs scanning.
    ///
    /// If an equivalent item (based on the FileIdentityComparer which takes priority) already exists,
    /// the method checks the TimeCreated property of both the existing item and the new item:
    /// If the existing item is older and the new item is newer: The older item is removed,
    /// and the newer item is added to the set.
    /// If the existing item is newer or has the same timestamp, the new item will not be added
    /// because they are considered equal or the existing one is preferred.
    /// </summary>
    public sealed class FileIdentityTimeBasedHashSet
    {
        // A HashSet to store FileIdentity objects with a custom comparer.
        // This comparer defines equality based on selected properties in that comparer, ignoring TimeCreated for now.
        private readonly HashSet<FileIdentity> _set;

        /// <summary>
        /// Initializes a new instance of the FileIdentityTimeBasedHashSet class.
        /// </summary>
        public FileIdentityTimeBasedHashSet()
        {
            _set = new HashSet<FileIdentity>(new FileIdentityComparer());
        }

        /// <summary>
        /// Expose the internal HashSet so we can access it directly.
        /// </summary>
        public HashSet<FileIdentity> FileIdentitiesInternal => _set;

        /// <summary>
        /// Adds a FileIdentity item to the set, replacing an older equivalent item if it exists.
        /// </summary>
        /// <param name="item">The FileIdentity item to add.</param>
        /// <returns>True if a new item is added or an older item is replaced; false otherwise.</returns>
        public bool Add(FileIdentity item)
        {
            // Check if an equivalent item (based on FileIdentityComparer) already exists in the set
            if (_set.TryGetValue(item, out FileIdentity? existingItem))
            {
                // If an equivalent older item exists, replace it with the newer item
                if (existingItem.TimeCreated.HasValue && item.TimeCreated.HasValue &&
                    existingItem.TimeCreated < item.TimeCreated)
                {
                    Logger.Write($"Replacing an older FileIdentity item with a newer one in MDE Advanced Hunting Logs " +
                                 $"for the file with name {existingItem.FileName} and SHA256 hash {existingItem.SHA256Hash}.");

                    // Remove the existing older item and add the newer one
                    _ = _set.Remove(existingItem);
                    _ = _set.Add(item);
                    return true; // Indicate that an item was replaced
                }

                // If an equivalent newer item already exists, do not add the older item
                return false;
            }

            // If no equivalent item exists, add the new item to the set
            _ = _set.Add(item);
            return true;
        }

        /// <summary>
        /// Checks if the set contains an item equivalent to the specified FileIdentity item.
        /// </summary>
        /// <param name="item">The FileIdentity item to check for.</param>
        /// <returns>True if an equivalent item exists in the set; false otherwise.</returns>
        public bool Contains(FileIdentity item) => _set.Contains(item);

        /// <summary>
        /// Removes an equivalent FileIdentity item from the set, if it exists.
        /// </summary>
        /// <param name="item">The FileIdentity item to remove.</param>
        /// <returns>True if the item was removed; false if it did not exist in the set.</returns>
        public bool Remove(FileIdentity item) => _set.Remove(item);

        /// <summary>
        /// Gets the count of items in the set.
        /// </summary>
        public int Count => _set.Count;
    }
}
