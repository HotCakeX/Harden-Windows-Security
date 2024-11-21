using System;

// Used by AppControl Simulations
namespace WDACConfig
{
    public sealed class PolicyHashObj(string hashvalue, string hashtype, string filepathforhash)
    {
        // Adding public getters and setters for the properties
        public string HashValue { get; set; } = hashvalue;
        public string HashType { get; set; } = hashtype;
        public string FilePathForHash { get; set; } = filepathforhash;

        // Making sure any HashSet or collection using this class will only keep unique objects based on their HashValue property

        // Override the Equals method
        public override bool Equals(object? obj)
        {
            if (obj == null || GetType() != obj.GetType())
            {
                return false;
            }

            PolicyHashObj other = (PolicyHashObj)obj;
            return string.Equals(HashValue, other.HashValue, StringComparison.OrdinalIgnoreCase);
        }

        // Override the GetHashCode method
        public override int GetHashCode()
        {
            return HashValue is not null ? StringComparer.OrdinalIgnoreCase.GetHashCode(HashValue) : 0;
        }
    }
}
