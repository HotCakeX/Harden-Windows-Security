using System;

// Used by WDAC Simulations
namespace WDACConfig
{
    public class PolicyHashObj
    {
        // Adding public getters and setters for the properties
        public string HashValue { get; set; }
        public string HashType { get; set; }
        public string FilePathForHash { get; set; }

        // Adding a constructor to initialize the properties
        public PolicyHashObj(string hashvalue, string hashtype, string filepathforhash)
        {
            HashValue = hashvalue;
            HashType = hashtype;
            FilePathForHash = filepathforhash;
        }

        // Making sure any HashSet or collection using this class will only keep unique objects based on their HashValue property

        // Override the Equals method
        public override bool Equals(object obj)
        {
            if (obj == null || GetType() != obj.GetType())
            {
                return false;
            }

            var other = (PolicyHashObj)obj;
            return HashValue == other.HashValue;
        }

        // Override the GetHashCode method
        public override int GetHashCode()
        {
            return HashValue != null ? HashValue.GetHashCode() : 0;
        }
    }
}
