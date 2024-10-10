using System;

#nullable enable

namespace WDACConfig
{
    public class VersionIncrementer
    {
        public static Version AddVersion(Version version)
        // This can recursively increment an input version by one, and is aware of the max limit
        {
            ArgumentNullException.ThrowIfNull(version);

            if (version.Revision < int.MaxValue)
            {
                return new Version(version.Major, version.Minor, version.Build, version.Revision + 1);
            }
            else if (version.Build < int.MaxValue)
            {
                return new Version(version.Major, version.Minor, version.Build + 1, 0);
            }
            else if (version.Minor < int.MaxValue)
            {
                return new Version(version.Major, version.Minor + 1, 0, 0);
            }
            else if (version.Major < int.MaxValue)
            {
                return new Version(version.Major + 1, 0, 0, 0);
            }
            else
            {
                throw new InvalidOperationException("Version has reached its maximum value.");
            }
        }
    }
}
