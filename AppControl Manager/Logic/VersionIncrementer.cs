using System;

namespace WDACConfig
{
    public static class VersionIncrementer
    {
        /// <summary>
        /// This can recursively increment an input version by one, and is aware of the max limit
        /// </summary>
        /// <param name="version"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static Version AddVersion(Version version)

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
