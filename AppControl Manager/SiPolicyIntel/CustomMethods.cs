using System;

namespace AppControlManager.SiPolicyIntel
{

    internal static class CustomMethods
    {
        internal static int GetByteArrayHashCode(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);

            int hash = 17;

            foreach (byte b in data)
            {
                unchecked
                {
                    hash = hash * 31 + b; // Allow overflow, it will wrap around naturally
                }
            }

            return hash;
        }
    }
}
