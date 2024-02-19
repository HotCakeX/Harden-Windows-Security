// necessary logics for Page hash calculation
using System;
using System.IO;
using System.Runtime.InteropServices; // for interoperability with unmanaged code
using System.Security.Cryptography; // for cryptographic algorithms
using System.Text;

namespace WDACConfig
{
    public static class PageHashCalculator
    {
        // a method to compute the hash of the first page of a file using a native function from Wintrust.dll
        [DllImport("Wintrust.dll", CharSet = CharSet.Unicode)] // an attribute to specify the DLL name and the character set
        public static extern int ComputeFirstPageHash( // the method signature
            string pszAlgId, // the first parameter: the name of the hash algorithm to use
            string filename, // the second parameter: the name of the file to hash
            IntPtr buffer, // the third parameter: a pointer to a buffer to store the hash value
            int bufferSize // the fourth parameter: the size of the buffer in bytes
        );

        // a method to get the hash of the first page of a file as a hexadecimal string
        public static string GetPageHash(string algName, string fileName) // the method signature
        {
            IntPtr buffer = IntPtr.Zero; // initialize the buffer pointer to zero
            int bufferSize = 0; // initialize the buffer size to zero
            StringBuilder stringBuilder = new StringBuilder(62); // create a string builder to append the hash value

            try // a try block to handle any exceptions
            {
                int firstPageHash1 = ComputeFirstPageHash(algName, fileName, buffer, bufferSize); // call the native function with the given parameters and store the return value
                if (firstPageHash1 == 0) // if the return value is zero, it means the function failed
                    return null; // return null to indicate an error

                buffer = Marshal.AllocHGlobal(firstPageHash1); // allocate memory for the buffer using the return value as the size
                int firstPageHash2 = ComputeFirstPageHash(algName, fileName, buffer, firstPageHash1); // call the native function again with the same parameters and the allocated buffer
                if (firstPageHash2 == 0) // if the return value is zero, it means the function failed
                    return null; // return null to indicate an error

                for (int ofs = 0; ofs < firstPageHash2; ++ofs) // loop through the buffer bytes
                    stringBuilder.Append(Marshal.ReadByte(buffer, ofs).ToString("X2")); // read each byte, convert it to a hexadecimal string, and append it to the string builder

                return stringBuilder.ToString(); // return the final string
            }
            finally // a finally block to execute regardless of the outcome
            {
                if (buffer != IntPtr.Zero) // if the buffer pointer is not zero, it means it was allocated
                    Marshal.FreeHGlobal(buffer); // free the allocated memory
            }
        }
    }
}
