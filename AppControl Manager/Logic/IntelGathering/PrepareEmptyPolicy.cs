using System.IO;

namespace WDACConfig.IntelGathering
{
    public static class PrepareEmptyPolicy
    {

        /// <summary>
        /// Copies one of the template Code Integrity policies to the directory it receives, empties it and returns its path
        /// </summary>
        /// <param name="directory"></param>
        /// <returns></returns>
        public static string Prepare(string directory)
        {

            string pathToReturn = Path.Combine(directory, "EmptyPolicyFile.xml");

            Logger.Write("Copying the template policy to the staging area");

            File.Copy(@"C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml", pathToReturn, true);

            Logger.Write("Emptying the policy file in preparation for the new data insertion");
            ClearCiPolicySemantic.Clear(pathToReturn);

            return pathToReturn;

        }
    }
}
