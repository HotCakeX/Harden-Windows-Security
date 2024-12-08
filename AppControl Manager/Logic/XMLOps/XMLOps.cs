
using AppControlManager.Logging;

namespace AppControlManager
{
    internal static class XMLOps
    {
        /// <summary>
        /// Uses the scan data to generate an App Control policy and makes sure the data are unique
        /// </summary>
        /// <param name="incomingData"></param>
        /// <param name="xmlFilePath"></param>
        internal static void Initiate(FileBasedInfoPackage incomingData, string xmlFilePath)
        {

            NewFilePublisherLevelRules.Create(xmlFilePath, incomingData.FilePublisherSigners);
            NewPublisherLevelRules.Create(xmlFilePath, incomingData.PublisherSigners);
            NewHashLevelRules.Create(xmlFilePath, incomingData.CompleteHashes);

            Logger.Write("Merging");
            SiPolicy.Merger.Merge(xmlFilePath, [xmlFilePath]);
        }
    }
}
