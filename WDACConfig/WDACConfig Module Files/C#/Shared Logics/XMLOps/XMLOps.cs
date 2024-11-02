#nullable enable

namespace WDACConfig
{
    public static class XMLOps
    {
        /// <summary>
        /// Uses the scan data to generate an AppControl policy and makes sure the data are unique
        /// </summary>
        /// <param name="incomingData"></param>
        /// <param name="xmlFilePath"></param>
        public static void Initiate(FileBasedInfoPackage incomingData, string xmlFilePath)
        {

            NewFilePublisherLevelRules.Create(xmlFilePath, incomingData.FilePublisherSigners);
            NewPublisherLevelRules.Create(xmlFilePath, incomingData.PublisherSigners);
            NewHashLevelRules.Create(xmlFilePath, incomingData.CompleteHashes);

            Logger.Write("Merging the Hash Level rules");
            RemoveAllowElementsSemantic.Remove(xmlFilePath);
            CloseEmptyXmlNodesSemantic.Close(xmlFilePath);

            Logger.Write("Merging the Signer Level rules");
            RemoveDuplicateFileAttribSemantic.Remove(xmlFilePath);

            // 2 passes are needed
            MergeSignersSemantic.Merge(xmlFilePath);
            MergeSignersSemantic.Merge(xmlFilePath);

            // This method runs twice, once for signed data and once for unsigned data
            CloseEmptyXmlNodesSemantic.Close(xmlFilePath);

        }
    }
}
