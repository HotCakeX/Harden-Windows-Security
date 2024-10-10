using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml;

namespace WDACConfig
{

    internal class SupplementalForSelf
    {
        /// <summary>
        /// Deploys the Supplemental Policy that allows the Application to be allowed to run after deployment
        /// </summary>
        /// <param name="StagingArea"></param>
        public static void Deploy(string StagingArea, string basePolicyID)
        {
            // Get the base directory where the app is running
            string xmlFilePath = Path.Combine(AppContext.BaseDirectory, @"Resources\AppControlManagerSupplementalPolicy.xml");

            // Read the file's content as string
            using FileStream stream = new(xmlFilePath, FileMode.Open, FileAccess.Read);
            using StreamReader reader = new(stream);
            string xmlContent = reader.ReadToEnd();

            // Convert the string to XML Document
            XmlDocument XMLData = new();
            XMLData.LoadXml(xmlContent);


            #region Replace the BasePolicyID of the Supplemental Policy

            // Select the nodes and update their values
            XmlNamespaceManager nsMgr = new(XMLData.NameTable);
            nsMgr.AddNamespace("ns", "urn:schemas-microsoft-com:sipolicy");


            XmlNode? basePolicyIdNode = XMLData.SelectSingleNode("/ns:SiPolicy/ns:BasePolicyID", nsMgr);
            if (basePolicyIdNode != null)
            {
                basePolicyIdNode.InnerText = basePolicyID;
            }
            #endregion


            string policyName = "AppControlManagerSupplementalPolicy";

            string savePath = Path.Combine(StagingArea, "AppControlManagerSupplementalPolicy.xml");

            string cipPath = Path.Combine(StagingArea, "AppControlManagerSupplementalPolicy.cip");

            // Save the XML to the path as XML file
            XMLData.Save(savePath);

            Logger.Write($"Checking if the {policyName} policy is already deployed");

            // Get all the deployed policies to see if our policy is among them
            List<CiPolicyInfo> CurrentlyDeployedPolicy = CiToolHelper.GetPolicies(false, true, false).Where(policy => string.Equals(policy.FriendlyName, policyName, StringComparison.OrdinalIgnoreCase)).ToList();

            if (CurrentlyDeployedPolicy.Count > 0)
            {

                Logger.Write($"{policyName} policy is already deployed. Not deploying it again.");

            }
            else
            {
                Logger.Write($"{policyName} policy is not deployed, deploying it now.");
            }

            PolicyToCIPConverter.Convert(savePath, cipPath);

            CiToolHelper.UpdatePolicy(cipPath);

        }

    }
}
