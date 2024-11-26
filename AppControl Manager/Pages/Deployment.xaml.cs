using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Xml;

namespace WDACConfig.Pages
{

    public sealed partial class Deployment : Page
    {
        // Lists to store user input selected files
        private readonly List<string> XMLFiles = [];
        private readonly List<string> CIPFiles = [];

        public Deployment()
        {
            this.InitializeComponent();

            this.NavigationCacheMode = NavigationCacheMode.Enabled;
        }

        /// <summary>
        /// Deploy button event handler
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private async void DeployButton_Click(object sender, RoutedEventArgs e)
        {
            if (XMLFiles.Count == 0 && CIPFiles.Count == 0)
            {
                DeployButtonTeachingTip.IsOpen = true;
                return;
            }

            bool errorsOccurred = false;

            try
            {
                DeployButton.IsEnabled = false;
                BrowseForXMLPolicyFilesSettingsCard.IsEnabled = false;
                BrowseForCIPBinaryFilesSettingsCard.IsEnabled = false;
                BrowseForXMLPolicyFilesButton.IsEnabled = false;
                BrowseForCIPBinaryFilesButton.IsEnabled = false;

                StatusInfoBar.Visibility = Visibility.Visible;
                StatusInfoBar.IsOpen = true;
                StatusInfoBar.Message = $"Deploying {XMLFiles.Count} XML files and {CIPFiles.Count} CIP binary files.";
                StatusInfoBar.Severity = InfoBarSeverity.Informational;
                StatusInfoBar.IsClosable = false;

                ProgressRing.Visibility = Visibility.Visible;

                // Deploy the selected files
                await Task.Run(() =>
                {

                    DirectoryInfo stagingArea = StagingArea.NewStagingArea("Deployments");

                    // Convert and then deploy each XML file
                    if (XMLFiles.Count > 0)
                    {
                        foreach (string file in XMLFiles)
                        {
                            {
                                // Instantiate the policy
                                CodeIntegrityPolicy codeIntegrityPolicy = new(file, null);

                                // Get all of the policy rule option nodes
                                XmlNodeList? policyRuleOptionNodes = codeIntegrityPolicy.SiPolicyNode.SelectNodes("ns:Rules/ns:Rule", codeIntegrityPolicy.NamespaceManager);

                                if (policyRuleOptionNodes is not null)
                                {

                                    List<string> policyRuleOptions = [];

                                    foreach (XmlNode item in policyRuleOptionNodes)
                                    {
                                        policyRuleOptions.Add(item.InnerText);
                                    }

                                    bool isUnsigned = policyRuleOptions.Any(p => string.Equals(p, "Enabled:Unsigned System Integrity Policy", StringComparison.OrdinalIgnoreCase));

                                    if (!isUnsigned)
                                    {
                                        throw new InvalidOperationException($"The XML file '{file}' is a signed policy!");
                                    }
                                }


                                string randomString = Guid.NewGuid().ToString().Replace("-", "");

                                string xmlFileName = Path.GetFileName(file);

                                string CIPFilePath = Path.Combine(stagingArea.FullName, $"{xmlFileName}-{randomString}.cip");

                                _ = DispatcherQueue.TryEnqueue(() =>
                                {
                                    StatusInfoBar.Message = $"Currently Deploying XML file: '{file}'";
                                });

                                // Convert the XML file to CIP
                                PolicyToCIPConverter.Convert(file, CIPFilePath);

                                // Deploy the CIP file
                                CiToolHelper.UpdatePolicy(CIPFilePath);

                                // Delete the CIP file after deployment
                                File.Delete(CIPFilePath);
                            }
                        }

                        // Deploy each CIP file
                        if (CIPFiles.Count > 0)
                        {
                            foreach (string file in CIPFiles)
                            {
                                _ = DispatcherQueue.TryEnqueue(() =>
                                {
                                    StatusInfoBar.Message = $"Currently Deploying CIP file: '{file}'";
                                });

                                CiToolHelper.UpdatePolicy(file);
                            }
                        }
                    }
                });
            }

            catch
            {
                errorsOccurred = true;

                StatusInfoBar.Severity = InfoBarSeverity.Error;
                StatusInfoBar.Message = "There was an error deploying the selected files";

                throw;
            }
            finally
            {
                if (!errorsOccurred)
                {
                    StatusInfoBar.Severity = InfoBarSeverity.Success;
                    StatusInfoBar.Message = "Successfully deployed all of the selected files";
                }

                DeployButton.IsEnabled = true;
                BrowseForXMLPolicyFilesSettingsCard.IsEnabled = true;
                BrowseForCIPBinaryFilesSettingsCard.IsEnabled = true;
                BrowseForXMLPolicyFilesButton.IsEnabled = true;
                BrowseForCIPBinaryFilesButton.IsEnabled = true;

                ProgressRing.Visibility = Visibility.Collapsed;
                StatusInfoBar.IsClosable = true;

                // Clear the lists at the end
                XMLFiles.Clear();
                CIPFiles.Clear();

            }
        }

        private void BrowseForXMLPolicyFilesButton_Click(object sender, RoutedEventArgs e)
        {
            string filter = "XML file|*.xml";

            List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(filter);

            if (selectedFiles is not null && selectedFiles.Count != 0)
            {
                foreach (string file in selectedFiles)
                {
                    XMLFiles.Add(file);
                }
            }
        }

        private void BrowseForXMLPolicyFilesSettingsCard_Click(object sender, RoutedEventArgs e)
        {
            string filter = "XML file|*.xml";

            List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(filter);

            if (selectedFiles is not null && selectedFiles.Count != 0)
            {
                foreach (string file in selectedFiles)
                {
                    XMLFiles.Add(file);
                }
            }
        }

        private void BrowseForCIPBinaryFilesButton_Click(object sender, RoutedEventArgs e)
        {
            string filter = "CIP file|*.cip";

            List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(filter);

            if (selectedFiles is not null && selectedFiles.Count != 0)
            {
                foreach (string file in selectedFiles)
                {
                    CIPFiles.Add(file);
                }
            }
        }

        private void BrowseForCIPBinaryFilesSettingsCard_Click(object sender, RoutedEventArgs e)
        {
            string filter = "CIP file|*.cip";

            List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(filter);

            if (selectedFiles is not null && selectedFiles.Count != 0)
            {
                foreach (string file in selectedFiles)
                {
                    CIPFiles.Add(file);
                }
            }
        }

    }
}
