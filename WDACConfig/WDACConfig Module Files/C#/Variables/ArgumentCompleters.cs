using System;
using System.Management.Automation;

namespace WDACConfig
{
    // Importing this ArgumentCompleters class in PowerShell will introduce App-Domain-Wide variables
    public static class ArgumentCompleters
    {
        public static ScriptBlock ArgumentCompleterAppxPackageNames;
        public static ScriptBlock ArgumentCompleterFolderPathsPicker;
        public static ScriptBlock ArgumentCompleterExeFilePathsPicker;
        public static ScriptBlock ArgumentCompleterCerFilePathsPicker;
        public static ScriptBlock ArgumentCompleterCerFilesPathsPicker;
        public static ScriptBlock ArgumentCompleterXmlFilePathsPicker;
        public static ScriptBlock ArgumentCompleterFolderPathsPickerWildCards;
        public static ScriptBlock ArgumentCompleterAnyFilePathsPicker;
        public static ScriptBlock ArgumentCompleterMultipleAnyFilePathsPicker;
        public static ScriptBlock ArgumentCompleterMultipleXmlFilePathsPicker;
        public static ScriptBlock ArgumentCompleterPolicyRuleOptions;
    }
}
