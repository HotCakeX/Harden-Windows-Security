namespace WDACConfig
{
    // Importing this ArgumentCompleters class in PowerShell will introduce App-Domain-Wide variables
    public static class ArgumentCompleters
    {
        public static object ArgumentCompleterAppxPackageNames;
        public static object ArgumentCompleterFolderPathsPicker;
        public static object ArgumentCompleterExeFilePathsPicker;
        public static object ArgumentCompleterCerFilePathsPicker;
        public static object ArgumentCompleterCerFilesPathsPicker;
        public static object ArgumentCompleterXmlFilePathsPicker;
        public static object ArgumentCompleterFolderPathsPickerWildCards;
        public static object ArgumentCompleterAnyFilePathsPicker;
        public static object ArgumentCompleterMultipleAnyFilePathsPicker;
        public static object ArgumentCompleterMultipleXmlFilePathsPicker;
    }
}
