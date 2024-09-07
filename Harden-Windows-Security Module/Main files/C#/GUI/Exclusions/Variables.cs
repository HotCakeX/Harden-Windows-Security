#nullable enable

namespace HardenWindowsSecurity
{
    public partial class GUIExclusions
    {
        public static System.Windows.Controls.UserControl? View;

        public static System.Windows.Controls.Grid? ParentGrid;

        // Stores the file paths selected by the user after using the browse button
        public static string[]? selectedFiles;

        // Defining this variables in an accessible scope, updated through the dispatcher, used from event handlers
        public static bool MicrosoftDefenderToggleButtonStatus;
        public static bool ControlledFolderAccessToggleButtonStatus;
        public static bool AttackSurfaceReductionRulesToggleButtonStatus;
    }
}
