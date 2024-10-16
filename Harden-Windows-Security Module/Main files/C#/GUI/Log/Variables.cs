using System.Windows.Controls;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class GUILogs
    {
        internal static UserControl? View;

        internal static Grid? ParentGrid;

        internal static TextBox? MainLoggerTextBox;

        internal static ScrollViewer? scrollerForOutputTextBox;

        // The Logger class refers to this variable before scrolling down the ScrollViewer
        // Setting this to true initially because the toggle button is set to "Checked" when the GUI logger view is loaded but that is visual only and does not trigger the Checked event that would set this variable to true.
        // without this initial assignment, switching to Logs page wouldn't have auto-scrolling capability until the toggle button is set to off and on again.
        internal static bool AutoScroll = true;
    }
}
