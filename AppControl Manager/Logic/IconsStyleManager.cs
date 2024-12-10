using System;

namespace AppControlManager
{
    // Custom EventArgs class for Icons Style changes
    internal sealed class IconsStyleChangedEventArgs(string? newIconsStyle) : EventArgs
    {
        internal string? NewIconsStyle { get; } = newIconsStyle;
    }

    internal static class IconsStyleManager
    {
        // The static event for Icons Style changes
        // MainWindow listens to this to set the icons style
        internal static event EventHandler<IconsStyleChangedEventArgs>? IconsStyleChanged;

        // Method to raise the event when the icons styles change
        internal static void OnIconsStylesChanged(string newIconsStyle)
        {
            // Raise the IconsStyleChanged event with the new style
            IconsStyleChanged?.Invoke(
                null,
                new IconsStyleChangedEventArgs(newIconsStyle)
            );
        }
    }
}
