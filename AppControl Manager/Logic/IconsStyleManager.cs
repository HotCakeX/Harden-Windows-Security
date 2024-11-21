using System;

namespace WDACConfig
{
    public static class IconsStyleManager
    {
        // The static event for Icons Style changes
        // MainWindow listens to this to set the icons style
        public static event Action<string>? IconsStyleChanged;

        // Method to raise the event when the icons styles change
        public static void OnIconsStylesChanged(string newIconsStyle)
        {
            IconsStyleChanged?.Invoke(newIconsStyle);
        }
    }
}
