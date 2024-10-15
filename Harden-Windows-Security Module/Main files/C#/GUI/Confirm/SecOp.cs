using System.Windows.Media.Imaging;

#nullable enable

namespace HardenWindowsSecurity
{

    // Define the SecOp class, representing an individual security option in the data grid
    public class SecOp : System.ComponentModel.INotifyPropertyChanged
    {
        // Private fields to hold property values

        // Stores whether the security option is compliant
        private bool _Compliant;

        // Stores the security option's character image
        private System.Windows.Media.ImageSource? _characterImage;

        // Stores the background color for the security option
        private System.Windows.Media.Brush? _bgColor;

        // Event to notify listeners when a property value changes
        public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;

        // Public property to get or set the security option's character image
        public System.Windows.Media.ImageSource? CharacterImage
        {
            get => _characterImage;
            set
            {
                _characterImage = value;

                // Notify that the CharacterImage property has changed
                OnPropertyChanged(nameof(CharacterImage));
            }
        }

        // Public property to get or set the background color
        public System.Windows.Media.Brush? BgColor
        {
            get => _bgColor;
            set
            {
                _bgColor = value;

                // Notify that the BgColor property has changed
                OnPropertyChanged(nameof(BgColor));
            }
        }

        // Public properties for security option details
        public string? FriendlyName { get; set; }
        public string? Value { get; set; }
        public string? Name { get; set; }
        public string? Category { get; set; }
        public string? Method { get; set; }

        // Public property to get or set whether the security option is compliant
        public bool Compliant
        {
            get => _Compliant;
            set
            {
                _Compliant = value;

                // Update CharacterImage based on compliance
                CharacterImage = LoadImage(_Compliant ? "ConfirmationTrue.png" : "ConfirmationFalse.png");

                // Notify that the Compliant property has changed
                OnPropertyChanged(nameof(Compliant));
            }
        }

        // Method to notify listeners that a property value has changed
        protected void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
        }

        // Private method to load an image from the specified file name
        static private BitmapImage LoadImage(string fileName)
        {
            // Construct the full path to the image file
            string imagePath = System.IO.Path.Combine(GlobalVars.path!, "Resources", "Media", fileName);
            // Return the loaded image as a BitmapImage
            return new BitmapImage(new System.Uri(imagePath, System.UriKind.Absolute));
        }
    }
}
