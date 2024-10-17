using System;
using System.Collections;
using System.Collections.Generic;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Windows.Forms;

// The returned collections for the argument completers need to be mutable so they should stay List<T> instead of the immutable Enumerable
#pragma warning disable IDE0028

#nullable enable

namespace WDACConfig.ArgCompleter
{

    /// <summary>
    /// Opens File picker GUI so that user can select any files
    /// </summary>
    public sealed class AnyFilePathsPicker : IArgumentCompleter
    {
        // Method to complete the argument with file path selection
        public IEnumerable<CompletionResult> CompleteArgument(
            string commandName,
            string parameterName,
            string wordToComplete,
            CommandAst commandAst,
            IDictionary fakeBoundParameters)
        {
            // Initialize the file open dialog
            using (OpenFileDialog dialog = new())
            {
                // Show the dialog and get the result
                DialogResult result = dialog.ShowDialog();

                // Check if the user selected a file
                if (result == DialogResult.OK)
                {
                    // Get the selected file path
                    string selectedFilePath = dialog.FileName;
                    // Return the file path wrapped in quotes as a completion result
                    return new List<CompletionResult>
                {
                    new($"\"{selectedFilePath}\"")
                };
                }
            }

            // Return an empty list if no file was selected
            return new List<CompletionResult>();
        }
    }

    // Attribute to use AnyFilePathsPicker as an argument completer
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Field)]
    public sealed class AnyFilePathsPickerAttribute : ArgumentCompleterAttribute, IArgumentCompleterFactory
    {
        // Constructor initializing the base class with AnyFilePathsPicker
        public AnyFilePathsPickerAttribute() : base(typeof(AnyFilePathsPicker)) { }

        // Create method to return an instance of AnyFilePathsPicker
        public IArgumentCompleter Create()
        {
            return new AnyFilePathsPicker();
        }
    }

    /// <summary>
    /// Opens File picker GUI so that user can select a .xml file
    /// </summary>
    public sealed class XmlFilePathsPicker : IArgumentCompleter
    {
        // Directory to initialize the file dialog
        private readonly string initialDirectory = WDACConfig.GlobalVars.UserConfigDir;

        // Method to complete the argument with XML file path selection
        public IEnumerable<CompletionResult> CompleteArgument(
            string commandName,
            string parameterName,
            string wordToComplete,
            CommandAst commandAst,
            IDictionary fakeBoundParameters)
        {
            // Initialize the file open dialog
            using (OpenFileDialog dialog = new())
            {
                // Set the dialog filter to XML files
                dialog.Filter = "XML files (*.xml)|*.xml";
                // Set the dialog title
                dialog.Title = "Select XML files";
                // Set the initial directory
                dialog.InitialDirectory = initialDirectory;

                // Show the dialog and get the result
                DialogResult result = dialog.ShowDialog();

                // Check if the user selected a file
                if (result == DialogResult.OK)
                {
                    // Get the selected file path
                    string selectedFilePath = dialog.FileName;
                    // Return the file path wrapped in quotes as a completion result
                    return new List<CompletionResult>
                {
                    new($"\"{selectedFilePath}\"")
                };
                }
            }

            // Return an empty list if no file was selected
            return new List<CompletionResult>();
        }
    }

    // Attribute to use XmlFilePathsPicker as an argument completer
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Field)]
    public sealed class XmlFilePathsPickerAttribute : ArgumentCompleterAttribute, IArgumentCompleterFactory
    {
        // Constructor initializing the base class with XmlFilePathsPicker
        public XmlFilePathsPickerAttribute() : base(typeof(XmlFilePathsPicker)) { }

        // Create method to return an instance of XmlFilePathsPicker
        public IArgumentCompleter Create()
        {
            return new XmlFilePathsPicker();
        }
    }

    /// <summary>
    /// Opens Folder picker GUI so that user can select folders to be processed
    /// </summary>
    public sealed class FolderPicker : IArgumentCompleter
    {
        // Method to complete the argument with folder path selection
        public IEnumerable<CompletionResult> CompleteArgument(
            string commandName,
            string parameterName,
            string wordToComplete,
            CommandAst commandAst,
            IDictionary fakeBoundParameters)
        {
            // Initialize the folder browser dialog
            using (FolderBrowserDialog dialog = new())
            {
                // Show the dialog and get the result
                DialogResult result = dialog.ShowDialog();

                // Check if the user selected a folder
                if (result == DialogResult.OK)
                {
                    // Get the selected folder path
                    string selectedFolderPath = dialog.SelectedPath;
                    // Return the folder path wrapped in quotes as a completion result
                    return new List<CompletionResult>
                {
                    new($"\"{selectedFolderPath}\"")
                };
                }
            }

            // Return an empty list if no folder was selected
            return new List<CompletionResult>();
        }
    }

    // Attribute to use FolderPicker as an argument completer
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Field)]
    public sealed class FolderPickerAttribute : ArgumentCompleterAttribute, IArgumentCompleterFactory
    {
        // Constructor initializing the base class with FolderPicker
        public FolderPickerAttribute() : base(typeof(FolderPicker)) { }

        // Create method to return an instance of FolderPicker
        public IArgumentCompleter Create()
        {
            return new FolderPicker();
        }
    }

    /// <summary>
    /// Opens File picker GUI so that user can select multiple .xml files
    /// </summary>
    public sealed class XmlFileMultiSelectPicker : IArgumentCompleter
    {
        // Directory to initialize the file dialog
        private readonly string initialDirectory = WDACConfig.GlobalVars.UserConfigDir;

        // Method to complete the argument with multiple XML file path selection
        public IEnumerable<CompletionResult> CompleteArgument(
            string commandName,
            string parameterName,
            string wordToComplete,
            CommandAst commandAst,
            IDictionary fakeBoundParameters)
        {
            // Initialize the file open dialog
            using (OpenFileDialog dialog = new())
            {
                // Set the dialog filter to XML files
                dialog.Filter = "XML files (*.xml)|*.xml";
                // Set the dialog title
                dialog.Title = "Select WDAC Policy XML files";
                // Set the initial directory
                dialog.InitialDirectory = initialDirectory;
                // Enable multi-select
                dialog.Multiselect = true;

                // Show the dialog and get the result
                DialogResult result = dialog.ShowDialog();

                // Check if the user selected files
                if (result == DialogResult.OK)
                {
                    // Get the selected file paths
                    string selectedFilePaths = string.Join("\",\"", dialog.FileNames);
                    // Return the file paths wrapped in quotes as a completion result
                    return new List<CompletionResult>
                {
                    new($"\"{selectedFilePaths}\"")
                };
                }
            }

            // Return an empty list if no files were selected
            return new List<CompletionResult>();
        }
    }

    // Attribute to use XmlFileMultiSelectPicker as an argument completer
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Field)]
    public sealed class XmlFileMultiSelectPickerAttribute : ArgumentCompleterAttribute, IArgumentCompleterFactory
    {
        // Constructor initializing the base class with XmlFileMultiSelectPicker
        public XmlFileMultiSelectPickerAttribute() : base(typeof(XmlFileMultiSelectPicker)) { }

        // Create method to return an instance of XmlFileMultiSelectPicker
        public IArgumentCompleter Create()
        {
            return new XmlFileMultiSelectPicker();
        }
    }

    /// <summary>
    /// Opens File picker GUI so that user can select multiple files
    /// </summary>
    public sealed class MultipleAnyFilePathsPicker : IArgumentCompleter
    {
        // Method to complete the argument with multiple file path selection
        public IEnumerable<CompletionResult> CompleteArgument(
            string commandName,
            string parameterName,
            string wordToComplete,
            CommandAst commandAst,
            IDictionary fakeBoundParameters)
        {
            // Initialize the file open dialog
            using (OpenFileDialog dialog = new())
            {
                // Enable multi-select
                dialog.Multiselect = true;
                // Set the dialog title
                dialog.Title = "Select Files";

                // Show the dialog and get the result
                DialogResult result = dialog.ShowDialog();

                // Check if the user selected files
                if (result == DialogResult.OK)
                {
                    // Get the selected file paths
                    string selectedFilePaths = string.Join("\",\"", dialog.FileNames);
                    // Return the file paths wrapped in quotes as a completion result
                    return new List<CompletionResult>
                {
                    new($"\"{selectedFilePaths}\"")
                };
                }
            }

            // Return an empty list if no files were selected
            return new List<CompletionResult>();
        }
    }

    // Attribute to use MultipleAnyFilePathsPicker as an argument completer
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Field)]
    public sealed class MultipleAnyFilePathsPickerAttribute : ArgumentCompleterAttribute, IArgumentCompleterFactory
    {
        // Constructor initializing the base class with MultipleAnyFilePathsPicker
        public MultipleAnyFilePathsPickerAttribute() : base(typeof(MultipleAnyFilePathsPicker)) { }

        // Create method to return an instance of MultipleAnyFilePathsPicker
        public IArgumentCompleter Create()
        {
            return new MultipleAnyFilePathsPicker();
        }
    }

    /// <summary>
    /// Opens File picker GUI so that user can select an .exe file
    /// </summary>
    public sealed class ExeFilePathsPicker : IArgumentCompleter
    {
        // Directory to initialize the file dialog
        private readonly string initialDirectory = WDACConfig.GlobalVars.UserConfigDir;

        // Method to complete the argument with executable file path selection
        public IEnumerable<CompletionResult> CompleteArgument(
            string commandName,
            string parameterName,
            string wordToComplete,
            CommandAst commandAst,
            IDictionary fakeBoundParameters)
        {
            // Initialize the file open dialog
            using (OpenFileDialog dialog = new())
            {
                // Set the dialog filter to executable files
                dialog.Filter = "Executable files (*.exe)|*.exe";
                // Set the dialog title
                dialog.Title = "Select the SignTool executable file";
                // Set the initial directory
                dialog.InitialDirectory = initialDirectory;

                // Show the dialog and get the result
                DialogResult result = dialog.ShowDialog();

                // Check if the user selected a file
                if (result == DialogResult.OK)
                {
                    // Get the selected file path
                    string selectedFilePath = dialog.FileName;
                    // Return the file path wrapped in quotes as a completion result
                    return new List<CompletionResult>
                {
                    new($"\"{selectedFilePath}\"")
                };
                }
            }

            // Return an empty list if no file was selected
            return new List<CompletionResult>();
        }
    }

    // Attribute to use ExeFilePathsPicker as an argument completer
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Field)]
    public sealed class ExeFilePathsPickerAttribute : ArgumentCompleterAttribute, IArgumentCompleterFactory
    {
        // Constructor initializing the base class with ExeFilePathsPicker
        public ExeFilePathsPickerAttribute() : base(typeof(ExeFilePathsPicker)) { }

        // Create method to return an instance of ExeFilePathsPicker
        public IArgumentCompleter Create()
        {
            return new ExeFilePathsPicker();
        }
    }

    /// <summary>
    /// Opens File picker GUI so that user can select a single .cer file
    /// </summary>
    public sealed class SingleCerFilePicker : IArgumentCompleter
    {
        // Directory to initialize the file dialog
        private readonly string initialDirectory = WDACConfig.GlobalVars.UserConfigDir;

        // Method to complete the argument with single certificate file path selection
        public IEnumerable<CompletionResult> CompleteArgument(
            string commandName,
            string parameterName,
            string wordToComplete,
            CommandAst commandAst,
            IDictionary fakeBoundParameters)
        {
            // Initialize the file open dialog
            using (OpenFileDialog dialog = new())
            {
                // Set the dialog filter to certificate files
                dialog.Filter = "Certificate files (*.cer)|*.cer";
                // Set the dialog title
                dialog.Title = "Select a certificate file";
                // Set the initial directory
                dialog.InitialDirectory = initialDirectory;
                // Disable multi-select
                dialog.Multiselect = false;

                // Show the dialog and get the result
                DialogResult result = dialog.ShowDialog();

                // Check if the user selected a file
                if (result == DialogResult.OK)
                {
                    // Get the selected file path
                    string selectedFilePath = dialog.FileName;
                    // Return the file path wrapped in quotes as a completion result
                    return new List<CompletionResult>
                {
                    new($"\"{selectedFilePath}\"")
                };
                }
            }

            // Return an empty list if no file was selected
            return new List<CompletionResult>();
        }
    }

    // Attribute to use SingleCerFilePicker as an argument completer
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Field)]
    public sealed class SingleCerFilePickerAttribute : ArgumentCompleterAttribute, IArgumentCompleterFactory
    {
        // Constructor initializing the base class with SingleCerFilePicker
        public SingleCerFilePickerAttribute() : base(typeof(SingleCerFilePicker)) { }

        // Create method to return an instance of SingleCerFilePicker
        public IArgumentCompleter Create()
        {
            return new SingleCerFilePicker();
        }
    }

    /// <summary>
    /// Opens File picker GUI so that user can select multiple .cer files
    /// </summary>
    public sealed class MultipleCerFilePicker : IArgumentCompleter
    {
        // Directory to initialize the file dialog
        private readonly string initialDirectory = WDACConfig.GlobalVars.UserConfigDir;

        // Method to complete the argument with multiple certificate file path selection
        public IEnumerable<CompletionResult> CompleteArgument(
            string commandName,
            string parameterName,
            string wordToComplete,
            CommandAst commandAst,
            IDictionary fakeBoundParameters)
        {
            // Initialize the file open dialog
            using (OpenFileDialog dialog = new())
            {
                // Set the dialog filter to certificate files
                dialog.Filter = "Certificate files (*.cer)|*.cer";
                // Set the dialog title
                dialog.Title = "Select certificate files";
                // Set the initial directory
                dialog.InitialDirectory = initialDirectory;
                // Enable multi-select
                dialog.Multiselect = true;

                // Show the dialog and get the result
                DialogResult result = dialog.ShowDialog();

                // Check if the user selected files
                if (result == DialogResult.OK)
                {
                    // Get the selected file paths
                    string selectedFilePaths = string.Join("\",\"", dialog.FileNames);
                    // Return the file paths wrapped in quotes as a completion result
                    return new List<CompletionResult>
                {
                    new($"\"{selectedFilePaths}\"")
                };
                }
            }

            // Return an empty list if no files were selected
            return new List<CompletionResult>();
        }
    }

    // Attribute to use MultipleCerFilePicker as an argument completer
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Field)]
    public sealed class MultipleCerFilePickerAttribute : ArgumentCompleterAttribute, IArgumentCompleterFactory
    {
        // Constructor initializing the base class with MultipleCerFilePicker
        public MultipleCerFilePickerAttribute() : base(typeof(MultipleCerFilePicker)) { }

        // Create method to return an instance of MultipleCerFilePicker
        public IArgumentCompleter Create()
        {
            return new MultipleCerFilePicker();
        }
    }

    /// <summary>
    /// Opens Folder picker GUI so that user can select a folder, and returns the selected path with quotes and a wildcard character at the end
    /// </summary>
    public sealed class FolderPickerWithWildcard : IArgumentCompleter
    {
        // Method to complete the argument with folder path selection, adding a wildcard character
        public IEnumerable<CompletionResult> CompleteArgument(
            string commandName,
            string parameterName,
            string wordToComplete,
            CommandAst commandAst,
            IDictionary fakeBoundParameters)
        {
            // Initialize the folder browser dialog
            using (FolderBrowserDialog dialog = new())
            {
                // Show the dialog and get the result
                DialogResult result = dialog.ShowDialog();

                // Check if the user selected a folder
                if (result == DialogResult.OK)
                {
                    // Get the selected folder path and add a wildcard character
                    string selectedFolderPath = dialog.SelectedPath;
                    // Return the folder path wrapped in quotes with a wildcard character as a completion result
                    return new List<CompletionResult>
                {
                    new($"\"{selectedFolderPath}\\*\"")
                };
                }
            }

            // Return an empty list if no folder was selected
            return new List<CompletionResult>();
        }
    }

    // Attribute to use FolderPickerWithWildcard as an argument completer
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Field)]
    public sealed class FolderPickerWithWildcardAttribute : ArgumentCompleterAttribute, IArgumentCompleterFactory
    {
        // Constructor initializing the base class with FolderPickerWithWildcard
        public FolderPickerWithWildcardAttribute() : base(typeof(FolderPickerWithWildcard)) { }

        // Create method to return an instance of FolderPickerWithWildcard
        public IArgumentCompleter Create()
        {
            return new FolderPickerWithWildcard();
        }
    }

}
