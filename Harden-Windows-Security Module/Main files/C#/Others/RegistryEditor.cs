using Microsoft.Win32;
using System;
using System.Globalization;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class RegistryEditor
    {
        private static readonly string[] separator = [";"];

        public static void EditRegistry(string path, string key, string value, string type, string action)
        {
            // Removing the 'Registry::' prefix from the path
            if (path.StartsWith("Registry::", StringComparison.OrdinalIgnoreCase))
            {
                path = path[10..];
            }

            // Get the registry base key and the sub key path
            string baseKey = path.Split('\\')[0];
            string subKeyPath = path[(baseKey.Length + 1)..];

            RegistryKey baseRegistryKey;

            switch (baseKey.ToUpperInvariant())
            {
                case "HKEY_LOCAL_MACHINE":
                    {
                        baseRegistryKey = Registry.LocalMachine;
                        break;
                    }
                case "HKEY_CURRENT_USER":
                    {
                        baseRegistryKey = Registry.CurrentUser;
                        break;
                    }
                case "HKEY_CLASSES_ROOT":
                    {
                        baseRegistryKey = Registry.ClassesRoot;
                        break;
                    }
                case "HKEY_USERS":
                    {
                        baseRegistryKey = Registry.Users;
                        break;
                    }
                case "HKEY_CURRENT_CONFIG":
                    {
                        baseRegistryKey = Registry.CurrentConfig;
                        break;
                    }
                default:
                    {
                        throw new ArgumentException("Invalid registry base key");
                    }
            }

            using RegistryKey subKey = baseRegistryKey.OpenSubKey(subKeyPath, true) ?? baseRegistryKey.CreateSubKey(subKeyPath);

            if (action.Equals("AddOrModify", StringComparison.OrdinalIgnoreCase))
            {
                RegistryValueKind valueType;
                object convertedValue;

                switch (type.ToUpperInvariant())
                {
                    case "STRING":
                        {
                            valueType = RegistryValueKind.String;
                            convertedValue = value;
                            break;
                        }
                    case "DWORD":
                        {
                            valueType = RegistryValueKind.DWord;
                            convertedValue = int.Parse(value, NumberStyles.Integer, CultureInfo.InvariantCulture);
                            break;
                        }
                    case "QWORD":
                        {
                            valueType = RegistryValueKind.QWord;
                            convertedValue = long.Parse(value, NumberStyles.Integer, CultureInfo.InvariantCulture);
                            break;
                        }
                    case "BINARY":
                        {
                            valueType = RegistryValueKind.Binary;
                            convertedValue = Convert.FromBase64String(value);
                            break;
                        }
                    case "MULTI_STRING":
                        {
                            valueType = RegistryValueKind.MultiString;
                            convertedValue = value.Split(separator, StringSplitOptions.None);
                            break;
                        }
                    case "EXPAND_STRING":
                        {
                            valueType = RegistryValueKind.ExpandString;
                            convertedValue = value;
                            break;
                        }
                    default:
                        {
                            throw new ArgumentException("Invalid registry value type");
                        }
                }

                subKey.SetValue(key, convertedValue, valueType);
            }
            else if (action.Equals("Delete", StringComparison.OrdinalIgnoreCase))
            {
                if (subKey.GetValue(key) is not null)
                {
                    subKey.DeleteValue(key, true);
                }
            }
            else
            {
                throw new ArgumentException($"Invalid action specified: {action}");
            }
        }
    }
}
