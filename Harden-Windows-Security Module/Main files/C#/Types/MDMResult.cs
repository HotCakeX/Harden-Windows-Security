using System;
using System.Collections.Generic;

#nullable enable

namespace HardenWindowsSecurity
{
    internal partial class MDMClassProcessor
    {
        internal string Name { get; set; }
        internal string Value { get; set; }
        internal string CimInstance { get; set; }

        internal MDMClassProcessor(string name, string value, string cimInstance)
        {
            Name = name;
            Value = value;
            CimInstance = cimInstance;
        }
    }
}