using System;
using System.Collections.Generic;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class MDMClassProcessor
    {
        public string Name { get; set; }
        public string Value { get; set; }
        public string CimInstance { get; set; }

        public MDMClassProcessor(string name, string value, string cimInstance)
        {
            Name = name;
            Value = value;
            CimInstance = cimInstance;
        }
    }
}