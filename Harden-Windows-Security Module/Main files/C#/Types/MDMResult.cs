#nullable enable

namespace HardenWindowsSecurity
{
    public sealed partial class MDMClassProcessor(string name, string value, string cimInstance)
    {
        public string Name { get; set; } = name;
        public string Value { get; set; } = value;
        public string CimInstance { get; set; } = cimInstance;
    }
}
