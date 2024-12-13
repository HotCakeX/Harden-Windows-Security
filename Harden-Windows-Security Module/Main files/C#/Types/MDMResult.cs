namespace HardenWindowsSecurity
{
    internal sealed partial class MDMClassProcessor(string name, string value, string cimInstance)
    {
        internal string Name { get; set; } = name;
        internal string Value { get; set; } = value;
        internal string CimInstance { get; set; } = cimInstance;
    }
}
