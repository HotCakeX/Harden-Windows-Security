// Used by WDAC Simulations
namespace WDACConfig
{
    public class SimulationInput
    {
        // Adding public getters and setters for the properties
        public System.IO.FileInfo FilePath { get; set; }
        public System.Management.Automation.Signature GetAuthenticodeResults { get; set; }
        public System.Xml.XmlDocument XMLContent { get; set; }

        // Adding a constructor to initialize the properties
        public SimulationInput(System.IO.FileInfo filepath, System.Management.Automation.Signature getauthenticoderesults, System.Xml.XmlDocument xmlcontent)
        {
            FilePath = filepath;
            GetAuthenticodeResults = getauthenticoderesults;
            XMLContent = xmlcontent;
        }
    }
}
