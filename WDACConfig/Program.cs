using System.Security.Cryptography.X509Certificates;

// Some test
List<WDACConfig.AllCertificatesGrabber.AllFileSigners> Certificates = WDACConfig.AllCertificatesGrabber.WinTrust.GetAllFileSigners(@"");

List<string> subjects = Certificates
    .Select(Cert => Cert.Chain?.ChainElements?.Cast<X509ChainElement>().FirstOrDefault()?.Certificate?.Subject?.ToString())
    .Where(subject => subject != null)
    .ToList();

foreach (var item in subjects)
{
    Console.WriteLine(item);
}
