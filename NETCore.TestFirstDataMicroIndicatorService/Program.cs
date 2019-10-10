using System;
using Newtonsoft.Json;

namespace NETCore.TestFirstDataMicroIndicatorService
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                System.Console.WriteLine("NETCore.TestFirstDataMicroIndicatorService running....");

                // use TLS 1.2. Note that Telecheck MI REST/JSON documentation only specifies use of SHA256 certificates, but TLS 1.2 is most recent standard
                // this is a static or global setting for the network security protocol to use... why not put this setting on the actual client?
                System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;
                System.Security.Cryptography.X509Certificates.X509Certificate2 x509Cert = null;
                x509Cert = FindCertByThumbprint("8e00205e0b8b567d720fea44059c391d4bfaf7ed", System.Security.Cryptography.X509Certificates.StoreName.TrustedPeople, System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine, true);

                System.Net.Http.HttpClientHandler someHttpHandler = new System.Net.Http.HttpClientHandler();
                someHttpHandler.ClientCertificates.Add(x509Cert);
                // see Appendix H in "TELECHECK NEW ACCOUNT SCREENING AND CONFIDENT SCORING AND MICRO INDICATORS DIAL AND LINK AND WEB SPECIFICATION"
                using (System.Net.Http.HttpClient client = new System.Net.Http.HttpClient(someHttpHandler))
                {
                    client.DefaultRequestHeaders.Accept.Clear();
                    client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
                    client.DefaultRequestHeaders.Add("Connection", "keep-alive");    // instruct server to close or keep-alive - we request keep-alive

                    var localTime = DateTime.Now;
                    var utcTime = localTime.ToUniversalTime();
                    var formattedUtcTime = utcTime.ToString("yyyy-MM-ddThh:mm:ssZ");

                    // compose request
                    var microIndicatorRequest = new
                    {
                        merchantId = "26008392", // DevWire 
                        //merchantId = "26008655", // CheckCity

                        versionControl = "DRAGNETNAS 20120830 WIN7 SNNK 000",
                        micr = "181210002484143878114",  // 18 + routing number + account number (no spaces)
                        amount = "1.00",
                        dateTime = formattedUtcTime,
                        teleCheckProductName = "NEW_ACCT"
                    };

                    // convert request to JSON
                    string jsonMicroIndicatorRequest = JsonConvert.SerializeObject(microIndicatorRequest).ToString();
                    var content = new System.Net.Http.StringContent(jsonMicroIndicatorRequest, System.Text.Encoding.UTF8, "application/json");

                    // POST request to First Data microindicator service
                    System.Diagnostics.Stopwatch sw = new System.Diagnostics.Stopwatch();
                    sw.Start();

                    // don't block on async code
                    // see http://blog.stephencleary.com/2012/07/dont-block-on-async-code.html
                    // see http://stackoverflow.com/questions/26597665/how-to-get-content-body-from-a-httpclient-call
                    var url = "https://api.telecheck.com/v1/TckWS/Authorization";

                    System.Net.Http.HttpResponseMessage rawHttpResponse = null;

                    rawHttpResponse = client.PostAsync(url, content).Result;  // configure the Client to not capture current context, returning on a Thread Pool thread, avoiding deadlocks
                    rawHttpResponse.EnsureSuccessStatusCode();      // EnsureSuccess is preferred, will generate exception on non-success


                    sw.Stop();

                    if (rawHttpResponse.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        // convert response to JSON
                        dynamic microIndicatorResponse = JsonConvert.DeserializeObject<dynamic>(
                            rawHttpResponse.Content.ReadAsStringAsync().Result);  // Result property blocks calling thread until task finishes

                        // dump response
                        Console.WriteLine(microIndicatorResponse.ToString());
                        Console.WriteLine();
                        Console.WriteLine("Elapsed Time: {0} ms", sw.ElapsedMilliseconds);
                    }
                    else
                    {
                        // dump error response
                        var errorResponse = rawHttpResponse.Content.ReadAsStringAsync().Result;
                        Console.WriteLine(errorResponse);
                        Console.WriteLine();
                        Console.WriteLine("Elapsed Time: {0} ms", sw.ElapsedMilliseconds);
                    }
                } // end using block



                //System.Net.Http.HttpClient theHttpClient = new System.Net.Http.HttpClient();


            }
            catch (Exception ex)
            {
                System.Console.WriteLine();
                System.Console.WriteLine(ex.Message);
            }

            System.Console.WriteLine();
            System.Console.WriteLine("Press any key to exit...");
            System.Console.ReadLine();
            

        }

        /// <summary>
        /// Find a certificate in the Personal area of the cert store, by thumbprint
        /// </summary>
        /// <param name="theThumbprint"></param>
        /// <param name="theCertStoreName"</param>
        /// <returns></returns>
        private static System.Security.Cryptography.X509Certificates.X509Certificate2 FindCertByThumbprint(string theThumbprint, 
                                                                                                            System.Security.Cryptography.X509Certificates.StoreName theCertStoreName, 
                                                                                                            System.Security.Cryptography.X509Certificates.StoreLocation theCertLocation, 
                                                                                                            bool SearchOnlyValidCerts)
        {
            System.Security.Cryptography.X509Certificates.X509Certificate2 theCert = null;
            System.Security.Cryptography.X509Certificates.X509Certificate2Collection allCerts;
            System.Security.Cryptography.X509Certificates.X509Store theStore = new System.Security.Cryptography.X509Certificates.X509Store(theCertStoreName, theCertLocation);
            theStore.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);

            allCerts = theStore.Certificates.Find(System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint, theThumbprint, SearchOnlyValidCerts);
            foreach (System.Security.Cryptography.X509Certificates.X509Certificate2 someCert in allCerts)
            {
                // take the first one found, it should be the only one matching the thumbprint anyway
                theCert = someCert;
                break;
            }

            if (null == theCert)
                throw new System.Security.Cryptography.CryptographicException("Requested X509 certificate not found in requested store.");

            return theCert;
        }

    }

}
