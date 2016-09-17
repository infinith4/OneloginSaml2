using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Web;
using System.Web.Mvc;
using System.Xml;

namespace OneloginSaml2.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            AccountSettings accountSettings = new AccountSettings();
            AuthRequest req = new AuthRequest(new AppSettings(), accountSettings);
            return Redirect(accountSettings.idp_sso_target_url + "?SAMLRequest=" + Server.UrlEncode(req.GetRequest(AuthRequest.AuthRequestFormat.Base64)));
        }

        public ActionResult acs()
        {
            AccountSettings accountSettings = new AccountSettings();
            Response samlResponse = new Response(accountSettings);
            samlResponse.LoadXmlFromBase64(Request.Form["SAMLResponse"]);
            return View();
        }
        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }

        public class Certificate
        {
            public X509Certificate2 cert;

            public void LoadCertificate(string certificate)
            {
                cert = new X509Certificate2();
                cert.Import(StringToByteArray(certificate));
            }

            public void LoadCertificate(byte[] certificate)
            {
                cert = new X509Certificate2();
                cert.Import(certificate);
            }

            private byte[] StringToByteArray(string st)
            {
                byte[] bytes = new byte[st.Length];
                for (int i = 0; i < st.Length; i++)
                {
                    bytes[i] = (byte)st[i];
                }
                return bytes;
            }
        }
        public class AccountSettings
        {
            public string certificate = "-----BEGIN CERTIFICATE-----MIIENTCCAx2gAwIBAgIUe2fiXdQ/sHx6uyYZ4tBCC1NWQ1wwDQYJKoZIhvcNAQEF\nBQAwYjELMAkGA1UEBhMCVVMxGzAZBgNVBAoMEuadseaoquOCt+OCueODhuODoDEV\nMBMGA1UECwwMT25lTG9naW4gSWRQMR8wHQYDVQQDDBZPbmVMb2dpbiBBY2NvdW50\nIDkwMjgwMB4XDTE2MDgyMzA0MDY1N1oXDTIxMDgyNDA0MDY1N1owYjELMAkGA1UE\nBhMCVVMxGzAZBgNVBAoMEuadseaoquOCt+OCueODhuODoDEVMBMGA1UECwwMT25l\nTG9naW4gSWRQMR8wHQYDVQQDDBZPbmVMb2dpbiBBY2NvdW50IDkwMjgwMIIBIjAN\nBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuOm7Z8U7rDdY8eYmMhdWugDKD+b3\n2Do5dHIFQCYxeqKxLdhWX8ZZf0ARVr1kENg2eOPKS5KJgmrWxBcaOohwqKgLBPzp\nWhpsX5ML7IqExyUkLeg8BZlLPJJGmKZtirC4PABZWZIPXxOsy3jxs8lbVd9x78rJ\nhgOoOeq5HPQGRoVfyjDfJZblak8uRiFj/awtqQFMk3ZUujfTxefZyYWXFHc1vo/z\n1xGdZBiVjSPJ7rx6Gpn5Lf14tym8OByYMQb2bn33Mu5ltHPairCeUv62XnR+HsBH\nCHYXv5vC5ppw/sRUa7QqBujH9UtKBxpqbBEEQX2IKEHTqL3u0QTob1VZNQIDAQAB\no4HiMIHfMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFDlqpTFF2Qi3scdzzHGVQnqX\nF4jxMIGfBgNVHSMEgZcwgZSAFDlqpTFF2Qi3scdzzHGVQnqXF4jxoWakZDBiMQsw\nCQYDVQQGEwJVUzEbMBkGA1UECgwS5p2x5qiq44K344K544OG44OgMRUwEwYDVQQL\nDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgOTAyODCC\nFHtn4l3UP7B8ersmGeLQQgtTVkNcMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0B\nAQUFAAOCAQEANLVRk2eo7XuhI7C5oxXOIrttbuYvL3bUIVDj88ZF8m7rCVGHPeB+\nrdKoDy40MKvenyA2a1JbWmkTA7mg+SvFADtmkMDqNqyNB0NbW5UtmSf2oDw3ZMSG\nxCFH+Uy5dJrJ5EWDfhj3ceE2FBbhRr1t+5seXdkDmdD4OOQoAaH0Gk2VWLu83ZHg\nJnOjXvFc94MtQVI4fBgA57SLj6y+ENwl9ACRG5zjXGyNwyqBdC3fBGC3hA1NkTru\nEg+4IKHzV0vx9a4rhDTU6guExN4ca7b1oPDcZRNt1d/lLSvddFlwEn6pqmy4Muth\nt9hvm0qVHLQJU90jgPTSr5C2Km7YGXIrpQ==\n-----END CERTIFICATE-----";
            public string idp_sso_target_url = "https://ts1045.onelogin.com/trust/saml2/http-post/sso/579094";
        }

        public class AppSettings
        {
            public string assertionConsumerServiceUrl = "http://localhost:65287/Home/acs";
            public string issuer = "test-app";
        }

        public class Response
        {
            private XmlDocument xmlDoc;
            private AccountSettings accountSettings;
            private Certificate certificate;

            public Response(AccountSettings accountSettings)
            {
                this.accountSettings = accountSettings;
                certificate = new Certificate();
                certificate.LoadCertificate(accountSettings.certificate);
            }

            public void LoadXml(string xml)
            {
                xmlDoc = new XmlDocument();
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.XmlResolver = null;
                xmlDoc.LoadXml(xml);
            }

            public void LoadXmlFromBase64(string response)
            {
                System.Text.ASCIIEncoding enc = new System.Text.ASCIIEncoding();
                LoadXml(enc.GetString(Convert.FromBase64String(response)));
            }

            public bool IsValid()
            {
                bool status = false;

                XmlNamespaceManager manager = new XmlNamespaceManager(xmlDoc.NameTable);
                manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
                XmlNodeList nodeList = xmlDoc.SelectNodes("//ds:Signature", manager);

                SignedXml signedXml = new SignedXml(xmlDoc);
                signedXml.LoadXml((XmlElement)nodeList[0]);
                return signedXml.CheckSignature(certificate.cert, true);
            }

            public string GetNameID()
            {
                XmlNamespaceManager manager = new XmlNamespaceManager(xmlDoc.NameTable);
                manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
                manager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
                manager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

                XmlNode node = xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion/saml:Subject/saml:NameID", manager);
                return node.InnerText;
            }
        }

        public class AuthRequest
        {
            public string id;
            private string issue_instant;
            private AppSettings appSettings;
            private AccountSettings accountSettings;

            public enum AuthRequestFormat
            {
                Base64 = 1
            }

            public AuthRequest(AppSettings appSettings, AccountSettings accountSettings)
            {
                this.appSettings = appSettings;
                this.accountSettings = accountSettings;

                id = "_" + System.Guid.NewGuid().ToString();
                issue_instant = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
            }

            public string GetRequest(AuthRequestFormat format)
            {
                using (StringWriter sw = new StringWriter())
                {
                    XmlWriterSettings xws = new XmlWriterSettings();
                    xws.OmitXmlDeclaration = true;

                    using (XmlWriter xw = XmlWriter.Create(sw, xws))
                    {
                        xw.WriteStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
                        xw.WriteAttributeString("AttributeConsumingServiceIndex", "1");
                        xw.WriteAttributeString("ID", id);
                        xw.WriteAttributeString("Version", "2.0");
                        xw.WriteAttributeString("IssueInstant", issue_instant);
                        //xw.WriteAttributeString("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
                        xw.WriteAttributeString("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact");
                        xw.WriteAttributeString("AssertionConsumerServiceURL", appSettings.assertionConsumerServiceUrl);

                        xw.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
                        xw.WriteString(appSettings.issuer);
                        xw.WriteEndElement();

                        xw.WriteStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol");
                        xw.WriteAttributeString("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
                        xw.WriteAttributeString("AllowCreate", "true");
                        xw.WriteEndElement();

                        xw.WriteStartElement("samlp", "RequestedAuthnContext", "urn:oasis:names:tc:SAML:2.0:protocol");
                        xw.WriteAttributeString("Comparison", "exact");

                        xw.WriteStartElement("saml", "AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:assertion");
                        xw.WriteString("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
                        xw.WriteEndElement();

                        xw.WriteEndElement(); // RequestedAuthnContext

                        xw.WriteEndElement();
                    }

                    if (format == AuthRequestFormat.Base64)
                    {
                        string requestXml = sw.ToString();
                        byte[] toEncodeAsBytes = System.Text.ASCIIEncoding.ASCII.GetBytes(sw.ToString());
                        return System.Convert.ToBase64String(toEncodeAsBytes);
                    }

                    return null;
                }
            }
        }
    }
}