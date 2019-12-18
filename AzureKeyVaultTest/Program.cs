using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace AzureKeyVaultTest
{
    class Program
    {
        static void Main(string[] args)
        {
            KeyVaultReader.DoVault();
        }
    }

    public class KeyVaultReader
    {
        // Authenticate
        private const string BASESECRETURI = "https://nameyouwant.vault.azure.net";
        private const string CLIENTSECRET = "k5m@JD/=LufTc=sT4QfB9Q5ov@[bN1JM";
        private const string CLIENTID = "af28651d-69d5-49e5-8ed5-4e90bf58d73a";
        private const string SECRETNAME = "AppSecret";

        private static KeyVaultClient kvc = null;

        private static async Task<string> GetToken(string authority, string resource, string scope)
        {
            var authContext = new AuthenticationContext(authority);
            ClientCredential clientCred = new ClientCredential(CLIENTID, CLIENTSECRET);
            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
            {
                throw new InvalidOperationException("Failed to obtain the JWT token");
            }

            return result.AccessToken;
        }

        public static void DoVault()
        {
            kvc = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(GetToken));

            // write
            WriteKeyVault();
            Console.WriteLine("Press enter after seeing the bundle value show up");
            Console.ReadLine();

            SecretBundle secret = Task.Run(() => kvc.GetSecretAsync(BASESECRETURI +
                                                                    @"/secrets/" + SECRETNAME)).ConfigureAwait(false).GetAwaiter().GetResult();
            Console.WriteLine(secret.Tags["Test1"].ToString());
            Console.WriteLine(secret.Tags["Test2"].ToString());
            Console.WriteLine(secret.Tags["CanBeAnything"].ToString());

            Console.ReadLine();
        }

        private static async void WriteKeyVault() // string szPFX, string szCER, string szPassword)
        {
            SecretAttributes attribs = new SecretAttributes
            {
                Enabled = true
            };

            IDictionary<string, string> alltags = new Dictionary<string, string>();
            alltags.Add("Test1", "This is a test1 value");
            alltags.Add("Test2", "This is a test2 value");
            alltags.Add("CanBeAnything", "Including a long encrypted string if you choose");
            string testValue = "searchValue"; // this is what you will use to search for the item later
            string contentType = "SecretInfo"; // whatever you want to categorize it by; you name it

            SecretBundle bundle = await kvc.SetSecretAsync
                (BASESECRETURI, SECRETNAME, testValue, alltags, contentType, attribs);
            Console.WriteLine("Bundle:" + bundle.Tags["Test1"].ToString());
        }
    }
}
