using System;
using System.IO;
using System.Text;

namespace WebGenericCredentialsLib
{
    /// <summary>
    /// Static class for methods of extracting username and password from the windows credential store.
    /// </summary>
    public static class CredAccess
    {
        /// <summary>
        /// Get the username and password that we can use to access things here.
        /// </summary>
        /// <returns>A tuple of strings. The first is the username, the second the password. It will throw if it can't get them.</returns>
        public static Tuple<string, string> LookupUserPass(string credName)
        {
            Credential cred;
            if (!NativeMethods.CredRead(credName, CRED_TYPE.GENERIC, 0, out cred))
            {
                var bld = new StringBuilder();
                bld.AppendLine("Error getting credentials");
                bld.AppendLine("Use the credential control panel, create a generic credential for windows domains for cern.ch with username and password");
                throw new UnauthorizedAccessException(bld.ToString());
            }

            string password;
            using (var m = new MemoryStream(cred.CredentialBlob, false))
            using (var sr = new StreamReader(m, System.Text.Encoding.Unicode))
            {
                password = sr.ReadToEnd();
            }

            return Tuple.Create(cred.UserName, password);
        }
    }
}
