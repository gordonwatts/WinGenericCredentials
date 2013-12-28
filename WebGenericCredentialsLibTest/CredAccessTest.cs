using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace WebGenericCredentialsLibTest
{
    [TestClass]
    public class CredAccessTest
    {
        [TestMethod]
        public void TestLoadCern()
        {
            var r = WebGenericCredentialsLib.CredAccess.LookupUserPass("cern.ch");
            Assert.AreEqual("gwatts", r.Item1, "username");
        }

        [TestMethod]
        [ExpectedException(typeof(System.UnauthorizedAccessException))]
        public void TestMissingCred()
        {
            var r = WebGenericCredentialsLib.CredAccess.LookupUserPass("bogus.ch");
        }
    }
}
