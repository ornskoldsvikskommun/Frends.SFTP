using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using NUnit.Framework;
using Org.BouncyCastle.Crypto;
using Renci.SshNet;
using Renci.SshNet.Common;
using Frends.SFTP.WriteFile.Definitions;
using Frends.SFTP.WriteFile.Enums;

namespace Frends.SFTP.WriteFile.Tests;

/// <summary>
/// ConnectionInfoBuilder auth and encoding setup. Keys in TestData are synthetic. No server needed.
/// </summary>
[TestFixture]
[Category("Unit")]
public class ConnectionInfoBuilderUnitTests
{
    private static readonly string _pemRsaKeyPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "../../../Volumes/ssh_host_rsa_key");

    private Input _input;
    private Connection _connection;

    [SetUp]
    public void SetUp()
    {
        _connection = Helpers.GetSftpConnection();
        _input = new Input
        {
            Path = "/upload/test.txt",
            Content = "test",
            FileEncoding = FileEncoding.UTF8,
            WriteBehaviour = WriteOperation.Error
        };
    }

    private ConnectionInfo Build() => new ConnectionInfoBuilder(_input, _connection).BuildConnectionInfo();

    [Test]
    public void BuildConnectionInfo_UsernamePassword()
    {
        var info = Build();

        Assert.AreEqual(_connection.Address, info.Host);
        Assert.AreEqual(_connection.Port, info.Port);
        Assert.AreEqual(_connection.Username, info.Username);
        Assert.AreEqual(TimeSpan.FromSeconds(_connection.ConnectionTimeout), info.Timeout);
        Assert.AreEqual(1, info.AuthenticationMethods.Count);
        Assert.IsInstanceOf<PasswordAuthenticationMethod>(info.AuthenticationMethods[0]);
    }

    [Test]
    public void BuildConnectionInfo_PrivateKeyFileEncryptedPem()
    {
        _connection.Authentication = AuthenticationType.UsernamePrivateKeyFile;
        _connection.PrivateKeyFile = _pemRsaKeyPath;
        _connection.PrivateKeyPassphrase = "passphrase";

        var info = Build();

        Assert.AreEqual(1, info.AuthenticationMethods.Count);
        Assert.IsInstanceOf<PrivateKeyAuthenticationMethod>(info.AuthenticationMethods[0]);
    }

    [Test]
    public void BuildConnectionInfo_PasswordAndPrivateKeyFileOpenSshEncrypted()
    {
        _connection.Authentication = AuthenticationType.UsernamePasswordPrivateKeyFile;
        _connection.PrivateKeyFile = Helpers.GetTestDataPath("rsa_openssh_key");
        _connection.PrivateKeyPassphrase = "passphrase";

        var info = Build();

        Assert.AreEqual(2, info.AuthenticationMethods.Count);
        Assert.IsInstanceOf<PasswordAuthenticationMethod>(info.AuthenticationMethods[0]);
        Assert.IsInstanceOf<PrivateKeyAuthenticationMethod>(info.AuthenticationMethods[1]);
    }

    // Every key format SSH.NET 2026 can load, all derived from synthetic keys in TestData.
    // The rsa_pem_key variants (PKCS#1, PKCS#8, PuTTY) are the same key, so they share rsa_pem_key.pub.
    [TestCase("rsa_pem_key", null, "rsa_pem_key.pub")]
    [TestCase("rsa_pem_key", "", "rsa_pem_key.pub")]
    [TestCase("rsa_pem_key_encrypted", "passphrase", "rsa_pem_key.pub")]
    [TestCase("rsa_pkcs8_key", null, "rsa_pem_key.pub")]
    [TestCase("rsa_pkcs8_key", "", "rsa_pem_key.pub")]
    [TestCase("rsa_pkcs8_key_encrypted", "passphrase", "rsa_pem_key.pub")]
    [TestCase("rsa_putty_v2_key.ppk", null, "rsa_pem_key.pub")]
    [TestCase("rsa_putty_v3_key.ppk", null, "rsa_pem_key.pub")]
    [TestCase("rsa_putty_v3_key.ppk", "", "rsa_pem_key.pub")]
    [TestCase("rsa_putty_v3_key_encrypted.ppk", "passphrase", "rsa_pem_key.pub")]
    [TestCase("rsa_openssh_key", "passphrase", "rsa_openssh_key.pub")]
    [TestCase("ecdsa_nistp256_key", "passphrase", "ecdsa_nistp256_key.pub")]
    [TestCase("ed25519_key", null, "ed25519_key.pub")]
    [TestCase("ed25519_key", "", "ed25519_key.pub")]
    public void BuildConnectionInfo_PrivateKeyFormatsLoadAsFileAndString(string keyFile, string passphrase, string publicKeyFile)
    {
        var expectedPublicKey = Helpers.ReadPublicKeyBlob(publicKeyFile);
        _connection.Password = null;
        _connection.PrivateKeyPassphrase = passphrase;

        _connection.Authentication = AuthenticationType.UsernamePrivateKeyFile;
        _connection.PrivateKeyFile = Helpers.GetTestDataPath(keyFile);
        AssertSinglePrivateKey(Build(), expectedPublicKey);

        _connection.Authentication = AuthenticationType.UsernamePrivateKeyString;
        _connection.PrivateKeyString = File.ReadAllText(Helpers.GetTestDataPath(keyFile));
        AssertSinglePrivateKey(Build(), expectedPublicKey);
    }

    private static void AssertSinglePrivateKey(ConnectionInfo info, byte[] expectedPublicKey)
    {
        var method = (PrivateKeyAuthenticationMethod)info.AuthenticationMethods.Single();
        var key = method.KeyFiles.Single();
        Assert.IsTrue(key.HostKeyAlgorithms.Any(a => a.Data.SequenceEqual(expectedPublicKey)), "Loaded key does not match the expected public key.");
    }

    [Test]
    public void BuildConnectionInfo_PasswordAndPrivateKeyStringPem()
    {
        _connection.Authentication = AuthenticationType.UsernamePasswordPrivateKeyString;
        _connection.PrivateKeyString = File.ReadAllText(_pemRsaKeyPath);
        _connection.PrivateKeyPassphrase = "passphrase";

        var info = Build();

        Assert.AreEqual(2, info.AuthenticationMethods.Count);
        Assert.IsInstanceOf<PrivateKeyAuthenticationMethod>(info.AuthenticationMethods[1]);
    }

    [TestCase(null)]
    [TestCase("")]
    public void BuildConnectionInfo_GeneratedRsaKeyAsFileAndString(string passphrase)
    {
        var key = Helpers.GenerateDummySshKey().ToPrivateKey();
        var keyFile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        try
        {
            File.WriteAllText(keyFile, key);

            _connection.Authentication = AuthenticationType.UsernamePrivateKeyFile;
            _connection.PrivateKeyFile = keyFile;
            _connection.PrivateKeyPassphrase = passphrase;
            Assert.IsInstanceOf<PrivateKeyAuthenticationMethod>(Build().AuthenticationMethods.Single());

            _connection.Authentication = AuthenticationType.UsernamePrivateKeyString;
            _connection.PrivateKeyString = key;
            Assert.IsInstanceOf<PrivateKeyAuthenticationMethod>(Build().AuthenticationMethods.Single());
        }
        finally
        {
            File.Delete(keyFile);
        }
    }

    [TestCase("dsa_pem_key", "Key 'DSA PRIVATE KEY' is not supported.")]
    [TestCase("dsa_openssh_key", "OpenSSH key type 'ssh-dss' is not supported.")]
    public void WriteFile_TestDsaPrivateKeyFailsBeforeConnectingWithClearMessage(string keyFile, string expectedMessage)
    {
        const string passphrase = "SyntheticSecret-4711";
        var keyLines = File.ReadAllLines(Helpers.GetTestDataPath(keyFile));
        _connection.Authentication = AuthenticationType.UsernamePrivateKeyFile;
        _connection.PrivateKeyFile = Helpers.GetTestDataPath(keyFile);
        _connection.PrivateKeyPassphrase = passphrase;
        // Nothing listens on port 1, so any connection attempt would surface as a SocketException instead.
        _connection.Port = 1;

        var ex = Assert.Throws<ArgumentException>(() => SFTP.WriteFile(_input, _connection, new Options()));
        StringAssert.StartsWith("Error when initializing connection info:", ex.Message);
        StringAssert.Contains(expectedMessage, ex.Message);
        StringAssert.DoesNotContain(passphrase, ex.Message);
        Assert.IsFalse(keyLines.Skip(1).Take(keyLines.Length - 2).Any(l => ex.Message.Contains(l)), "Exception message contains key material.");
    }

    [TestCase("rsa_pem_key_encrypted", null)]
    [TestCase("rsa_pem_key_encrypted", "")]
    [TestCase("rsa_openssh_key", null)]
    [TestCase("rsa_putty_v3_key_encrypted.ppk", "")]
    public void BuildConnectionInfo_EncryptedKeyWithoutPassphraseThrows(string keyFile, string passphrase)
    {
        _connection.Authentication = AuthenticationType.UsernamePrivateKeyFile;
        _connection.PrivateKeyFile = Helpers.GetTestDataPath(keyFile);
        _connection.PrivateKeyPassphrase = passphrase;

        var ex = Assert.Throws<SshPassPhraseNullOrEmptyException>(() => Build());
        Assert.AreEqual("Private key is encrypted but passphrase is empty.", ex.Message);
    }

    // SSH.NET reports a wrong passphrase differently per key format.
    [TestCase("rsa_openssh_key", typeof(SshException))]
    [TestCase("ecdsa_nistp256_key", typeof(SshException))]
    [TestCase("rsa_putty_v3_key_encrypted.ppk", typeof(SshException))]
    [TestCase("rsa_pem_key_encrypted", typeof(CryptographicException))]
    [TestCase("rsa_pkcs8_key_encrypted", typeof(InvalidCipherTextException))]
    public void BuildConnectionInfo_WrongPassphraseThrows(string keyFile, Type expectedException)
    {
        _connection.Authentication = AuthenticationType.UsernamePrivateKeyFile;
        _connection.PrivateKeyFile = Helpers.GetTestDataPath(keyFile);
        _connection.PrivateKeyPassphrase = "wrong";

        var ex = Assert.Throws(expectedException, () => Build());
        StringAssert.DoesNotContain("wrong", ex.Message);
    }

    [Test]
    public void BuildConnectionInfo_MissingPrivateKeyFileThrows()
    {
        _connection.Authentication = AuthenticationType.UsernamePrivateKeyFile;
        _connection.PrivateKeyFile = "";

        var ex = Assert.Throws<ArgumentException>(() => Build());
        Assert.AreEqual("Private key file path was not given.", ex.Message);
    }

    [Test]
    public void BuildConnectionInfo_KeyboardInteractiveIsAddedFirst()
    {
        _connection.UseKeyboardInteractiveAuthentication = true;

        var info = Build();

        Assert.AreEqual(2, info.AuthenticationMethods.Count);
        Assert.IsInstanceOf<KeyboardInteractiveAuthenticationMethod>(info.AuthenticationMethods[0]);
        Assert.IsInstanceOf<PasswordAuthenticationMethod>(info.AuthenticationMethods[1]);
    }

    [Test]
    public void BuildConnectionInfo_SetsEncoding()
    {
        _input.FileEncoding = FileEncoding.WINDOWS1252;

        var info = Build();

        Assert.AreEqual(1252, info.Encoding.CodePage);
    }

    [Test]
    public void BuildConnectionInfo_CurveKeyExchangeCanStillBeRemoved()
    {
        using var client = new SftpClient(Build());

        Assert.IsTrue(client.ConnectionInfo.KeyExchangeAlgorithms.Remove("curve25519-sha256"));
        Assert.IsTrue(client.ConnectionInfo.KeyExchangeAlgorithms.Remove("curve25519-sha256@libssh.org"));
        Assert.IsTrue(client.ConnectionInfo.KeyExchangeAlgorithms.Keys.Any());
    }
}
