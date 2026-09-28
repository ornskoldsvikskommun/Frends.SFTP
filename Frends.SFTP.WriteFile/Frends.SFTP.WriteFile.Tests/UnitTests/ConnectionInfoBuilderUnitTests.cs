using System;
using System.IO;
using System.Linq;
using System.Text;
using NUnit.Framework;
using Renci.SshNet;
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

    [TestCase("ed25519_key", null)]
    [TestCase("ed25519_key", "")]
    [TestCase("ecdsa_nistp256_key", "passphrase")]
    [TestCase("rsa_openssh_key", "passphrase")]
    public void BuildConnectionInfo_PrivateKeyString(string keyFile, string passphrase)
    {
        _connection.Authentication = AuthenticationType.UsernamePrivateKeyString;
        _connection.PrivateKeyString = File.ReadAllText(Helpers.GetTestDataPath(keyFile));
        _connection.PrivateKeyPassphrase = passphrase;

        var info = Build();

        Assert.AreEqual(1, info.AuthenticationMethods.Count);
        Assert.IsInstanceOf<PrivateKeyAuthenticationMethod>(info.AuthenticationMethods[0]);
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

    [TestCase("rsa_pem_key", null)]
    [TestCase("rsa_pem_key", "")]
    [TestCase("ed25519_key", null)]
    [TestCase("ed25519_key", "")]
    [TestCase("rsa_openssh_key", "passphrase")]
    [TestCase("ecdsa_nistp256_key", "passphrase")]
    public void BuildConnectionInfo_PrivateKeyFileOnly(string keyFile, string passphrase)
    {
        _connection.Authentication = AuthenticationType.UsernamePrivateKeyFile;
        _connection.Password = null;
        _connection.PrivateKeyFile = Helpers.GetTestDataPath(keyFile);
        _connection.PrivateKeyPassphrase = passphrase;

        var info = Build();

        Assert.AreEqual(1, info.AuthenticationMethods.Count);
        Assert.IsInstanceOf<PrivateKeyAuthenticationMethod>(info.AuthenticationMethods[0]);
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
    public void WriteFile_TestDsaPrivateKeyFailsWithClearMessage(string keyFile, string expectedMessage)
    {
        _connection.Authentication = AuthenticationType.UsernamePrivateKeyFile;
        _connection.PrivateKeyFile = Helpers.GetTestDataPath(keyFile);
        _connection.Port = 1;

        var ex = Assert.Throws<ArgumentException>(() => SFTP.WriteFile(_input, _connection, new Options()));
        StringAssert.StartsWith("Error when initializing connection info:", ex.Message);
        StringAssert.Contains(expectedMessage, ex.Message);
    }

    [TestCase("rsa_openssh_key")]
    [TestCase("ecdsa_nistp256_key")]
    public void BuildConnectionInfo_WrongPassphraseThrows(string keyFile)
    {
        _connection.Authentication = AuthenticationType.UsernamePrivateKeyFile;
        _connection.PrivateKeyFile = Helpers.GetTestDataPath(keyFile);
        _connection.PrivateKeyPassphrase = "wrong";

        Assert.Catch<Exception>(() => Build());
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
