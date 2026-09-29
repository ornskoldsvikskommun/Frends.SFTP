using NUnit.Framework;
using Renci.SshNet.Common;
using System;
using System.IO;
using System.Net.Sockets;
using Frends.SFTP.WriteFile.Enums;

namespace Frends.SFTP.WriteFile.Tests;

[TestFixture]
public class ErrorTests : WriteFileTestBase
{
    [Test]
    public void WriteFile_TestFileExistsThrows()
    {
        var result = SFTP.WriteFile(_input, _connection, _options);
        Assert.IsTrue(Helpers.DestinationFileExists(_input.Path));

        var ex = Assert.Throws<ArgumentException>(() => SFTP.WriteFile(_input, _connection, _options));
        Assert.AreEqual($"File already exists: {_input.Path}", ex.Message);
    }

    [Test]
    public void WriteFile_TestThrowsWithWrongPort()
    {
        _connection.Port = 51644;
        var ex = Assert.Throws<SocketException>(() => SFTP.WriteFile(_input, _connection, _options));
    }

    [Test]
    public void WriteFile_TestThrowsWithIncorrectCredentials()
    {
        _connection.Password = "demo";
        _connection.Username = "demo";

        var ex = Assert.Throws<SshAuthenticationException>(() => SFTP.WriteFile(_input, _connection, _options));
        Assert.AreEqual("Permission denied (password).", ex.Message);
    }

    [Test]
    public void WriteFile_TestThrowsWithIncorrectPrivateKeyPassphrase()
    {
        _connection.Authentication = AuthenticationType.UsernamePasswordPrivateKeyFile;
        _connection.PrivateKeyPassphrase = "demo";
        _connection.PrivateKeyFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "../../../Volumes/ssh_host_rsa_key");

        var ex = Assert.Throws<ArgumentException>(() => SFTP.WriteFile(_input, _connection, _options));
        Assert.IsTrue(ex.Message.StartsWith("Error when initializing connection info:"));
    }

    [Test]
    public void WriteFile_TestThrowsWithEmptyPrivateKeyFile()
    {
        _connection.Authentication = AuthenticationType.UsernamePasswordPrivateKeyFile;
        _connection.PrivateKeyPassphrase = "passphrase";
        _connection.PrivateKeyFile = "";

        var ex = Assert.Throws<ArgumentException>(() => SFTP.WriteFile(_input, _connection, _options));
        Assert.IsTrue(ex.Message.StartsWith("Error when initializing connection info: "));
    }

    [Test]
    public void WriteFile_TestThrowsWithIncorrectPrivateKeyString()
    {
        var key = Helpers.GenerateDummySshKey();

        _connection.Authentication = AuthenticationType.UsernamePasswordPrivateKeyString;
        _connection.PrivateKeyPassphrase = "passphrase";
        _connection.PrivateKeyString = key.ToString();

        var ex = Assert.Throws<ArgumentException>(() => SFTP.WriteFile(_input, _connection, _options));
        Assert.IsTrue(ex.Message.StartsWith("Error when initializing connection info: "));
    }

    [Test]
    public void WriteFile_TestThrowsWithIncorrectServerFingerprint()
    {
        var fingerprint = "f6:fc:1c:03:17:5f:67:4f:1f:0b:50:5a:9f:f9:30:e5";

        _connection.ServerFingerPrint = fingerprint;

        var ex = Assert.Throws<SshConnectionException>(() => SFTP.WriteFile(_input, _connection, _options));
        Assert.AreEqual("Host key could not be verified.", ex.Message);
    }
}

