using System;
using System.Linq;
using NUnit.Framework;
using Renci.SshNet;
using Frends.SFTP.WriteFile.Definitions;
using Frends.SFTP.WriteFile.Enums;

namespace Frends.SFTP.WriteFile.Tests;

/// <summary>
/// Host key algorithm forcing. No server needed.
/// </summary>
[TestFixture]
[Category("Unit")]
public class HostKeyAlgorithmUnitTests
{
    private static SftpClient CreateClient()
    {
        return new SftpClient(new ConnectionInfo("localhost", 22, "user", new PasswordAuthenticationMethod("user", "pass")));
    }

    [TestCase(HostKeyAlgorithms.RSA, "ssh-rsa", "rsa_openssh_key.pub")]
    [TestCase(HostKeyAlgorithms.Ed25519, "ssh-ed25519", "ed25519_key.pub")]
    [TestCase(HostKeyAlgorithms.nistp256, "ecdsa-sha2-nistp256", "ecdsa_nistp256_key.pub")]
    [TestCase(HostKeyAlgorithms.nistp384, "ecdsa-sha2-nistp384", "ecdsa_nistp384_key.pub")]
    [TestCase(HostKeyAlgorithms.nistp521, "ecdsa-sha2-nistp521", "ecdsa_nistp521_key.pub")]
    public void ForceHostKeyAlgorithm_OnlyOffersForcedAlgorithm(HostKeyAlgorithms algorithm, string expectedName, string publicKeyFile)
    {
        using var client = CreateClient();

        Util.ForceHostKeyAlgorithm(client, algorithm);

        CollectionAssert.AreEqual(new[] { expectedName }, client.ConnectionInfo.HostKeyAlgorithms.Keys.ToArray());

        var host = client.ConnectionInfo.HostKeyAlgorithms[expectedName](Helpers.ReadPublicKeyBlob(publicKeyFile));
        Assert.AreEqual(expectedName, host.Name);
    }

    [Test]
    public void ForceHostKeyAlgorithm_DssThrows()
    {
        using var client = CreateClient();

        var ex = Assert.Throws<ArgumentException>(() => Util.ForceHostKeyAlgorithm(client, HostKeyAlgorithms.DSS));
        StringAssert.Contains("DSS (ssh-dss) is no longer supported", ex.Message);
    }

    [Test]
    public void WriteFile_TestDssHostKeyAlgorithmThrowsBeforeConnecting()
    {
        var connection = Helpers.GetSftpConnection();
        connection.Port = 1;
        connection.HostKeyAlgorithm = HostKeyAlgorithms.DSS;
        var input = new Input { Path = "/upload/test.txt", Content = "test", FileEncoding = FileEncoding.UTF8, WriteBehaviour = WriteOperation.Error };

        var ex = Assert.Throws<ArgumentException>(() => SFTP.WriteFile(input, connection, new Options()));
        StringAssert.Contains("DSS (ssh-dss) is no longer supported", ex.Message);
    }

    [Test]
    public void DefaultHostKeyAlgorithms_NoLongerContainDss()
    {
        using var client = CreateClient();

        CollectionAssert.DoesNotContain(client.ConnectionInfo.HostKeyAlgorithms.Keys, "ssh-dss");
        CollectionAssert.Contains(client.ConnectionInfo.HostKeyAlgorithms.Keys, "ssh-ed25519");
        CollectionAssert.Contains(client.ConnectionInfo.HostKeyAlgorithms.Keys, "rsa-sha2-256");
    }
}
