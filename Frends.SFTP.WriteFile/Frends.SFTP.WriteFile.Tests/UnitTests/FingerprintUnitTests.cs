using NUnit.Framework;
using Renci.SshNet;
using Renci.SshNet.Common;
using Frends.SFTP.WriteFile.Definitions;
using Frends.SFTP.WriteFile.Enums;

namespace Frends.SFTP.WriteFile.Tests;

/// <summary>
/// Fingerprint checks against known host keys. Expected values are taken from `ssh-keygen -l -E md5|sha256`,
/// so these also verify that the SSH.NET fingerprint formats still match what users copy from OpenSSH.
/// No server needed.
/// </summary>
[TestFixture]
[Category("Unit")]
public class FingerprintUnitTests
{
    private const string RsaMD5 = "2c:d8:1c:8d:47:36:8c:36:8e:8d:1b:06:c4:e3:60:9c";
    private const string RsaSha256Base64 = "TYKso2S+ny7MsKGG+sE0GbxOPeeqxxh4Bm8us98S680";
    private const string RsaSha256Hex = "4d82aca364be9f2eccb0a186fac13419bc4e3de7aac71878066f2eb3df12ebcd";
    private const string Ed25519MD5 = "fb:76:b2:d3:95:dd:e0:3d:46:1a:b4:5c:c2:2f:db:98";
    private const string Ed25519Sha256Base64 = "haeNxVrptx93jl+ylx97CMh3CjLNpHhAb0FejukrEYY";
    private const string Ed25519Sha256Hex = "85a78dc55ae9b71f778e5fb2971f7b08c8770a32cda478406f415e8ee92b1186";

    private static HostKeyEventArgs CreateHostKeyEventArgs(HostKeyAlgorithms algorithm, string algorithmName, string publicKeyFile)
    {
        using var client = new SftpClient(new ConnectionInfo("localhost", 22, "user", new PasswordAuthenticationMethod("user", "pass")));
        Util.ForceHostKeyAlgorithm(client, algorithm);
        var host = client.ConnectionInfo.HostKeyAlgorithms[algorithmName](Helpers.ReadPublicKeyBlob(publicKeyFile));
        return new HostKeyEventArgs(host);
    }

    private static HostKeyEventArgs RsaHostKey() => CreateHostKeyEventArgs(HostKeyAlgorithms.RSA, "ssh-rsa", "rsa_openssh_key.pub");

    private static HostKeyEventArgs Ed25519HostKey() => CreateHostKeyEventArgs(HostKeyAlgorithms.Ed25519, "ssh-ed25519", "ed25519_key.pub");

    [Test]
    public void VerifyServerFingerprint_HostKeyEventArgsFormatsMatchOpenSsh()
    {
        var e = RsaHostKey();
        Assert.AreEqual(RsaMD5, e.FingerPrintMD5);
        Assert.AreEqual(RsaSha256Base64, e.FingerPrintSHA256);
    }

    [TestCase(RsaMD5)]
    [TestCase("2C:D8:1C:8D:47:36:8C:36:8E:8D:1B:06:C4:E3:60:9C")]
    [TestCase("2cd81c8d47368c368e8d1b06c4e3609c")]
    [TestCase("2CD81C8D47368C368E8D1B06C4E3609C")]
    [TestCase(RsaSha256Base64)]
    [TestCase(RsaSha256Hex)]
    public void VerifyServerFingerprint_RsaMatches(string expected)
    {
        var e = RsaHostKey();
        var message = Util.VerifyServerFingerprint(e, expected);
        Assert.IsTrue(e.CanTrust);
        Assert.AreEqual("", message);
    }

    [TestCase(Ed25519MD5)]
    [TestCase(Ed25519Sha256Base64)]
    [TestCase(Ed25519Sha256Hex)]
    public void VerifyServerFingerprint_Ed25519Matches(string expected)
    {
        var e = Ed25519HostKey();
        var message = Util.VerifyServerFingerprint(e, expected);
        Assert.IsTrue(e.CanTrust);
        Assert.AreEqual("", message);
    }

    [TestCase(Ed25519MD5)]
    [TestCase("fb76b2d395dde03d461ab45cc22fdb98")]
    [TestCase(Ed25519Sha256Base64)]
    [TestCase(Ed25519Sha256Hex)]
    public void VerifyServerFingerprint_MismatchIsNotTrusted(string expected)
    {
        var e = RsaHostKey();
        var message = Util.VerifyServerFingerprint(e, expected);
        Assert.IsFalse(e.CanTrust);
        StringAssert.StartsWith("Can't trust SFTP server. The server fingerprint does not match.", message);
    }

    [Test]
    public void VerifyServerFingerprint_UnsupportedFormatIsNotTrusted()
    {
        var e = RsaHostKey();
        var message = Util.VerifyServerFingerprint(e, "nuDEsWN4tfEQ684x7RySiCwjGXmX2CfBaBHeSqO8vfiurenvire56");
        Assert.IsFalse(e.CanTrust);
        Assert.AreEqual("Expected server fingerprint was given in unsupported format.", message);
    }
}
