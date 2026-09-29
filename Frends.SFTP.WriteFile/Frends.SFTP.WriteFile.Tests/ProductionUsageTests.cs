using System;
using System.IO;
using System.Text;
using NUnit.Framework;
using Renci.SshNet.Common;
using Frends.SFTP.WriteFile.Definitions;
using Frends.SFTP.WriteFile.Enums;

namespace Frends.SFTP.WriteFile.Tests;

/// <summary>
/// Mirrors how production processes call the task (HostKeyAlgorithm Any, no fingerprint, no keyboard-interactive).
/// Requires the Dockerized SFTP server; its sshd_config allows publickey and starts sessions in /upload.
/// </summary>
[TestFixture]
public class ProductionUsageTests : WriteFileTestBase
{
    [TestCase(FileEncoding.UTF8, null, "Innehåll med åäö ÅÄÖ.")]
    [TestCase(FileEncoding.Other, "windows-1252", "Innehåll med åäö ÅÄÖ.")]
    public void WriteFile_TestPasswordOverwriteWithCreatedDirectoriesAndVerify(FileEncoding fileEncoding, string encodingName, string content)
    {
        _input.Path = "/upload/production/nested/file.txt";
        _input.FileEncoding = fileEncoding;
        _input.EncodingInString = encodingName;
        _input.EnableBom = false;
        _input.WriteBehaviour = WriteOperation.Overwrite;
        _input.AddNewLine = false;
        _input.Content = "First version.";
        var options = new Options { CreateDestinationDirectories = true, VerifyWrite = true };

        SFTP.WriteFile(_input, _connection, options);
        _input.Content = content;
        var result = SFTP.WriteFile(_input, _connection, options);

        var expectedBytes = fileEncoding == FileEncoding.UTF8
            ? new UTF8Encoding(false).GetBytes(content)
            : CodePagesEncodingProvider.Instance.GetEncoding(encodingName).GetBytes(content);
        Assert.IsTrue(result.Verified);
        Assert.AreEqual(_input.Path, result.RemotePath);
        CollectionAssert.AreEqual(expectedBytes, Helpers.GetDestinationFileBytes(_input.Path));
    }

    [TestCase("rsa_pem_key", null)]
    [TestCase("rsa_pem_key", "")]
    [TestCase("rsa_pem_key_encrypted", "passphrase")]
    [TestCase("rsa_pkcs8_key", null)]
    [TestCase("rsa_putty_v3_key.ppk", null)]
    [TestCase("rsa_openssh_key", "passphrase")]
    [TestCase("ed25519_key", null)]
    [TestCase("ecdsa_nistp256_key", "passphrase")]
    public void WriteFile_TestPrivateKeyFileOnlyToLoginDirectoryWithoutVerify(string keyFile, string passphrase)
    {
        var connection = Helpers.GetSftpConnection();
        connection.Authentication = AuthenticationType.UsernamePrivateKeyFile;
        connection.Password = null;
        connection.PrivateKeyFile = Helpers.GetTestDataPath(keyFile);
        connection.PrivateKeyPassphrase = passphrase;
        _input.Path = "payment.xml";
        _input.FileEncoding = FileEncoding.UTF8;
        _input.EnableBom = false;
        _input.WriteBehaviour = WriteOperation.Error;
        _input.Content = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Document><Nm>Åsa Öberg</Nm></Document>";
        var options = new Options { CreateDestinationDirectories = false, VerifyWrite = false };

        var result = SFTP.WriteFile(_input, connection, options);

        Assert.IsFalse(result.Verified);
        Assert.AreEqual("payment.xml", result.RemotePath);
        CollectionAssert.AreEqual(new UTF8Encoding(false).GetBytes(_input.Content), Helpers.GetDestinationFileBytes("/upload/payment.xml"));

        var ex = Assert.Throws<ArgumentException>(() => SFTP.WriteFile(_input, connection, options));
        Assert.AreEqual("File already exists: payment.xml", ex.Message);
    }

    [Test]
    public void WriteFile_TestPrivateKeyFileOnlyWithUnauthorizedKeyThrows()
    {
        var keyFile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        try
        {
            File.WriteAllText(keyFile, Helpers.GenerateDummySshKey().ToPrivateKey());
            var connection = Helpers.GetSftpConnection();
            connection.Authentication = AuthenticationType.UsernamePrivateKeyFile;
            connection.Password = null;
            connection.PrivateKeyFile = keyFile;
            _input.Path = "payment.xml";

            Assert.Throws<SshAuthenticationException>(() => SFTP.WriteFile(_input, connection, new Options { VerifyWrite = false }));
        }
        finally
        {
            File.Delete(keyFile);
        }
    }
}
