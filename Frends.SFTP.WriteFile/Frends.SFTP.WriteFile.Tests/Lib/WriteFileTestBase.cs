using NUnit.Framework;
using Frends.SFTP.WriteFile.Definitions;
using Frends.SFTP.WriteFile.Enums;

namespace Frends.SFTP.WriteFile.Tests;

/// <summary>
/// Base for integration tests. Requires the Dockerized SFTP server on localhost:2222.
/// </summary>
[Category("Integration")]
public class WriteFileTestBase
{
    internal static Input _input;
    internal static Connection _connection;
    internal static Options _options;
    internal static string _content;


    [SetUp]
    public void SetUp()
    {
        _content = "This is a test file.";
        _connection = Helpers.GetSftpConnection();
        _input = new Input
        {
            Path = "/upload/test.txt",
            Content = _content,
            FileEncoding = FileEncoding.ANSI,
            WriteBehaviour = WriteOperation.Error
        };
        _options = new Options();
    }

    [TearDown]
    public void TearDown()
    {
        Helpers.DeleteDestinationFiles();
    }
}

