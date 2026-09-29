using System;
using System.Text;
using NUnit.Framework;
using Frends.SFTP.WriteFile.Definitions;
using Frends.SFTP.WriteFile.Enums;

namespace Frends.SFTP.WriteFile.Tests;

/// <summary>
/// Util.GetEncoding. No server needed.
/// </summary>
[TestFixture]
[Category("Unit")]
public class EncodingUnitTests
{
    [TestCase(true, 3)]
    [TestCase(false, 0)]
    public void GetEncoding_Utf8Bom(bool enableBom, int preambleLength)
    {
        var encoding = Util.GetEncoding(FileEncoding.UTF8, enableBom);
        Assert.AreEqual(65001, encoding.CodePage);
        Assert.AreEqual(preambleLength, encoding.GetPreamble().Length);
    }

    [TestCase(FileEncoding.ASCII, 20127)]
    [TestCase(FileEncoding.WINDOWS1252, 1252)]
    public void GetEncoding_CodePage(FileEncoding fileEncoding, int codePage)
    {
        Assert.AreEqual(codePage, Util.GetEncoding(fileEncoding, false).CodePage);
    }

    [Test]
    public void GetEncoding_Ansi()
    {
        Assert.AreEqual(Encoding.Default, Util.GetEncoding(FileEncoding.ANSI, false));
    }

    [TestCase("windows-1252", 1252)]
    [TestCase("iso-8859-1", 28591)]
    [TestCase("windows-1257", 1257)]
    public void GetEncoding_Other(string name, int codePage)
    {
        Assert.AreEqual(codePage, Util.GetEncoding(FileEncoding.Other, false, name).CodePage);
    }

    [Test]
    public void GetEncoding_OtherWindows1252EncodesSwedishCharacters()
    {
        var encoding = Util.GetEncoding(FileEncoding.Other, false, "windows-1252");
        CollectionAssert.AreEqual(new byte[] { 0xE5, 0xE4, 0xF6, 0xC5, 0xC4, 0xD6 }, encoding.GetBytes("åäöÅÄÖ"));
        Assert.AreEqual(0, encoding.GetPreamble().Length);
    }

    [Test]
    public void GetEncoding_Utf8WithoutBomWritesNoPreamble()
    {
        var encoding = Util.GetEncoding(FileEncoding.UTF8, false);
        CollectionAssert.AreEqual(new byte[] { 0x3C, 0xC3, 0xA5 }, encoding.GetBytes("<å"));
        CollectionAssert.IsEmpty(encoding.GetPreamble());
    }

    [Test]
    public void GetEncoding_OtherInvalidThrows()
    {
        Assert.Throws<ArgumentException>(() => Util.GetEncoding(FileEncoding.Other, false, "not-an-encoding"));
    }
}
