using System.ComponentModel;
using Renci.SshNet;
using Frends.SFTP.WriteFile.Definitions;
using Frends.SFTP.WriteFile.Enums;
using Renci.SshNet.Sftp;

namespace Frends.SFTP.WriteFile;

/// <summary>
/// Main class for the task.
/// </summary>
public class SFTP
{
    /// <summary>
    /// Writes string content to a file through SFTP connection.
    /// [Documentation](https://tasks.frends.com/tasks/frends-tasks/Frends.SFTP.WriteFile)
    /// </summary>
    /// <param name="connection">Transfer connection parameters</param>
    /// <param name="input">Write options with full path and string content</param>
    /// <param name="options">Options for write file</param>
    /// <returns>Object {string RemotePath, double SizeInMegaBytes, bool Verified} </returns>
    public static Result WriteFile([PropertyTab] Input input, [PropertyTab] Connection connection, [PropertyTab] Options options)
    {
        ConnectionInfo connectionInfo;
        // Establish connectionInfo with connection parameters
        try
        {
            var builder = new ConnectionInfoBuilder(input, connection);
            connectionInfo = builder.BuildConnectionInfo();
        }
        catch (Exception e)
        {
            throw new ArgumentException($"Error when initializing connection info: {e}");
        }

        using var client = new SftpClient(connectionInfo);

        //Disable support for these host key exchange algorithms relating: https://github.com/FrendsPlatform/Frends.SFTP/security/dependabot/4
        client.ConnectionInfo.KeyExchangeAlgorithms.Remove("curve25519-sha256");
        client.ConnectionInfo.KeyExchangeAlgorithms.Remove("curve25519-sha256@libssh.org");

        if (connection.HostKeyAlgorithm != HostKeyAlgorithms.Any)
            Util.ForceHostKeyAlgorithm(client, connection.HostKeyAlgorithm);

        // Check the fingerprint of the server if given.
        if (!string.IsNullOrEmpty(connection.ServerFingerPrint))
        {
            var userResultMessage = "";
            try
            {
                userResultMessage = Util.CheckServerFingerprint(client, connection.ServerFingerPrint);
            }
            catch (Exception ex) { throw new ArgumentException($"Error when checking the server fingerprint: {ex.Message}"); }
        }

        client.ConnectionInfo.Timeout = TimeSpan.FromSeconds(connection.ConnectionTimeout);

        client.BufferSize = connection.BufferSize * 1024;

        client.Connect();

        if (!client.IsConnected) throw new ArgumentException($"Error while connecting to destination: {connection.Address}");

        try
        {
            var targetDirectory = Path.GetDirectoryName(input.Path);

            if (!string.IsNullOrEmpty(targetDirectory))
            {
                targetDirectory = targetDirectory.Replace("\\", "/");

                if (!client.Exists(targetDirectory))
                {
                    if (options.CreateDestinationDirectories == true)
                    {
                        try
                        {
                            Util.CreateDirectoriesRecursively(client, targetDirectory);
                        }
                        catch (Exception ex)
                        {
                            throw new ArgumentException($"Error while creating destination directory '{targetDirectory}': {ex.Message}", ex);
                        }
                    }
                    else
                    {
                        throw new ArgumentException($"Destination directory '{targetDirectory}' was not found.");
                    }
                }
            }

            var encoding = Util.GetEncoding(input.FileEncoding, input.EnableBom, input.EncodingInString);

            switch (input.WriteBehaviour)
            {
                case WriteOperation.Append:
                    var content = string.Empty;
                    if (input.AddNewLine)
                        content = "\n";
                    content += input.Content;
                    client.AppendAllText(input.Path, content, encoding);
                    break;
                case WriteOperation.Overwrite:
                    if (client.Exists(input.Path))
                        client.DeleteFile(input.Path);
                    client.WriteAllText(input.Path, input.Content, encoding);
                    break;
                case WriteOperation.Error:
                    if (client.Exists(input.Path))
                        throw new ArgumentException($"File already exists: {input.Path}");
                    client.WriteAllText(input.Path, input.Content, encoding);
                    break;
                default:
                    throw new ArgumentException($"Unknown WriteBehaviour type: '{input.WriteBehaviour}'.");
            }

            if (options.VerifyWrite)
            {
                return new Result(client.Get(input.Path));
            }
            else
            {
                // If skipping verification, calculate size locally so the Result.SizeInMegaBytes isn't empty
                string payload;
                if (input.WriteBehaviour == WriteOperation.Append)
                    payload = input.AddNewLine ? "\n" + input.Content : input.Content;
                else
                    payload = input.Content;

                var bytes = encoding.GetByteCount(payload);
                if (input.WriteBehaviour != WriteOperation.Append && input.EnableBom)
                    bytes += encoding.GetPreamble().Length;

                return new Result(input.Path, bytes);
            }
        }
        finally
        {
            client.Disconnect();
            client.Dispose();
        }
    }
}
