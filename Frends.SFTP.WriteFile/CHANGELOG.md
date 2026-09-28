# Changelog

## [Unreleased]
### Added
- Added `VerifyWrite` option to allow skipping post-write verification (useful when the SFTP user does not have read permissions).
- Added `Result.Verified` property to indicate whether verification was performed.

### Changed
- [Breaking] Renamed `Result.Path` to `Result.RemotePath` for clarity. Update existing code to use `result.RemotePath` instead of `result.Path`.
- [Breaking] `HostKeyAlgorithm` `DSS` is no longer supported, because SSH.NET dropped DSA. Selecting it now throws an `ArgumentException`.
- A server fingerprint mismatch now throws `SshConnectionException` with the message "Host key could not be verified." instead of "Key exchange negotiation failed.".

### Updated
- Updated SSH.NET to version 2026.0.0 to fix security advisories GHSA-mggc-4xg6-vcxf and GHSA-q939-rpr3-3284.
- Added an explicit Microsoft.Bcl.AsyncInterfaces dependency, which SSH.NET needs at runtime on net6.0.

## [2.5.0] - 2025-10-15
### Added
- Added new Options class with CreateDestinationDirectories property to enable automatic target directory creation 

## [2.4.0] - 2025-01-13
### Fixed
- Fixed issue with ConnectionInfoBuilder having static properties for connection and input paramaters which lead to Task not being thread safe.

## [2.3.0] - 2024-08-19
### Updated
- Updated Renci.SshNet library to version 2024.1.0.

## [2.2.0] - 2024-01-03
### Updated
- [Breaking] Updated dependency SSH.NET to the newest version 2023.0.0.

### Changed
- Changed connection info builder to create the connection info as it's done in DownloadFiles.
- [Breaking] Changed PrivateKeyFilePassphrase parameter to PrivateKeyPassphrase and enabled it when PrivateKeyString was used.

## [2.0.1] - 2022-12-01
### Updated
- Updated dependency Microsoft.Extensions.DependencyInjection to the newest version.

## [2.0.0] - 2022-11-10
### Changed
- [Breaking] Added parameters for keyboard-interactive authentication and add new line when appending.
- Fixed overwrite deleting the original file before writing the new file.
- Added keyboard-interactive authentication method.
- Added more tests e.g. Serverfingerprint tests
- Added System.Text.CodePages NuGet to the project
- Added ConnectionInfoBuilder
- Added HostKeyAlgorithm enum

## [1.0.1] - 2022-06-14
### Changed
- Changed the main method to write from stream to a file.
- Updated tests
- Updated Renci.SshNet library

## [1.0.0] - 2022-03-10
### Added
- Initial implementation
