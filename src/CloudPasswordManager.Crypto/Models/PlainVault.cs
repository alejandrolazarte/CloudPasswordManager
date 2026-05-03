namespace CloudPasswordManager.Crypto.Models;

/// <summary>
/// Decrypted vault content. Lives in RAM only.
/// Never written to disk or sent over the network in plaintext.
/// </summary>
public sealed record PlainVault(
    int SchemaVersion,
    Guid VaultId,
    long Version,
    List<VaultEntry> Entries);