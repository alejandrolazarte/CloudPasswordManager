namespace CloudPasswordManager.Crypto.Models;

/// <summary>
/// Fields authenticated as AAD in every AES-256-GCM encryption.
/// Serialized as canonical JSON (UTF-8, lexicographic key order, no whitespace).
/// Any modification to these fields causes decryption to fail.
/// </summary>
public sealed record AadFields(
    int FormatVersion,
    Guid AccountId,
    Guid VaultId,
    long VaultVersion,
    ulong EncryptionCounter,
    string Algorithm,
    string Kdf,
    string KdfParamsId);