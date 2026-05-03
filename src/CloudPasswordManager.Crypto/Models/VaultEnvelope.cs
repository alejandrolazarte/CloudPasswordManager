namespace CloudPasswordManager.Crypto.Models;

/// <summary>
/// Encrypted vault blob stored on disk or server.
/// The server never decrypts this — it only stores and retrieves it.
/// </summary>
public sealed record VaultEnvelope(
    int FormatVersion,
    Guid AccountId,
    Guid VaultId,
    long VaultVersion,
    ulong EncryptionCounter,
    byte[] NoncePrefix,
    byte[] Nonce,
    byte[] Ciphertext,
    byte[] Tag,
    string Aad,
    string Algorithm,
    string Kdf,
    string KdfParamsId,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);