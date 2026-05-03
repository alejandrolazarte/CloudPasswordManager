namespace CloudPasswordManager.Crypto.Models;

/// <summary>
/// 32-byte key derived from master password + secret key via Argon2id + HKDF.
/// Exists in RAM only while the vault is unlocked.
/// </summary>
public sealed record UnlockKey(byte[] Value);