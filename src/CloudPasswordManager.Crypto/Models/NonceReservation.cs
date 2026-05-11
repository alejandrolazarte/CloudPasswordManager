namespace CloudPasswordManager.Crypto.Models;

/// <summary>
/// Reserved nonce material for one AES-GCM encryption.
/// Nonce = DeviceNoncePrefix || EncryptionCounter, 96 bits total.
/// </summary>
public sealed record NonceReservation(
    byte[] DeviceNoncePrefix,
    ulong EncryptionCounter);