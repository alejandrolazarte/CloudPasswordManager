using CloudPasswordManager.Crypto.Models;

namespace CloudPasswordManager.Crypto.Interfaces;

/// <summary>
/// Responsible for guaranteeing nonce uniqueness per vault content key.
/// Implementations may use in-memory state, SQLite, secure storage or remote coordination.
/// </summary>
public interface INonceCounterStore
{
    NonceReservation ReserveNext(byte[] key, Guid vaultId);
}