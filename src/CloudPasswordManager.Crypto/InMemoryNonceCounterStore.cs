using System.Collections.Concurrent;
using System.Security.Cryptography;
using CloudPasswordManager.Crypto.Interfaces;
using CloudPasswordManager.Crypto.Models;

namespace CloudPasswordManager.Crypto;

/// <summary>
/// MVP in-memory nonce coordinator.
/// Guarantees nonce uniqueness only within the current process lifetime.
/// Future implementations should persist counters in SQLite/server-backed state.
/// </summary>
public sealed class InMemoryNonceCounterStore : INonceCounterStore
{
    private static readonly ConcurrentDictionary<string, ulong> NextCounters = new();
    private static readonly ConcurrentDictionary<string, byte[]> DevicePrefixes = new();

    public NonceReservation ReserveNext(byte[] key, Guid vaultId)
    {
        string keyFingerprint = Convert.ToHexString(SHA256.HashData(key));
        string stateKey = $"{vaultId:D}:{keyFingerprint}";

        ulong counter = NextCounters.AddOrUpdate(stateKey, 1, (_, current) => current + 1) - 1;

        byte[] prefix = DevicePrefixes.GetOrAdd(stateKey,
            _ => RandomNumberGenerator.GetBytes(4));

        return new NonceReservation(prefix, counter);
    }

    internal static void Reset()
    {
        NextCounters.Clear();
        DevicePrefixes.Clear();
    }
}