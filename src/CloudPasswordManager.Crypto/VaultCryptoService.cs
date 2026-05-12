using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CloudPasswordManager.Crypto.Interfaces;
using CloudPasswordManager.Crypto.Models;
using Konscious.Security.Cryptography;

namespace CloudPasswordManager.Crypto;

public sealed class VaultCryptoService : IVaultCryptoService
{
    private const int KeyLength = 32;
    private const int FormatVersion = 1;
    private const string AlgorithmAes256Gcm = "AES-256-GCM";
    private const string KdfArgon2idV1 = "argon2id-v1";

    private readonly INonceCounterStore nonceCounterStore;

    private static readonly byte[] VaultContentKeyInfo =
        Encoding.UTF8.GetBytes("vault_content_key");

    private static readonly JsonSerializerOptions VaultJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    public VaultCryptoService()
        : this(new InMemoryNonceCounterStore())
    {
    }

    public VaultCryptoService(INonceCounterStore nonceCounterStore)
    {
        this.nonceCounterStore = nonceCounterStore;
    }

    public UnlockKey DeriveUnlockKey(string masterPassword, byte[] secretKey, byte[] accountSalt)
    {
        byte[] passwordBytes = NfcNormalizeToUtf8(masterPassword);
        byte[] derivationInput = ConcatenatePasswordSecretKeyAndSalt(passwordBytes, secretKey, accountSalt);
        byte[] rootKey = StretchWithArgon2idUsing64MibAnd3Iterations(derivationInput, accountSalt);
        byte[] contentKey = DeriveVaultContentKeyViaHkdfSha256(rootKey);
        WipeFromMemory(rootKey, passwordBytes, derivationInput);
        return new UnlockKey(contentKey);
    }

    public VaultEnvelope Encrypt(PlainVault vault, UnlockKey key, Guid accountId, byte[] accountSalt)
    {
        NonceReservation nonceReservation = nonceCounterStore.ReserveNext(key.Value, vault.VaultId);
        byte[] nonce = BuildNonceWithDevicePrefixAndCounter(nonceReservation);
        byte[] plaintext = SerializeVaultToUtf8Json(vault);
        string aad = BuildAadWithCanonicalJsonBinding(vault, accountId, nonceReservation.EncryptionCounter);
        (byte[] ciphertext, byte[] tag) = EncryptWithAes256Gcm(key.Value, nonce, plaintext, aad);
        WipeFromMemory(plaintext);
        return PackageEnvelope(vault.VaultId, vault.Version, accountId,
            nonceReservation.EncryptionCounter, nonce, ciphertext, tag, aad);
    }

    public PlainVault Decrypt(VaultEnvelope envelope, UnlockKey key)
    {
        byte[] plaintext = DecryptWithAes256GcmAndThrowIfTampered(key.Value, envelope);
        PlainVault vault = DeserializeVaultFromUtf8Json(plaintext);
        WipeFromMemory(plaintext);
        return vault;
    }

    private static byte[] NfcNormalizeToUtf8(string masterPassword)
    {
        string canonical = masterPassword.Normalize(NormalizationForm.FormC);
        return Encoding.UTF8.GetBytes(canonical);
    }

    private static byte[] ConcatenatePasswordSecretKeyAndSalt(byte[] password, byte[] secretKey, byte[] salt)
    {
        var input = new byte[password.Length + secretKey.Length + salt.Length];
        Buffer.BlockCopy(password, 0, input, 0, password.Length);
        Buffer.BlockCopy(secretKey, 0, input, password.Length, secretKey.Length);
        Buffer.BlockCopy(salt, 0, input, password.Length + secretKey.Length, salt.Length);
        return input;
    }

    private static byte[] StretchWithArgon2idUsing64MibAnd3Iterations(byte[] input, byte[] salt)
    {
        using var argon2 = new Argon2id(input)
        {
            Salt = salt,
            DegreeOfParallelism = 1,
            Iterations = 3,
            MemorySize = 64 * 1024
        };
        return argon2.GetBytes(KeyLength);
    }

    private static byte[] DeriveVaultContentKeyViaHkdfSha256(byte[] rootKey)
    {
        return HKDF.Expand(HashAlgorithmName.SHA256, rootKey, KeyLength, VaultContentKeyInfo);
    }

    private static void WipeFromMemory(params byte[][] arrays)
    {
        foreach (var arr in arrays)
        {
            CryptographicOperations.ZeroMemory(arr);
        }
    }

    private static byte[] BuildNonceWithDevicePrefixAndCounter(NonceReservation reservation)
    {
        return AppendCounterBigEndian(reservation.DeviceNoncePrefix, reservation.EncryptionCounter);
    }

    private static byte[] AppendCounterBigEndian(byte[] prefix, ulong counter)
    {
        if (prefix.Length != 4)
        {
            throw new ArgumentException("AES-GCM nonce prefix must be exactly 4 bytes.", nameof(prefix));
        }

        byte[] nonce = new byte[12];
        Buffer.BlockCopy(prefix, 0, nonce, 0, 4);
        for (int i = 0; i < 8; i++)
        {
            nonce[4 + i] = (byte)(counter >> (56 - i * 8));
        }

        return nonce;
    }

    private static byte[] SerializeVaultToUtf8Json(PlainVault vault)
    {
        string json = JsonSerializer.Serialize(vault, VaultJsonOptions);
        return Encoding.UTF8.GetBytes(json);
    }

    private static PlainVault DeserializeVaultFromUtf8Json(byte[] data)
    {
        string json = Encoding.UTF8.GetString(data);
        return JsonSerializer.Deserialize<PlainVault>(json, VaultJsonOptions)!;
    }

    /// <summary>
    /// Builds the AAD (Additional Authenticated Data) as canonical JSON with lexicographic key order.
    /// Any modification to account_id, vault_version, encryption_counter, etc. will cause decryption
    /// to fail — this binds metadata to the ciphertext and detects rollback/tampering.
    /// </summary>
    private static string BuildAadWithCanonicalJsonBinding(PlainVault vault, Guid accountId, ulong counter)
    {
        var aad = new AadFields(FormatVersion, accountId, vault.VaultId, vault.Version,
            counter, AlgorithmAes256Gcm, KdfArgon2idV1, KdfArgon2idV1);
        return SerializeAadAsCanonicalJson(aad);
    }

    private static string SerializeAadAsCanonicalJson(AadFields aad)
    {
        using var ms = new MemoryStream();
        using var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = false });

        writer.WriteStartObject();
        WriteJsonProperty(writer, "account_id", aad.AccountId);
        WriteJsonProperty(writer, "algorithm", aad.Algorithm);
        WriteJsonProperty(writer, "encryption_counter", aad.EncryptionCounter);
        WriteJsonProperty(writer, "format_version", aad.FormatVersion);
        WriteJsonProperty(writer, "kdf", aad.Kdf);
        WriteJsonProperty(writer, "kdf_params_id", aad.KdfParamsId);
        WriteJsonProperty(writer, "vault_id", aad.VaultId);
        WriteJsonProperty(writer, "vault_version", aad.VaultVersion);
        writer.WriteEndObject();

        writer.Flush();
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    private static (byte[] ciphertext, byte[] tag) EncryptWithAes256Gcm(
        byte[] key, byte[] nonce, byte[] plaintext, string aad)
    {
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        byte[] aadBytes = Encoding.UTF8.GetBytes(aad);
        using var aesGcm = new AesGcm(key, 16);
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, aadBytes);
        WipeFromMemory(aadBytes);
        return (ciphertext, tag);
    }

    private static byte[] DecryptWithAes256GcmAndThrowIfTampered(byte[] key, VaultEnvelope envelope)
    {
        byte[] aadBytes = Encoding.UTF8.GetBytes(envelope.Aad);
        byte[] plaintext = new byte[envelope.Ciphertext.Length];
        using var aesGcm = new AesGcm(key, 16);
        aesGcm.Decrypt(envelope.Nonce, envelope.Ciphertext, envelope.Tag, plaintext, aadBytes);
        WipeFromMemory(aadBytes);
        return plaintext;
    }

    private static VaultEnvelope PackageEnvelope(Guid vaultId, long vaultVersion, Guid accountId,
        ulong counter, byte[] nonce, byte[] ciphertext, byte[] tag, string aad)
    {
        byte[] prefix = nonce[..4];
        var now = DateTimeOffset.UtcNow;
        return new VaultEnvelope(FormatVersion, accountId, vaultId, vaultVersion,
            counter, prefix, nonce, ciphertext, tag, aad,
            AlgorithmAes256Gcm, KdfArgon2idV1, KdfArgon2idV1, now, now);
    }

    private static void WriteJsonProperty(Utf8JsonWriter writer, string name, object value)
    {
        writer.WritePropertyName(name);
        switch (value)
        {
            case int intVal:
                writer.WriteNumberValue(intVal);
                break;
            case long longVal:
                writer.WriteNumberValue(longVal);
                break;
            case ulong ulongVal:
                writer.WriteNumberValue(ulongVal);
                break;
            case Guid guidVal:
                writer.WriteStringValue(guidVal.ToString("D"));
                break;
            case string strVal:
                writer.WriteStringValue(strVal);
                break;
        }
    }

    internal static void ResetCounterState()
    {
        InMemoryNonceCounterStore.Reset();
    }
}
