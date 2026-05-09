using System.Security.Cryptography;
using System.Text.Json;
using CloudPasswordManager.Crypto;
using CloudPasswordManager.Crypto.Models;
using Shouldly;
using Xunit;

namespace CloudPasswordManager.Crypto.U.Tests.When_vault_is_encrypted_and_decrypted;

public class Then_plaintext_matches_original
{
    [Fact]
    public void _Run()
    {
        VaultCryptoService.ResetCounterState();

        var service = new VaultCryptoService();
        var masterPassword = "correct horse battery staple";
        var secretKey = RandomNumberGenerator.GetBytes(32);
        var accountSalt = RandomNumberGenerator.GetBytes(32);
        var accountId = Guid.NewGuid();

        var entries = new List<VaultEntry>
        {
            new(
                Guid.NewGuid(),
                "example.com",
                "user@example.com",
                "s3cret!",
                "https://example.com/login",
                "My main account",
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow)
        };

        var original = new PlainVault(1, Guid.NewGuid(), 1, entries);

        var key = service.DeriveUnlockKey(masterPassword, secretKey, accountSalt);
        var envelope = service.Encrypt(original, key, accountId, accountSalt);
        var decrypted = service.Decrypt(envelope, key);

        decrypted.SchemaVersion.ShouldBe(original.SchemaVersion);
        decrypted.VaultId.ShouldBe(original.VaultId);
        decrypted.Version.ShouldBe(original.Version);
        decrypted.Entries.Count.ShouldBe(original.Entries.Count);
        decrypted.Entries[0].Id.ShouldBe(original.Entries[0].Id);
        decrypted.Entries[0].Title.ShouldBe(original.Entries[0].Title);
        decrypted.Entries[0].Username.ShouldBe(original.Entries[0].Username);
        decrypted.Entries[0].Password.ShouldBe(original.Entries[0].Password);
        decrypted.Entries[0].Url.ShouldBe(original.Entries[0].Url);
        decrypted.Entries[0].Notes.ShouldBe(original.Entries[0].Notes);
    }
}
