using Xunit;

namespace CloudPasswordManager.Crypto.U.Tests.When_vault_is_encrypted_and_decrypted;

public class Then_plaintext_matches_original
{
    [Fact(Skip = "not implemented — requires M1 crypto implementation")]
    public async Task _Run()
    {
        // Arrange: build a PlainVault with sample entries and derive an UnlockKey
        // Act: Encrypt -> Decrypt
        // Assert: decrypted vault equals original (VaultId, Version, Entries)
        await Task.CompletedTask;
    }
}