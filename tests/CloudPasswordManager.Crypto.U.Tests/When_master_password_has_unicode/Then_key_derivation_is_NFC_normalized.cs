using Xunit;

namespace CloudPasswordManager.Crypto.U.Tests.When_master_password_has_unicode;

public class Then_key_derivation_is_NFC_normalized
{
    [Fact(Skip = "not implemented — requires M1 crypto implementation")]
    public async Task _Run()
    {
        // Arrange: two strings that are canonically equivalent under Unicode NFC
        //   e.g. "café" (precomposed) and "café" (decomposed + combining accent)
        // Act: DeriveUnlockKey with each string (implementation must NFC-normalize before Argon2id)
        // Assert: both produce identical UnlockKey.Value
        // Why: iOS and Android may produce different representations of the same password,
        //      which would make the vault unrecoverable across platforms without normalization.
        await Task.CompletedTask;
    }
}