using Xunit;

namespace CloudPasswordManager.Crypto.U.Tests.When_key_derivation_inputs_are_identical;

public class Then_derived_key_is_deterministic
{
    [Fact(Skip = "not implemented — requires M1 crypto implementation")]
    public async Task _Run()
    {
        // Arrange: same masterPassword, secretKey, accountSalt
        // Act: DeriveUnlockKey called twice
        // Assert: both UnlockKey.Value arrays are equal byte-for-byte
        await Task.CompletedTask;
    }
}