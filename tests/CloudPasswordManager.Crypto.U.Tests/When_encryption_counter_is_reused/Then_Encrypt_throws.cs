using Xunit;

namespace CloudPasswordManager.Crypto.U.Tests.When_encryption_counter_is_reused;

public class Then_Encrypt_throws
{
    [Fact(Skip = "not implemented — requires M1 crypto implementation")]
    public async Task _Run()
    {
        // Arrange: encrypt once, capture the resulting EncryptionCounter
        //          then attempt to encrypt again with a vault that has the same counter
        // Act + Assert: Encrypt must reject counter reuse — nonce uniqueness is mandatory
        // Note: AES-GCM nonce reuse with the same key is catastrophic and must be prevented by the API
        await Task.CompletedTask;
    }
}