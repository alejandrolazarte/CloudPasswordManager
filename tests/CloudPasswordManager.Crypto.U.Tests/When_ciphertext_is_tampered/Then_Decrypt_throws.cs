using Xunit;

namespace CloudPasswordManager.Crypto.U.Tests.When_ciphertext_is_tampered;

public class Then_Decrypt_throws
{
    [Fact(Skip = "not implemented — requires M1 crypto implementation")]
    public async Task _Run()
    {
        // Arrange: encrypt a valid vault, then flip one byte in Ciphertext
        // Act: call Decrypt with the tampered envelope
        // Assert: throws CryptographicException (or derived type)
        await Task.CompletedTask;
    }
}