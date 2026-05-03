using Xunit;

namespace CloudPasswordManager.Crypto.U.Tests.When_aad_field_is_modified;

public class Then_Decrypt_throws
{
    [Fact(Skip = "not implemented — requires M1 crypto implementation")]
    public async Task _Run()
    {
        // Arrange: encrypt a valid vault, then change vault_version in the Aad string
        // Act: call Decrypt with the modified envelope
        // Assert: throws CryptographicException — AAD mismatch must fail authentication
        await Task.CompletedTask;
    }
}