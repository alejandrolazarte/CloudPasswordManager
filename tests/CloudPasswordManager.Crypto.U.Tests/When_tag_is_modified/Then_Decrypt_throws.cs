using Xunit;

namespace CloudPasswordManager.Crypto.U.Tests.When_tag_is_modified;

public class Then_Decrypt_throws
{
    [Fact(Skip = "not implemented — requires M1 crypto implementation")]
    public async Task _Run()
    {
        // Arrange: encrypt a valid vault, then flip one byte in Tag
        // Act: call Decrypt
        // Assert: throws CryptographicException
        await Task.CompletedTask;
    }
}