using Xunit;

namespace CloudPasswordManager.Crypto.U.Tests.When_key_derivation_input_changes;

public class Then_derived_key_is_different
{
    [Fact(Skip = "not implemented — requires M1 crypto implementation")]
    public async Task _Run()
    {
        // Arrange: derive key with original inputs, then with each input changed individually:
        //   - different masterPassword
        //   - different secretKey
        //   - different accountSalt
        // Assert: every variation produces a key different from the original
        await Task.CompletedTask;
    }
}