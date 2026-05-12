using System.Security.Cryptography;
using CloudPasswordManager.Crypto;
using Shouldly;
using Xunit;

namespace CloudPasswordManager.Crypto.U.Tests.When_key_derivation_inputs_are_identical;

public class Then_derived_key_is_deterministic
{
    [Fact]
    public void _Run()
    {
        VaultCryptoService.ResetCounterState();

        var service = new VaultCryptoService();
        var masterPassword = "correct horse battery staple";
        var secretKey = RandomNumberGenerator.GetBytes(32);
        var accountSalt = RandomNumberGenerator.GetBytes(32);

        var key1 = service.DeriveUnlockKey(masterPassword, secretKey, accountSalt);
        var key2 = service.DeriveUnlockKey(masterPassword, secretKey, accountSalt);

        key1.Value.ShouldBe(key2.Value);
    }
}
