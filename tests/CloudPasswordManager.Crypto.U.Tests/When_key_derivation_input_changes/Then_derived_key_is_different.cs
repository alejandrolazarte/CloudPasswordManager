using System.Security.Cryptography;
using CloudPasswordManager.Crypto;
using Shouldly;
using Xunit;

namespace CloudPasswordManager.Crypto.U.Tests.When_key_derivation_input_changes;

public class Then_derived_key_is_different
{
    [Fact]
    public void _Run()
    {
        VaultCryptoService.ResetCounterState();

        var service = new VaultCryptoService();
        var masterPassword = "correct horse battery staple";
        var secretKey = RandomNumberGenerator.GetBytes(32);
        var accountSalt = RandomNumberGenerator.GetBytes(32);

        var original = service.DeriveUnlockKey(masterPassword, secretKey, accountSalt);

        var diffPassword = service.DeriveUnlockKey("different password", secretKey, accountSalt);
        var diffSecretKey = service.DeriveUnlockKey(masterPassword, RandomNumberGenerator.GetBytes(32), accountSalt);
        var diffSalt = service.DeriveUnlockKey(masterPassword, secretKey, RandomNumberGenerator.GetBytes(32));

        diffPassword.Value.ShouldNotBe(original.Value);
        diffSecretKey.Value.ShouldNotBe(original.Value);
        diffSalt.Value.ShouldNotBe(original.Value);
    }
}
