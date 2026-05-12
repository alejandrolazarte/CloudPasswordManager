using System.Security.Cryptography;
using System.Text;
using CloudPasswordManager.Crypto;
using Shouldly;
using Xunit;

namespace CloudPasswordManager.Crypto.U.Tests.When_master_password_has_unicode;

public class Then_key_derivation_is_NFC_normalized
{
    [Fact]
    public void _Run()
    {
        VaultCryptoService.ResetCounterState();

        var service = new VaultCryptoService();
        var secretKey = RandomNumberGenerator.GetBytes(32);
        var accountSalt = RandomNumberGenerator.GetBytes(32);

        // "café" NFC precomposed: e with acute accent is single codepoint U+00E9
        var precomposed = "café";

        // "café" NFD decomposed: e followed by combining acute accent U+0065 U+0301
        var decomposed = "caf\u0065\u0301";

        // Verify they are canonically equivalent
        precomposed.Normalize(NormalizationForm.FormC).ShouldBe(
            decomposed.Normalize(NormalizationForm.FormC));

        var keyPrecomposed = service.DeriveUnlockKey(precomposed, secretKey, accountSalt);
        var keyDecomposed = service.DeriveUnlockKey(decomposed, secretKey, accountSalt);

        keyPrecomposed.Value.ShouldBe(keyDecomposed.Value);
    }
}
