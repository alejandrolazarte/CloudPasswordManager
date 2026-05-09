using System.Security.Cryptography;
using CloudPasswordManager.Crypto;
using CloudPasswordManager.Crypto.Models;
using Shouldly;
using Xunit;

namespace CloudPasswordManager.Crypto.U.Tests.When_ciphertext_is_tampered;

public class Then_Decrypt_throws
{
    [Fact]
    public void _Run()
    {
        VaultCryptoService.ResetCounterState();

        var service = new VaultCryptoService();
        var masterPassword = "test password";
        var secretKey = RandomNumberGenerator.GetBytes(32);
        var accountSalt = RandomNumberGenerator.GetBytes(32);
        var accountId = Guid.NewGuid();

        var vault = new PlainVault(1, Guid.NewGuid(), 1, new List<VaultEntry>());
        var key = service.DeriveUnlockKey(masterPassword, secretKey, accountSalt);
        var envelope = service.Encrypt(vault, key, accountId, accountSalt);

        var tamperedCiphertext = (byte[])envelope.Ciphertext.Clone();
        tamperedCiphertext[0] ^= 0xFF;

        var tampered = envelope with { Ciphertext = tamperedCiphertext };

        Should.Throw<AuthenticationTagMismatchException>(() => service.Decrypt(tampered, key));
    }
}
