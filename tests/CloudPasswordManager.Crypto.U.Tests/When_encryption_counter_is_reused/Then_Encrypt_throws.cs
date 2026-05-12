using System.Security.Cryptography;
using CloudPasswordManager.Crypto;
using CloudPasswordManager.Crypto.Models;
using Shouldly;
using Xunit;

namespace CloudPasswordManager.Crypto.U.Tests.When_encryption_counter_is_reused;

public class Then_Encrypt_throws
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

        VaultCryptoService.MarkCounterUsed(key.Value, 0);

        Should.Throw<InvalidOperationException>(() =>
            service.Encrypt(vault, key, accountId, accountSalt));
    }
}
