namespace CloudPasswordManager.Crypto.Models;

/// <summary>A single credential entry inside the plain vault.</summary>
public sealed record VaultEntry(
    Guid Id,
    string Title,
    string Username,
    string Password,
    string Url,
    string Notes,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);