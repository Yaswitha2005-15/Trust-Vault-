using Xunit;

namespace TrustVault.Tests;

[Collection("api")]
public class SecurityHeadersTests
{
    private readonly TrustVaultFixture _fx;
    public SecurityHeadersTests(TrustVaultFixture fx) => _fx = fx;

    [Fact]
    public async Task Responses_carry_security_headers()
    {
        var client = _fx.CreateClient();
        var response = await client.GetAsync("/api/auth/csrf");

        Assert.Contains("nosniff", response.Headers.GetValues("X-Content-Type-Options"));
        Assert.Contains("no-referrer", response.Headers.GetValues("Referrer-Policy"));
        Assert.Contains("frame-ancestors 'none'", string.Join(";", response.Headers.GetValues("Content-Security-Policy")));
    }
}