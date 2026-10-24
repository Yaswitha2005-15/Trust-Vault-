using System.Net;
using System.Text.Json;
using TrustVault.Api.Data;
using Xunit;

namespace TrustVault.Tests;

[Collection("api")]
public class AuthTests
{
    private readonly TrustVaultFixture _fx;
    public AuthTests(TrustVaultFixture fx) => _fx = fx;

    private const string OwnerEmail = "owner@trustvault.local";

    [Fact]
    public async Task Login_without_csrf_token_is_rejected()
    {
        var client = _fx.CreateClient();
        var response = await ApiClient.PostJsonAsync(client, "/api/auth/login",
            new { email = OwnerEmail, password = TrustVaultFixture.DemoPassword }, csrf: null);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Login_with_wrong_password_returns_401()
    {
        var client = _fx.CreateClient();
        var response = await ApiClient.LoginAsync(client, OwnerEmail, "wrong-password-123");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Unknown_email_gets_the_same_answer_as_wrong_password()
    {
        var client = _fx.CreateClient();
        var wrongPassword = await ApiClient.LoginAsync(client, OwnerEmail, "wrong-password-123");
        var unknownUser = await ApiClient.LoginAsync(client, "nobody@trustvault.local", "wrong-password-123");

        Assert.Equal(wrongPassword.StatusCode, unknownUser.StatusCode);
        Assert.Equal(await Title(wrongPassword), await Title(unknownUser));
    }

    [Fact]
    public async Task Me_without_login_returns_401()
    {
        var client = _fx.CreateClient();
        var response = await client.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Login_succeeds_and_me_returns_the_identity()
    {
        var client = _fx.CreateClient();
        var login = await ApiClient.LoginAsync(client, OwnerEmail, TrustVaultFixture.DemoPassword);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);

        var me = await client.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        Assert.Contains(OwnerEmail, await me.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Logout_with_a_token_from_before_login_is_rejected()
    {
        var client = _fx.CreateClient();
        var oldToken = await ApiClient.GetCsrfAsync(client);
        var login = await ApiClient.PostJsonAsync(client, "/api/auth/login",
            new { email = OwnerEmail, password = TrustVaultFixture.DemoPassword }, oldToken);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);

        var logout = await ApiClient.PostJsonAsync(client, "/api/auth/logout", null, oldToken);
        Assert.Equal(HttpStatusCode.BadRequest, logout.StatusCode);
    }

    [Fact]
    public async Task Logout_with_a_fresh_token_ends_the_session()
    {
        var client = _fx.CreateClient();
        await ApiClient.LoginAsync(client, OwnerEmail, TrustVaultFixture.DemoPassword);

        var freshToken = await ApiClient.GetCsrfAsync(client);
        var logout = await ApiClient.PostJsonAsync(client, "/api/auth/logout", null, freshToken);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        var me = await client.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
    }

    [Fact]
    public async Task Account_locks_after_five_wrong_passwords_even_for_the_right_password()
    {
        var email = $"lockout-{Guid.NewGuid():N}@test.local";
        await _fx.CreateUserAsync(email, Roles.Viewer);
        var client = _fx.CreateClient();

        for (var i = 0; i < 5; i++)
        {
            var bad = await ApiClient.LoginAsync(client, email, "wrong-password-123");
            Assert.Equal(HttpStatusCode.Unauthorized, bad.StatusCode);
        }

        var good = await ApiClient.LoginAsync(client, email, TrustVaultFixture.DemoPassword);
        Assert.Equal(HttpStatusCode.Unauthorized, good.StatusCode);
    }

    private static async Task<string?> Title(HttpResponseMessage response)
    {
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("title").GetString();
    }
}