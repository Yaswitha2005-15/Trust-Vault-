using System.Net;
using TrustVault.Api.Data;
using Xunit;

namespace TrustVault.Tests;

[Collection("api")]
public class SessionTests
{
    private readonly TrustVaultFixture _fx;
    public SessionTests(TrustVaultFixture fx) => _fx = fx;

    [Fact]
    public async Task Deactivated_user_loses_an_already_issued_session_immediately()
    {
        var email = $"deactivate-{Guid.NewGuid():N}@test.local";
        var user = await _fx.CreateUserAsync(email, Roles.Viewer);
        var client = _fx.CreateClient();

        var login = await ApiClient.LoginAsync(client, email, TrustVaultFixture.DemoPassword);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/auth/me")).StatusCode);

        await _fx.SetActiveAsync(user.Id, false);

        var me = await client.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
    }
}