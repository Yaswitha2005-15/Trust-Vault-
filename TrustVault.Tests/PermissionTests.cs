using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using TrustVault.Api.Data;
using Xunit;

namespace TrustVault.Tests;

[Collection("api")]
public class PermissionTests
{
    private readonly TrustVaultFixture _fx;
    public PermissionTests(TrustVaultFixture fx) => _fx = fx;

    private static readonly byte[] PdfBytes = Encoding.ASCII.GetBytes("%PDF-1.4\nTrustVault permission test\n");

    private async Task<(HttpClient Client, string Csrf)> SignInAsync(string email)
    {
        var client = _fx.CreateClient();
        var login = await ApiClient.LoginAsync(client, email, TrustVaultFixture.DemoPassword);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var csrf = await ApiClient.GetCsrfAsync(client);
        return (client, csrf);
    }

    private async Task<(HttpClient Client, string Csrf, AppUser User)> NewUserAsync(string role)
    {
        var email = $"{role.ToLowerInvariant()}-{Guid.NewGuid():N}@test.local";
        var user = await _fx.CreateUserAsync(email, role);
        var (client, csrf) = await SignInAsync(email);
        return (client, csrf, user);
    }

    private static async Task<Guid> UploadOkAsync(HttpClient client, string csrf)
    {
        var form = new MultipartFormDataContent();
        var file = new ByteArrayContent(PdfBytes);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/pdf");
        form.Add(file, "file", "permissions.pdf");
        form.Add(new StringContent("Permission test"), "title");

        var request = new HttpRequestMessage(HttpMethod.Post, "/api/documents") { Content = form };
        request.Headers.Add("X-XSRF-TOKEN", csrf);
        var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("id").GetGuid();
    }

    private static async Task<HttpResponseMessage> GrantAsync(HttpClient client, string csrf, Guid docId, string email, string level)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, $"/api/documents/{docId}/permissions")
        {
            Content = JsonContent.Create(new { userEmail = email, level })
        };
        request.Headers.Add("X-XSRF-TOKEN", csrf);
        return await client.SendAsync(request);
    }

    private static async Task<HttpResponseMessage> RevokeAsync(HttpClient client, string csrf, Guid docId, Guid userId)
    {
        var request = new HttpRequestMessage(HttpMethod.Delete, $"/api/documents/{docId}/permissions/{userId}");
        request.Headers.Add("X-XSRF-TOKEN", csrf);
        return await client.SendAsync(request);
    }

    private static async Task<List<JsonElement>> GetAuditAsync(HttpClient client)
    {
        var response = await client.GetAsync("/api/audit");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.EnumerateArray().Select(e => e.Clone()).ToList();
    }

    private static bool IsDoc(JsonElement e, Guid id) =>
        e.GetProperty("documentId").ValueKind == JsonValueKind.String && e.GetProperty("documentId").GetGuid() == id;

    [Fact]
    public async Task Owner_can_grant_and_revoke_through_the_api()
    {
        var (owner, ownerCsrf, _) = await NewUserAsync(Roles.Owner);
        var id = await UploadOkAsync(owner, ownerCsrf);
        var (reader, _, readerUser) = await NewUserAsync(Roles.Viewer);

        Assert.Equal(HttpStatusCode.NotFound, (await reader.GetAsync($"/api/documents/{id}/content")).StatusCode);

        var grant = await GrantAsync(owner, ownerCsrf, id, readerUser.Email!, "Read");
        Assert.Equal(HttpStatusCode.OK, grant.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync($"/api/documents/{id}/content")).StatusCode);

        var revoke = await RevokeAsync(owner, ownerCsrf, id, readerUser.Id);
        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await reader.GetAsync($"/api/documents/{id}/content")).StatusCode);
    }

    [Fact]
    public async Task Only_the_owner_can_manage_permissions()
    {
        var (owner, ownerCsrf, _) = await NewUserAsync(Roles.Owner);
        var id = await UploadOkAsync(owner, ownerCsrf);
        var (editor, editorCsrf, editorUser) = await NewUserAsync(Roles.Viewer);
        var (reader, readerCsrf, readerUser) = await NewUserAsync(Roles.Viewer);
        var (stranger, strangerCsrf, _) = await NewUserAsync(Roles.Viewer);
        var (third, _, thirdUser) = await NewUserAsync(Roles.Viewer);

        Assert.Equal(HttpStatusCode.OK, (await GrantAsync(owner, ownerCsrf, id, editorUser.Email!, "Edit")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await GrantAsync(owner, ownerCsrf, id, readerUser.Email!, "Read")).StatusCode);

        // Someone who can see the document but is not the owner: 403.
        Assert.Equal(HttpStatusCode.Forbidden, (await GrantAsync(editor, editorCsrf, id, thirdUser.Email!, "Read")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await RevokeAsync(reader, readerCsrf, id, editorUser.Id)).StatusCode);

        // Someone who cannot see the document at all: 404.
        Assert.Equal(HttpStatusCode.NotFound, (await GrantAsync(stranger, strangerCsrf, id, thirdUser.Email!, "Read")).StatusCode);

        // And the third user really did not get access.
        Assert.Equal(HttpStatusCode.NotFound, (await third.GetAsync($"/api/documents/{id}/content")).StatusCode);
    }

    [Fact]
    public async Task Administrator_cannot_grant_access_to_someone_elses_document()
    {
        var (owner, ownerCsrf, _) = await NewUserAsync(Roles.Owner);
        var id = await UploadOkAsync(owner, ownerCsrf);
        var (_, _, targetUser) = await NewUserAsync(Roles.Viewer);
        var (admin, adminCsrf) = await SignInAsync("admin@trustvault.local");

        Assert.Equal(HttpStatusCode.NotFound, (await GrantAsync(admin, adminCsrf, id, targetUser.Email!, "Read")).StatusCode);
    }

    [Fact]
    public async Task Grants_revokes_and_denied_attempts_are_audited()
    {
        var (owner, ownerCsrf, _) = await NewUserAsync(Roles.Owner);
        var id = await UploadOkAsync(owner, ownerCsrf);
        var (_, _, readerUser) = await NewUserAsync(Roles.Viewer);
        var (stranger, strangerCsrf, _) = await NewUserAsync(Roles.Viewer);

        await GrantAsync(owner, ownerCsrf, id, readerUser.Email!, "Read");
        await RevokeAsync(owner, ownerCsrf, id, readerUser.Id);
        await GrantAsync(stranger, strangerCsrf, id, readerUser.Email!, "Read");

        var (admin, _) = await SignInAsync("admin@trustvault.local");
        var events = await GetAuditAsync(admin);

        Assert.Contains(events, e => IsDoc(e, id)
            && e.GetProperty("action").GetString()!.StartsWith("permission.grant")
            && e.GetProperty("outcome").GetString() == "Success");
        Assert.Contains(events, e => IsDoc(e, id)
            && e.GetProperty("action").GetString()!.StartsWith("permission.revoke")
            && e.GetProperty("outcome").GetString() == "Success");
        Assert.Contains(events, e => IsDoc(e, id)
            && e.GetProperty("action").GetString()!.StartsWith("permission.grant")
            && e.GetProperty("outcome").GetString() == "Denied"
            && e.GetProperty("denyReason").GetString() == "no_grant");
    }

    [Fact]
    public async Task Unknown_user_or_invalid_level_is_rejected()
    {
        var (owner, ownerCsrf, _) = await NewUserAsync(Roles.Owner);
        var id = await UploadOkAsync(owner, ownerCsrf);
        var (_, _, readerUser) = await NewUserAsync(Roles.Viewer);

        Assert.Equal(HttpStatusCode.BadRequest,
            (await GrantAsync(owner, ownerCsrf, id, $"nobody-{Guid.NewGuid():N}@test.local", "Read")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest,
            (await GrantAsync(owner, ownerCsrf, id, readerUser.Email!, "Admin")).StatusCode);
    }
}