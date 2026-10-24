using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using TrustVault.Api.Data;
using Xunit;

namespace TrustVault.Tests;

[Collection("api")]
public class DocumentManagementTests
{
    private readonly TrustVaultFixture _fx;
    public DocumentManagementTests(TrustVaultFixture fx) => _fx = fx;

    private static readonly byte[] Pdf = Encoding.ASCII.GetBytes("%PDF-1.4\nTrustVault management test\n");

    private async Task<(HttpClient Client, string Csrf)> SignInAsync(string email)
    {
        var client = _fx.CreateClient();
        var login = await ApiClient.LoginAsync(client, email, TrustVaultFixture.DemoPassword);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        // A CSRF token issued before login is useless afterwards, so fetch a fresh one.
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

    private static Task<HttpResponseMessage> SendAsync(HttpClient client, HttpMethod method, string url, string? csrf, object? body = null)
    {
        var request = new HttpRequestMessage(method, url);
        if (body is not null) request.Content = JsonContent.Create(body);
        if (csrf is not null) request.Headers.Add("X-XSRF-TOKEN", csrf);
        return client.SendAsync(request);
    }

    private static async Task<Guid> UploadAsync(HttpClient client, string csrf, string title, string? category = null)
    {
        var form = new MultipartFormDataContent();
        var file = new ByteArrayContent(Pdf);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/pdf");
        form.Add(file, "file", "doc.pdf");
        form.Add(new StringContent(title), "title");
        if (category is not null) form.Add(new StringContent(category), "category");

        var request = new HttpRequestMessage(HttpMethod.Post, "/api/documents") { Content = form };
        request.Headers.Add("X-XSRF-TOKEN", csrf);
        var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("id").GetGuid();
    }

    private static async Task GrantAsync(HttpClient owner, string csrf, Guid documentId, string email, string level)
    {
        var response = await ApiClient.PostJsonAsync(owner, $"/api/documents/{documentId}/permissions",
            new { userEmail = email, level }, csrf);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private static async Task<List<Guid>> SearchIdsAsync(HttpClient client, string queryString)
    {
        var response = await client.GetAsync("/api/documents" + queryString);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.EnumerateArray().Select(e => e.GetProperty("id").GetGuid()).ToList();
    }

    private static string Title() => $"Contract {Guid.NewGuid():N}";

    // ---------- edit ----------

    [Fact]
    public async Task Edit_needs_an_edit_grant()
    {
        var (owner, ownerCsrf, _) = await NewUserAsync(Roles.Owner);
        var (reader, readerCsrf, readerUser) = await NewUserAsync(Roles.Viewer);
        var (editor, editorCsrf, editorUser) = await NewUserAsync(Roles.Viewer);
        var (stranger, strangerCsrf, _) = await NewUserAsync(Roles.Viewer);

        var id = await UploadAsync(owner, ownerCsrf, Title());
        await GrantAsync(owner, ownerCsrf, id, readerUser.Email!, "Read");
        await GrantAsync(owner, ownerCsrf, id, editorUser.Email!, "Edit");

        var body = new { title = "Edited title", category = "Finance" };

        Assert.Equal(HttpStatusCode.Forbidden, (await SendAsync(reader, HttpMethod.Put, $"/api/documents/{id}", readerCsrf, body)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await SendAsync(stranger, HttpMethod.Put, $"/api/documents/{id}", strangerCsrf, body)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(editor, HttpMethod.Put, $"/api/documents/{id}", editorCsrf, body)).StatusCode);

        var after = await owner.GetAsync($"/api/documents/{id}");
        Assert.Contains("Edited title", await after.Content.ReadAsStringAsync());
    }

    // ---------- delete ----------

    [Fact]
    public async Task Delete_by_anyone_but_the_owner_is_refused()
    {
        var (owner, ownerCsrf, _) = await NewUserAsync(Roles.Owner);
        var (editor, editorCsrf, editorUser) = await NewUserAsync(Roles.Viewer);
        var (stranger, strangerCsrf, _) = await NewUserAsync(Roles.Viewer);
        var (admin, adminCsrf) = await SignInAsync("admin@trustvault.local");

        var id = await UploadAsync(owner, ownerCsrf, Title());
        await GrantAsync(owner, ownerCsrf, id, editorUser.Email!, "Edit");

        Assert.Equal(HttpStatusCode.Forbidden, (await SendAsync(editor, HttpMethod.Delete, $"/api/documents/{id}", editorCsrf)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await SendAsync(stranger, HttpMethod.Delete, $"/api/documents/{id}", strangerCsrf)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await SendAsync(admin, HttpMethod.Delete, $"/api/documents/{id}", adminCsrf)).StatusCode);

        // Still there for the owner.
        Assert.Equal(HttpStatusCode.OK, (await owner.GetAsync($"/api/documents/{id}")).StatusCode);
    }

    [Fact]
    public async Task Owner_delete_ends_access_for_everyone()
    {
        var (owner, ownerCsrf, _) = await NewUserAsync(Roles.Owner);
        var (reader, _, readerUser) = await NewUserAsync(Roles.Viewer);

        var id = await UploadAsync(owner, ownerCsrf, Title());
        await GrantAsync(owner, ownerCsrf, id, readerUser.Email!, "Read");
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync($"/api/documents/{id}/content")).StatusCode);

        var delete = await SendAsync(owner, HttpMethod.Delete, $"/api/documents/{id}", ownerCsrf);
        Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);

        Assert.Equal(HttpStatusCode.NotFound, (await reader.GetAsync($"/api/documents/{id}/content")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await reader.GetAsync($"/api/documents/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await owner.GetAsync($"/api/documents/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await owner.GetAsync($"/api/documents/{id}/content")).StatusCode);
    }

    [Fact]
    public async Task Delete_without_csrf_token_is_rejected()
    {
        var (owner, ownerCsrf, _) = await NewUserAsync(Roles.Owner);
        var id = await UploadAsync(owner, ownerCsrf, Title());

        var response = await SendAsync(owner, HttpMethod.Delete, $"/api/documents/{id}", csrf: null);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await owner.GetAsync($"/api/documents/{id}")).StatusCode);
    }

    // ---------- search ----------

    [Fact]
    public async Task Search_finds_own_documents_by_title_category_owner_and_date()
    {
        var (owner, ownerCsrf, ownerUser) = await NewUserAsync(Roles.Owner);
        var title = Title();
        var id = await UploadAsync(owner, ownerCsrf, title, "Legal");
        var q = $"?q={Uri.EscapeDataString(title)}";

        Assert.Contains(id, await SearchIdsAsync(owner, q));
        Assert.Contains(id, await SearchIdsAsync(owner, q + "&category=legal"));
        Assert.DoesNotContain(id, await SearchIdsAsync(owner, q + "&category=other"));
        Assert.Contains(id, await SearchIdsAsync(owner, q + $"&owner={Uri.EscapeDataString(ownerUser.Email!)}"));
        Assert.Contains(id, await SearchIdsAsync(owner, q + "&from=2000-01-01&to=2099-12-31"));
        Assert.DoesNotContain(id, await SearchIdsAsync(owner, q + "&from=2099-01-01"));
    }

    [Fact]
    public async Task Search_never_returns_documents_the_caller_cannot_access()
    {
        var (owner, ownerCsrf, _) = await NewUserAsync(Roles.Owner);
        var (stranger, _, _) = await NewUserAsync(Roles.Viewer);
        var (admin, _) = await SignInAsync("admin@trustvault.local");

        var title = Title();
        var id = await UploadAsync(owner, ownerCsrf, title);

        // Neither a targeted search nor an unfiltered list may reveal it.
        Assert.DoesNotContain(id, await SearchIdsAsync(stranger, $"?q={Uri.EscapeDataString(title)}"));
        Assert.DoesNotContain(id, await SearchIdsAsync(stranger, ""));
        Assert.DoesNotContain(id, await SearchIdsAsync(admin, $"?q={Uri.EscapeDataString(title)}"));
        Assert.DoesNotContain(id, await SearchIdsAsync(admin, ""));
    }

    [Fact]
    public async Task Search_follows_grants_and_revocation()
    {
        var (owner, ownerCsrf, _) = await NewUserAsync(Roles.Owner);
        var (reader, _, readerUser) = await NewUserAsync(Roles.Viewer);

        var title = Title();
        var id = await UploadAsync(owner, ownerCsrf, title);
        var q = $"?q={Uri.EscapeDataString(title)}";

        Assert.DoesNotContain(id, await SearchIdsAsync(reader, q));

        await GrantAsync(owner, ownerCsrf, id, readerUser.Email!, "Read");
        Assert.Contains(id, await SearchIdsAsync(reader, q));

        var revoke = await SendAsync(owner, HttpMethod.Delete, $"/api/documents/{id}/permissions/{readerUser.Id}", ownerCsrf);
        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        Assert.DoesNotContain(id, await SearchIdsAsync(reader, q));
    }

    [Fact]
    public async Task Search_with_an_injection_string_is_harmless()
    {
        var (owner, ownerCsrf, _) = await NewUserAsync(Roles.Owner);
        var (stranger, _, _) = await NewUserAsync(Roles.Viewer);
        var id = await UploadAsync(owner, ownerCsrf, Title());

        var attack = Uri.EscapeDataString("' OR '1'='1' --");
        var ids = await SearchIdsAsync(stranger, $"?q={attack}");
        Assert.DoesNotContain(id, ids);

        var attack2 = Uri.EscapeDataString("%");
        Assert.DoesNotContain(id, await SearchIdsAsync(stranger, $"?q={attack2}"));
    }

    // ---------- admin ----------

    [Fact]
    public async Task Admin_deactivation_kills_an_existing_session()
    {
        var (viewer, _, viewerUser) = await NewUserAsync(Roles.Viewer);
        Assert.Equal(HttpStatusCode.OK, (await viewer.GetAsync("/api/auth/me")).StatusCode);

        var (admin, adminCsrf) = await SignInAsync("admin@trustvault.local");
        var deactivate = await SendAsync(admin, HttpMethod.Post, $"/api/admin/users/{viewerUser.Id}/deactivate", adminCsrf);
        Assert.Equal(HttpStatusCode.NoContent, deactivate.StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await viewer.GetAsync("/api/auth/me")).StatusCode);

        var relogin = await ApiClient.LoginAsync(_fx.CreateClient(), viewerUser.Email!, TrustVaultFixture.DemoPassword);
        Assert.Equal(HttpStatusCode.Unauthorized, relogin.StatusCode);
    }

    [Fact]
    public async Task Non_admin_cannot_use_admin_endpoints()
    {
        var (owner, ownerCsrf, _) = await NewUserAsync(Roles.Owner);

        Assert.Equal(HttpStatusCode.Forbidden, (await owner.GetAsync("/api/admin/users")).StatusCode);

        var create = await SendAsync(owner, HttpMethod.Post, "/api/admin/users", ownerCsrf,
            new { email = $"x-{Guid.NewGuid():N}@test.local", password = TrustVaultFixture.DemoPassword, role = "Viewer" });
        Assert.Equal(HttpStatusCode.Forbidden, create.StatusCode);
    }

    [Fact]
    public async Task Admin_cannot_deactivate_an_administrator()
    {
        var (admin, adminCsrf) = await SignInAsync("admin@trustvault.local");

        var list = await admin.GetAsync("/api/admin/users");
        Assert.Equal(HttpStatusCode.OK, list.StatusCode);
        using var json = JsonDocument.Parse(await list.Content.ReadAsStringAsync());
        var adminId = json.RootElement.EnumerateArray()
            .First(u => u.GetProperty("email").GetString() == "admin@trustvault.local")
            .GetProperty("id").GetGuid();

        var response = await SendAsync(admin, HttpMethod.Post, $"/api/admin/users/{adminId}/deactivate", adminCsrf);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync("/api/auth/me")).StatusCode);
    }

    [Fact]
    public async Task Admin_created_user_can_log_in_but_cannot_be_made_an_administrator()
    {
        var (admin, adminCsrf) = await SignInAsync("admin@trustvault.local");
        var email = $"created-{Guid.NewGuid():N}@test.local";

        var asAdmin = await SendAsync(admin, HttpMethod.Post, "/api/admin/users", adminCsrf,
            new { email, password = TrustVaultFixture.DemoPassword, role = "Administrator" });
        Assert.Equal(HttpStatusCode.BadRequest, asAdmin.StatusCode);

        var created = await SendAsync(admin, HttpMethod.Post, "/api/admin/users", adminCsrf,
            new { email, password = TrustVaultFixture.DemoPassword, role = "Viewer" });
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);

        var login = await ApiClient.LoginAsync(_fx.CreateClient(), email, TrustVaultFixture.DemoPassword);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
    }
}