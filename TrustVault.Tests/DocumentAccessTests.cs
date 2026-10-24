using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using TrustVault.Api.Data;
using TrustVault.Api.Documents;
using Xunit;

namespace TrustVault.Tests;

[Collection("api")]
public class DocumentAccessTests
{
    private readonly TrustVaultFixture _fx;
    public DocumentAccessTests(TrustVaultFixture fx) => _fx = fx;

    private static readonly byte[] PdfBytes = Encoding.ASCII.GetBytes("%PDF-1.4\nTrustVault secret contents\n");

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

    private static async Task<HttpResponseMessage> UploadAsync(HttpClient client, string csrf, string fileName, byte[] bytes, string title = "Test document")
    {
        var form = new MultipartFormDataContent();
        var file = new ByteArrayContent(bytes);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/pdf");
        form.Add(file, "file", fileName);
        form.Add(new StringContent(title), "title");

        var request = new HttpRequestMessage(HttpMethod.Post, "/api/documents") { Content = form };
        request.Headers.Add("X-XSRF-TOKEN", csrf);
        return await client.SendAsync(request);
    }

    private static async Task<Guid> UploadOkAsync(HttpClient client, string csrf)
    {
        var response = await UploadAsync(client, csrf, "secret.pdf", PdfBytes);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("id").GetGuid();
    }

    [Fact]
    public async Task Owner_can_upload_and_download_their_own_document()
    {
        var (owner, csrf, _) = await NewUserAsync(Roles.Owner);
        var id = await UploadOkAsync(owner, csrf);

        var download = await owner.GetAsync($"/api/documents/{id}/content");
        Assert.Equal(HttpStatusCode.OK, download.StatusCode);
        Assert.Equal(PdfBytes, await download.Content.ReadAsByteArrayAsync());
        Assert.Equal("attachment", download.Content.Headers.ContentDisposition?.DispositionType);
        Assert.Contains("nosniff", download.Headers.GetValues("X-Content-Type-Options"));
        Assert.Equal("application/octet-stream", download.Content.Headers.ContentType?.MediaType);
        Assert.True(download.Headers.CacheControl?.NoStore == true);
    }

    [Fact]
    public async Task User_without_a_grant_cannot_read_metadata_or_download()
    {
        var (owner, ownerCsrf, _) = await NewUserAsync(Roles.Owner);
        var id = await UploadOkAsync(owner, ownerCsrf);
        var (stranger, _, _) = await NewUserAsync(Roles.Viewer);

        Assert.Equal(HttpStatusCode.NotFound, (await stranger.GetAsync($"/api/documents/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await stranger.GetAsync($"/api/documents/{id}/content")).StatusCode);
    }

    [Fact]
    public async Task Guessed_document_id_gets_the_same_answer_as_an_unauthorised_one()
    {
        var (owner, ownerCsrf, _) = await NewUserAsync(Roles.Owner);
        var realId = await UploadOkAsync(owner, ownerCsrf);
        var (stranger, _, _) = await NewUserAsync(Roles.Viewer);

        var existing = await stranger.GetAsync($"/api/documents/{realId}");
        var guessed = await stranger.GetAsync($"/api/documents/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, existing.StatusCode);
        Assert.Equal(existing.StatusCode, guessed.StatusCode);
    }

    [Fact]
    public async Task User_with_a_read_grant_can_download()
    {
        var (owner, ownerCsrf, ownerUser) = await NewUserAsync(Roles.Owner);
        var id = await UploadOkAsync(owner, ownerCsrf);
        var (reader, _, readerUser) = await NewUserAsync(Roles.Viewer);

        await _fx.GrantAsync(id, readerUser.Id, DocumentLevel.Read, ownerUser.Id);

        var download = await reader.GetAsync($"/api/documents/{id}/content");
        Assert.Equal(HttpStatusCode.OK, download.StatusCode);
        Assert.Equal(PdfBytes, await download.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task Revoked_grant_stops_access_on_the_very_next_request()
    {
        var (owner, ownerCsrf, ownerUser) = await NewUserAsync(Roles.Owner);
        var id = await UploadOkAsync(owner, ownerCsrf);
        var (reader, _, readerUser) = await NewUserAsync(Roles.Viewer);

        await _fx.GrantAsync(id, readerUser.Id, DocumentLevel.Read, ownerUser.Id);
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync($"/api/documents/{id}/content")).StatusCode);

        await _fx.RevokeAsync(id, readerUser.Id);

        Assert.Equal(HttpStatusCode.NotFound, (await reader.GetAsync($"/api/documents/{id}/content")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await reader.GetAsync($"/api/documents/{id}")).StatusCode);
    }

    [Fact]
    public async Task Administrator_cannot_read_or_download_someone_elses_document()
    {
        var (owner, ownerCsrf, _) = await NewUserAsync(Roles.Owner);
        var id = await UploadOkAsync(owner, ownerCsrf);
        var (admin, _) = await SignInAsync("admin@trustvault.local");

        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/api/documents/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/api/documents/{id}/content")).StatusCode);
    }

    [Fact]
    public async Task Viewer_role_cannot_upload()
    {
        var (viewer, csrf, _) = await NewUserAsync(Roles.Viewer);
        var response = await UploadAsync(viewer, csrf, "secret.pdf", PdfBytes);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Executable_disguised_as_pdf_is_rejected()
    {
        var (owner, csrf, _) = await NewUserAsync(Roles.Owner);
        var fakePdf = Encoding.ASCII.GetBytes("MZ-this-is-not-a-pdf-it-is-an-executable");
        var response = await UploadAsync(owner, csrf, "invoice.pdf", fakePdf);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Disallowed_extension_is_rejected()
    {
        var (owner, csrf, _) = await NewUserAsync(Roles.Owner);
        var response = await UploadAsync(owner, csrf, "program.exe", PdfBytes);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Anonymous_request_gets_401()
    {
        var client = _fx.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync($"/api/documents/{Guid.NewGuid()}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync($"/api/documents/{Guid.NewGuid()}/content")).StatusCode);
    }
}