using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using TrustVault.Api.Data;
using Xunit;


namespace TrustVault.Tests;

[Collection("api")]
public class AuditTests
{
    private readonly TrustVaultFixture _fx;
    public AuditTests(TrustVaultFixture fx) => _fx = fx;

    private static readonly byte[] PdfBytes = Encoding.ASCII.GetBytes("%PDF-1.4\nTrustVault audit test\n");

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

    private static async Task<HttpResponseMessage> UploadAsync(HttpClient client, string csrf)
    {
        var form = new MultipartFormDataContent();
        var file = new ByteArrayContent(PdfBytes);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/pdf");
        form.Add(file, "file", "audit.pdf");
        form.Add(new StringContent("Audit test"), "title");

        var request = new HttpRequestMessage(HttpMethod.Post, "/api/documents") { Content = form };
        request.Headers.Add("X-XSRF-TOKEN", csrf);
        return await client.SendAsync(request);
    }

    private static async Task<Guid> UploadOkAsync(HttpClient client, string csrf)
    {
        var response = await UploadAsync(client, csrf);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("id").GetGuid();
    }

    private static async Task<List<JsonElement>> GetAuditAsync(HttpClient client)
    {
        var response = await client.GetAsync("/api/audit");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.EnumerateArray().Select(e => e.Clone()).ToList();
    }

    private static async Task<JsonElement> VerifyAsync(HttpClient admin)
    {
        var response = await admin.GetAsync("/api/audit/verify");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.Clone();
    }

    private static bool IsDoc(JsonElement e, Guid id) =>
        e.GetProperty("documentId").ValueKind == JsonValueKind.String && e.GetProperty("documentId").GetGuid() == id;

    private static bool IsActor(JsonElement e, Guid id) =>
        e.GetProperty("actorUserId").ValueKind == JsonValueKind.String && e.GetProperty("actorUserId").GetGuid() == id;

    [Fact]
    public async Task Successful_upload_and_download_are_audited()
    {
        var (owner, csrf, ownerUser) = await NewUserAsync(Roles.Owner);
        var id = await UploadOkAsync(owner, csrf);
        Assert.Equal(HttpStatusCode.OK, (await owner.GetAsync($"/api/documents/{id}/content")).StatusCode);

        var (admin, _) = await SignInAsync("admin@trustvault.local");
        var events = await GetAuditAsync(admin);

        Assert.Contains(events, e => IsDoc(e, id) && IsActor(e, ownerUser.Id)
            && e.GetProperty("action").GetString() == "document.upload"
            && e.GetProperty("outcome").GetString() == "Success");
        Assert.Contains(events, e => IsDoc(e, id) && IsActor(e, ownerUser.Id)
            && e.GetProperty("action").GetString() == "document.download"
            && e.GetProperty("outcome").GetString() == "Success");
    }

    
    [Fact]    
    public async Task Denied_request_audit_row_carries_the_response_correlation_id()
    {
        var (owner, csrf, _) = await NewUserAsync(Roles.Owner);
        var id = await UploadOkAsync(owner, csrf);
        var (stranger, _, strangerUser) = await NewUserAsync(Roles.Viewer);

        var denied = await stranger.GetAsync($"/api/documents/{id}/content");
        Assert.Equal(HttpStatusCode.NotFound, denied.StatusCode);
        var correlationId = denied.Headers.GetValues("X-Correlation-Id").Single();

        var (admin, _) = await SignInAsync("admin@trustvault.local");
        var events = await GetAuditAsync(admin);

        Assert.Contains(events, e => IsDoc(e, id) && IsActor(e, strangerUser.Id)
            && e.GetProperty("outcome").GetString() == "Denied"
            && e.GetProperty("correlationId").GetString() == correlationId);

        Assert.True((await VerifyAsync(admin)).GetProperty("valid").GetBoolean());
    }
    [Fact]
    public async Task Denied_download_is_audited_with_the_real_reason()
    {
        var (owner, csrf, _) = await NewUserAsync(Roles.Owner);
        var id = await UploadOkAsync(owner, csrf);
        var (stranger, _, strangerUser) = await NewUserAsync(Roles.Viewer);

        Assert.Equal(HttpStatusCode.NotFound, (await stranger.GetAsync($"/api/documents/{id}/content")).StatusCode);

        var (admin, _) = await SignInAsync("admin@trustvault.local");
        var events = await GetAuditAsync(admin);

        Assert.Contains(events, e => IsDoc(e, id) && IsActor(e, strangerUser.Id)
            && e.GetProperty("action").GetString() == "document.download"
            && e.GetProperty("outcome").GetString() == "Denied"
            && e.GetProperty("denyReason").GetString() == "no_grant");
    }

    [Fact]
    public async Task Upload_by_a_viewer_is_denied_and_audited()
    {
        var (viewer, csrf, viewerUser) = await NewUserAsync(Roles.Viewer);
        Assert.Equal(HttpStatusCode.Forbidden, (await UploadAsync(viewer, csrf)).StatusCode);

        var (admin, _) = await SignInAsync("admin@trustvault.local");
        var events = await GetAuditAsync(admin);

        Assert.Contains(events, e => IsActor(e, viewerUser.Id)
            && e.GetProperty("action").GetString() == "document.upload"
            && e.GetProperty("outcome").GetString() == "Denied"
            && e.GetProperty("denyReason").GetString() == "role_not_allowed");
    }

    [Fact]
    public async Task Verify_reports_an_intact_chain()
    {
        var (owner, csrf, _) = await NewUserAsync(Roles.Owner);
        await UploadOkAsync(owner, csrf);

        var (admin, _) = await SignInAsync("admin@trustvault.local");
        var result = await VerifyAsync(admin);

        Assert.True(result.GetProperty("valid").GetBoolean());
        Assert.True(result.GetProperty("eventCount").GetInt32() > 0);
    }

    [Fact]
    public async Task Tampering_with_an_audit_row_is_detected()
    {
        var (owner, csrf, _) = await NewUserAsync(Roles.Owner);
        var docId = await UploadOkAsync(owner, csrf);

        var (admin, _) = await SignInAsync("admin@trustvault.local");
        var events = await GetAuditAsync(admin);
        var target = events.First(e => IsDoc(e, docId) && e.GetProperty("action").GetString() == "document.upload");
        var eventId = target.GetProperty("id").GetInt64();

        Assert.True((await VerifyAsync(admin)).GetProperty("valid").GetBoolean());

        await _fx.ExecuteSqlAsync($"UPDATE \"AuditEvents\" SET \"Outcome\" = 'Denied' WHERE \"Id\" = {eventId}");
        try
        {
            var tampered = await VerifyAsync(admin);
            Assert.False(tampered.GetProperty("valid").GetBoolean());
            Assert.Equal(eventId, tampered.GetProperty("firstBrokenEventId").GetInt64());
        }
        finally
        {
            // Restore the row so other tests that share this database still see a valid chain.
            await _fx.ExecuteSqlAsync($"UPDATE \"AuditEvents\" SET \"Outcome\" = 'Success' WHERE \"Id\" = {eventId}");
        }

        Assert.True((await VerifyAsync(admin)).GetProperty("valid").GetBoolean());
    }

    [Fact]
    public async Task Owner_sees_only_audit_events_for_their_own_documents()
    {
        var (ownerA, csrfA, _) = await NewUserAsync(Roles.Owner);
        var (ownerB, csrfB, _) = await NewUserAsync(Roles.Owner);
        var docA = await UploadOkAsync(ownerA, csrfA);
        var docB = await UploadOkAsync(ownerB, csrfB);

        var eventsA = await GetAuditAsync(ownerA);

        Assert.Contains(eventsA, e => IsDoc(e, docA));
        Assert.DoesNotContain(eventsA, e => IsDoc(e, docB));
    }

    [Fact]
    public async Task Viewer_cannot_read_the_audit_log_or_verify_it()
    {
        var (viewer, _, _) = await NewUserAsync(Roles.Viewer);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.GetAsync("/api/audit")).StatusCode);

        var (owner, _, _) = await NewUserAsync(Roles.Owner);
        Assert.Equal(HttpStatusCode.Forbidden, (await owner.GetAsync("/api/audit/verify")).StatusCode);
    }
}