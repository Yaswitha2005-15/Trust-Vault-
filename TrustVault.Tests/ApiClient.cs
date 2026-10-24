using System.Net.Http.Json;
using System.Text.Json;

namespace TrustVault.Tests;

public static class ApiClient
{
    public static async Task<string> GetCsrfAsync(HttpClient client)
    {
        var response = await client.GetAsync("/api/auth/csrf");
        response.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("token").GetString()!;
    }

    public static Task<HttpResponseMessage> PostJsonAsync(HttpClient client, string url, object? body, string? csrf)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = JsonContent.Create(body ?? new { }) };
        if (csrf is not null) request.Headers.Add("X-XSRF-TOKEN", csrf);
        return client.SendAsync(request);
    }

    public static async Task<HttpResponseMessage> LoginAsync(HttpClient client, string email, string password)
    {
        var csrf = await GetCsrfAsync(client);
        return await PostJsonAsync(client, "/api/auth/login", new { email, password }, csrf);
    }
}