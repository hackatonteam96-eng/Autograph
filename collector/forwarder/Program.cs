using System.Net.Http.Json;
using System.Text.Json;

// AuthGraph ITDR — send PowerShell snapshot JSON to backend /api/ingest
// Usage: AuthGraphForwarder.exe C:\AuthGraph\out\dc-snapshot.json http://localhost:8000

if (args.Length < 2)
{
    Console.WriteLine("Usage: AuthGraphForwarder <snapshot.json> <api-base-url>");
    Console.WriteLine("Example: AuthGraphForwarder C:\\AuthGraph\\out\\dc-snapshot.json http://192.168.1.10:8000");
    return 1;
}

var filePath = args[0];
var apiBase = args[1].TrimEnd('/');

if (!File.Exists(filePath))
{
    Console.Error.WriteLine($"File not found: {filePath}");
    return 1;
}

var json = await File.ReadAllTextAsync(filePath);
using var doc = JsonDocument.Parse(json);
var payload = doc.RootElement.Clone();

using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
var response = await http.PostAsJsonAsync($"{apiBase}/api/ingest", payload);

var body = await response.Content.ReadAsStringAsync();
Console.WriteLine($"Status: {(int)response.StatusCode}");
Console.WriteLine(body);

return response.IsSuccessStatusCode ? 0 : 1;
