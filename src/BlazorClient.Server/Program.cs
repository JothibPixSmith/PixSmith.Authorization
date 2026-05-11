var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(options => options.AddDefaultPolicy(policy => policy
    .WithOrigins("https://localhost:7200")
    .AllowAnyHeader()
    .AllowAnyMethod()
    .AllowCredentials()));

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.Cookie.Name = ".blazor.bff";
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    // SameSite=None + Secure so the cookie is sent on cross-origin fetch from localhost:7200
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.IdleTimeout = TimeSpan.FromHours(1);
});

var authServerUrl = builder.Configuration["AuthServer:BaseUrl"] ?? "https://localhost:7100";

builder.Services.AddHttpClient("AuthServer", client =>
    client.BaseAddress = new Uri(authServerUrl))
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
    {
        // Trust the localhost dev certificate used by AuthServer
        ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) =>
            msg.RequestUri?.Host is "localhost" or "127.0.0.1" ||
            errors == System.Net.Security.SslPolicyErrors.None
    });

builder.Services.AddControllers();

var app = builder.Build();

app.UseCors();
app.UseSession();
app.MapControllers();

app.Run();
