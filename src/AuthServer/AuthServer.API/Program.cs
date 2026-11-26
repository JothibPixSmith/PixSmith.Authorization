using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi;
using PixSmith.Authorization.API;
using PixSmith.Authorization.API.Security;
using PixSmith.Authorization.DataContext;
using PixSmith.Authorization.Services;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// ─── Logging ─────────────────────────────────────────────────────────────────

Log.Logger = new LoggerConfiguration()
	.ReadFrom.Configuration(builder.Configuration)
	.Enrich.FromLogContext()
	.WriteTo.Console()
	.CreateLogger();

builder.Host.UseSerilog();

// ─── Services ─────────────────────────────────────────────────────────────────

builder.Services.AddInfrastructure(builder.Configuration, builder.Environment);
builder.Services.AddHostedService<AdminUserSeeder>(); // runs after OpenIddictSeeder (registration order)

// Must be last: the backfill enumerates the users and clients the two seeders above create.
builder.Services.AddHostedService<TenantBackfillSeeder>();


// Controllers + Swagger.
// Views are needed for the server-rendered login page that backs /connect/authorize.
builder.Services.AddControllersWithViews();
builder.Services.AddAuthRateLimiting(builder.Configuration);
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
	c.SwaggerDoc("v1", new() { Title = "AuthServer API", Version = "v1" });
	c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
	{
		Type = SecuritySchemeType.Http,
		Scheme = "bearer",
		BearerFormat = "JWT",
		Description = "Enter your bearer token"
	});
	c.AddSecurityRequirement(document => new OpenApiSecurityRequirement
	{
		[new OpenApiSecuritySchemeReference("Bearer", document)] = new List<string>()
	});
});

// ─── App Pipeline ─────────────────────────────────────────────────────────────

var app = builder.Build();

// Migrate and seed database on startup
using (var scope = app.Services.CreateScope())
{
	var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
	await db.Database.MigrateAsync();
}

if (app.Environment.IsDevelopment())
{
	app.UseSwagger();
	app.UseSwaggerUI();
}

// First, so every later decision (HSTS, OpenIddict's HTTPS requirement, request logging)
// sees the original scheme and client IP — from trusted proxies only.
app.UseForwardedHeaders();

app.UseSecurityHeaders();

if (app.Environment.IsDevelopment())
{
	// Local `dotnet run` listens on both https://localhost:7100 and http://localhost:7101;
	// this sends the http one to https. Production has no plain-HTTP listener to redirect:
	// the reverse proxy owns that, and OpenIddict rejects any non-HTTPS protocol request.
	app.UseHttpsRedirection();
}
else
{
	// Only emitted on HTTPS responses, so it relies on the forwarded scheme above.
	app.UseHsts();
}

app.UseBlazorFrameworkFiles();
app.UseStaticFiles();
app.UseSerilogRequestLogging();

// Explicit UseRouting so the endpoint — and therefore its [EnableRateLimiting] policy — is
// already selected when the limiter runs. Before authentication, so an unauthenticated flood
// is rejected without doing password-hashing work first.
app.UseRouting();
app.UseRateLimiter();

// Before the endpoint: while a device code is pending OpenIddict answers
// authorization_pending from its own pipeline, so ConnectController never sees these polls.
app.UseMiddleware<DevicePollingThrottle>();

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.MapFallbackToFile("index.html");

app.Run();

// Exposed so WebApplicationFactory<Program> in the integration test project can host this app.
public partial class Program { }
