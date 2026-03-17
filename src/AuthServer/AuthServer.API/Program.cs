using AuthServer.API;
using PixSmith.Authorization.DataContext;
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

builder.Services.AddInfrastructure(builder.Configuration);


// CORS - allow Blazor client origin
builder.Services.AddCors(options =>
{
	options.AddPolicy("BlazorClient", policy =>
	{
		policy.WithOrigins(
				builder.Configuration["AllowedOrigins:BlazorClient"]
				?? "https://localhost:7200")
			  .AllowAnyHeader()
			  .AllowAnyMethod()
			  .AllowCredentials();
	});
});

// External SSO providers
builder.Services
	.AddAuthentication()
	.AddGoogle(options =>
	{
		options.ClientId = builder.Configuration["Authentication:Google:ClientId"] ?? "google-client-id";
		options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"] ?? "google-client-secret";
		options.CallbackPath = "/signin-google";
		options.SaveTokens = true;
	})
	.AddMicrosoftAccount(options =>
	{
		options.ClientId = builder.Configuration["Authentication:Microsoft:ClientId"] ?? "ms-client-id";
		options.ClientSecret = builder.Configuration["Authentication:Microsoft:ClientSecret"] ?? "ms-client-secret";
		options.CallbackPath = "/signin-microsoft";
		options.SaveTokens = true;
	});

// Controllers + Swagger
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
	c.SwaggerDoc("v1", new() { Title = "AuthServer API", Version = "v1" });
	c.AddSecurityDefinition("Bearer", new()
	{
		Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
		Scheme = "bearer",
		BearerFormat = "JWT",
		Description = "Enter your bearer token"
	});
	c.AddSecurityRequirement(new()
	{
		{
			new() { Reference = new() { Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme, Id = "Bearer" } },
			[]
		}
	});
});

// ─── App Pipeline ─────────────────────────────────────────────────────────────

var app = builder.Build();

// Migrate and seed database on startup
using (var scope = app.Services.CreateScope())
{
	var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
	await db.Database.EnsureCreatedAsync();
}

if (app.Environment.IsDevelopment())
{
	app.UseSwagger();
	app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseSerilogRequestLogging();
app.UseCors("BlazorClient");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
