using SecureRequest.Extensions;

var builder = WebApplication.CreateBuilder(args);

// ── Step 1: Add a distributed cache ───────────────────────────────────────────
//
// Option A: In-memory (development / single-server)
builder.Services.AddDistributedMemoryCache();

// Option B: Redis (recommended for production — load-balancer safe)
// builder.Services.AddStackExchangeRedisCache(o =>
//     o.Configuration = builder.Configuration.GetConnectionString("Redis"));

// ── Step 2: Register SecureRequest ────────────────────────────────────────────
//
// Default setup — reads settings from appsettings.json "SecureRequest" section.
// Uses DistributedCacheKeyStorageProvider (stores RSA key in Redis/memory).
builder.Services
    .AddSecureRequest(builder.Configuration);

//
// For production: swap to a KMS provider using .WithKeyStorage<T>()
//
// ── Azure Key Vault ───────────────────────────────────────────────────────────
// builder.Services.AddAzureClients(b =>
//     b.AddSecretClient(new Uri(builder.Configuration["KeyVault:Uri"]!)));
//
// builder.Services
//     .AddSecureRequest(builder.Configuration)
//     .WithKeyStorage<AzureKeyVaultStorageProvider>();
//
// ── AWS Secrets Manager ───────────────────────────────────────────────────────
// builder.Services.AddAWSService<IAmazonSecretsManager>();
//
// builder.Services
//     .AddSecureRequest(builder.Configuration)
//     .WithKeyStorage<AwsSecretsManagerStorageProvider>();
//
// ── Factory overload (when constructor args needed) ───────────────────────────
// builder.Services
//     .AddSecureRequest(builder.Configuration)
//     .WithKeyStorage(sp => new MyCustomProvider(
//         sp.GetRequiredService<IMyDependency>()));

// ── Step 3: Add your other services ───────────────────────────────────────────
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// ── Step 4: Add SecureRequest middleware ──────────────────────────────────────
// Place BEFORE UseRouting / UseAuthentication / UseAuthorization
// so the body is decrypted before any binding or auth happens.
app.UseSecureRequest();

app.UseAuthentication();
app.UseAuthorization();

// ── Step 5: Map endpoints ─────────────────────────────────────────────────────

// Public key endpoint — clients fetch this once to cache the RSA public key.
// Add "/api/secure/public-key" to ExcludedPaths in appsettings so the middleware
// does not try to decrypt its own response.
app.MapSecureRequestPublicKey();

// Key rotation endpoint — requires authorization (protect it!).
// After rotation clients will get a 422, re-fetch the new public key, and retry automatically.
app.MapSecureRequestKeyRotation(policy: "AdminOnly");  // replace with your policy name

app.MapControllers();

app.Run();
