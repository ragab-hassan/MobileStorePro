using System.Text.Json;
using System.Text.Json.Serialization;
using Dapper;
using Microsoft.Extensions.Logging;
using MobileStorePro;
using BC = BCrypt.Net.BCrypt; // ✅ إضافة اختصار لتجنب تعارض الأسماء

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(o =>
{
    o.IdleTimeout = TimeSpan.FromHours(24);
    o.Cookie.HttpOnly = true;
    o.Cookie.IsEssential = true;
    o.Cookie.SameSite = SameSiteMode.Lax;
});

builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.Converters.Add(new DateOnlyConverter());
    o.SerializerOptions.Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping;
});

builder.Services.AddSingleton<Db>();

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();
app.UseSession();

// ===== Auto-init DB (idempotent) =====
try
{
    using var conn = app.Services.GetRequiredService<Db>().Open();
    foreach (var sql in Schema.Statements) conn.Execute(sql);

    var hasAdmin = conn.QuerySingleOrDefault<int?>("SELECT id FROM users WHERE role='superadmin' LIMIT 1");
    if (hasAdmin == null)
    {
        // ✅ تصحيح: استخدام كائن مجهول لـ Dapper وتصحيح استدعاء BCrypt
        conn.Execute(
            "INSERT INTO users (username, password_hash, role, name, is_active) VALUES ('admin', @p, 'superadmin', 'المدير العام', 1)",
            new { p = BC.HashPassword("Ragab142536") });

        app.Logger.LogInformation("Created default superadmin: admin / Ragab142536");
    }
    app.Logger.LogInformation("DB init OK");
}
catch (Exception ex)
{
    app.Logger.LogError(ex, "DB init failed — check ConnectionStrings:Default in appsettings.json");
}

// ===== Health check =====
app.MapGet("/api/health", async (Db db) =>
{
    try
    {
        using var c = db.Open();
        var tables = (await c.QueryAsync<string>("SHOW TABLES")).ToList();
        return Results.Json(new { success = true, db = "OK", tables });
    }
    catch (Exception ex)
    {
        return Results.Json(new { success = false, db = "FAIL", error = ex.Message }, statusCode: 500);
    }
});

// ===== Endpoints =====
app.MapAuthEndpoints();
app.MapStoresEndpoints();
app.MapProductsEndpoints();
app.MapInvoicesEndpoints();
app.MapRepairsEndpoints();
app.MapSettingsEndpoints();
app.MapStaffEndpoints();

app.Run();

// ✅ تم حذف السطر الزائد internal record NewRecord(object P); من هنا