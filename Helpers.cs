using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;
using MySqlConnector;

namespace MobileStorePro;

public class Db
{
    private readonly string _cs;
    public Db(IConfiguration cfg) => _cs = cfg.GetConnectionString("Default")
        ?? throw new InvalidOperationException("Missing ConnectionStrings:Default");
    public MySqlConnection Open()
    {
        var c = new MySqlConnection(_cs);
        c.Open();
        return c;
    }
}

public static class Auth
{
    public static UserRow? GetUser(HttpContext ctx) => ctx.Session.GetObject<UserRow>("user");
    public static void SetUser(HttpContext ctx, UserRow u) => ctx.Session.SetObject("user", u);

    public static IResult? RequireLogin(HttpContext ctx, out UserRow? user)
    {
        user = GetUser(ctx);
        if (user == null)
            return Results.Json(new { success = false, message = "غير مصرح" }, statusCode: 401);
        return null;
    }

    public static IResult? RequireStore(HttpContext ctx, out UserRow? user)
    {
        if (RequireLogin(ctx, out user) is IResult r) return r;
        if (user!.store_id == null)
            return Results.Json(new { success = false, message = "لا يوجد متجر مرتبط بالحساب" }, statusCode: 403);
        return null;
    }

    public static IResult? RequireRole(HttpContext ctx, out UserRow? user, params string[] roles)
    {
        if (RequireLogin(ctx, out user) is IResult r) return r;
        if (!roles.Contains(user!.role))
            return Results.Json(new { success = false, message = "صلاحية غير كافية" }, statusCode: 403);
        return null;
    }
}

public static class SessionExt
{
    private static readonly JsonSerializerOptions Opt = new() { PropertyNameCaseInsensitive = true };
    public static T? GetObject<T>(this ISession s, string key)
    {
        var json = s.GetString(key);
        return json == null ? default : JsonSerializer.Deserialize<T>(json, Opt);
    }
    public static void SetObject<T>(this ISession s, string key, T value) =>
        s.SetString(key, JsonSerializer.Serialize(value, Opt));
}

public class DateOnlyConverter : JsonConverter<DateTime>
{
    public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => reader.GetDateTime();
    public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options)
    {
        if (value.TimeOfDay == TimeSpan.Zero)
            writer.WriteStringValue(value.ToString("yyyy-MM-dd"));
        else
            writer.WriteStringValue(value);
    }
}