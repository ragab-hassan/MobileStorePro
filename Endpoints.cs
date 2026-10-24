using Dapper;
using MobileStorePro;
using BC = BCrypt.Net.BCrypt; // ✅ الحل الجذري لمشكلة تعارض أسماء BCrypt

public static class Endpoints
{
    private static Dictionary<string, object?> ToDict(IDictionary<string, object> row) =>
        row.ToDictionary(kv => kv.Key, kv => kv.Value is DBNull ? null : (object?)kv.Value);

    // ================= AUTH =================
    public static void MapAuthEndpoints(this WebApplication app)
    {
        app.MapPost("/api/auth/login", async (HttpContext ctx, Db db, LoginRequest req) =>
        {
            var username = (req.username ?? "").Trim();
            var password = req.password ?? "";
            if (username == "" || password == "")
                return Results.Json(new { success = false, message = "أدخل اسم المستخدم وكلمة المرور" });

            using var conn = db.Open();
            var user = await conn.QuerySingleOrDefaultAsync<UserRow>(
                "SELECT * FROM users WHERE username=@u AND is_active=1 LIMIT 1", new { u = username });

            if (user == null || !BC.Verify(password, user.password_hash))
                return Results.Json(new { success = false, message = "بيانات الدخول غير صحيحة" }, statusCode: 401);

            if (user.role != "superadmin")
            {
                var sub = await conn.QuerySingleOrDefaultAsync<SubscriptionRow>(
                    "SELECT * FROM subscriptions WHERE store_id=@s ORDER BY id DESC LIMIT 1",
                    new { s = user.store_id });
                if (sub == null || sub.is_active != 1 || sub.expiry_date.Date < DateTime.Today)
                    return Results.Json(new { success = false, message = "انتهى اشتراك المتجر" }, statusCode: 403);
            }

            Auth.SetUser(ctx, user);
            return Results.Json(new { success = true, user });
        });

        app.MapPost("/api/auth/logout", (HttpContext ctx) =>
        {
            ctx.Session.Clear();
            return Results.Json(new { success = true });
        });

        app.MapGet("/api/auth/me", (HttpContext ctx) =>
        {
            var user = Auth.GetUser(ctx);
            if (user == null)
                return Results.Json(new { success = false, message = "غير مصرح" }, statusCode: 401);
            return Results.Json(new { success = true, user });
        });
    }

    // ================= STORES =================
    public static void MapStoresEndpoints(this WebApplication app)
    {
        app.MapGet("/api/stores/list", async (HttpContext ctx, Db db) =>
        {
            if (Auth.RequireRole(ctx, out _, "superadmin") is IResult r) return r;
            using var conn = db.Open();
            var rows = await conn.QueryAsync(@"
                SELECT s.id, s.store_name, s.phone, s.address,
                       u.username, u.name AS owner_name,
                       sub.plan, sub.expiry_date, sub.is_active
                FROM stores s
                LEFT JOIN users u ON u.store_id=s.id AND u.role='storeowner'
                LEFT JOIN subscriptions sub ON sub.store_id=s.id
                ORDER BY s.id DESC");
            var list = new List<Dictionary<string, object?>>();
            foreach (IDictionary<string, object> row in rows) list.Add(ToDict(row));
            return Results.Json(new { success = true, stores = list });
        });

        app.MapPost("/api/stores/add", async (HttpContext ctx, Db db, StoreAddRequest req) =>
        {
            if (Auth.RequireRole(ctx, out _, "superadmin") is IResult r) return r;
            var storeName = (req.store_name ?? "").Trim();
            var ownerName = (req.owner_name ?? "").Trim();
            var phone = (req.phone ?? "").Trim();
            var address = (req.address ?? "").Trim();
            var username = (req.username ?? "").Trim();
            var password = req.password ?? "";
            var plan = req.plan ?? "trial";

            if (storeName == "" || username == "" || password == "")
                return Results.Json(new { success = false, message = "أكمل البيانات المطلوبة" });

            using var conn = db.Open();
            var exists = await conn.QuerySingleOrDefaultAsync<int?>(
                "SELECT id FROM users WHERE username=@u", new { u = username });
            if (exists != null)
                return Results.Json(new { success = false, message = "اسم المستخدم موجود بالفعل" });

            int days = plan switch { "monthly" => 30, "yearly" => 365, "unlimited" => 36500, _ => 7 };

            using var tx = conn.BeginTransaction();
            try
            {
                var storeId = await conn.ExecuteScalarAsync<long>(
                    "INSERT INTO stores (store_name, owner_name, phone, address) VALUES (@a,@b,@c,@d); SELECT LAST_INSERT_ID();",
                    new { a = storeName, b = ownerName, c = phone, d = address }, tx);
                await conn.ExecuteAsync(
                    "INSERT INTO users (store_id, username, password_hash, role, name, is_active) VALUES (@s,@u,@p,'storeowner',@n,1)",
                    new { s = storeId, u = username, p = BC.HashPassword(password), n = ownerName != "" ? ownerName : storeName }, tx);
                await conn.ExecuteAsync(
                    "INSERT INTO subscriptions (store_id, plan, expiry_date, is_active) VALUES (@s,@p,@e,1)",
                    new { s = storeId, p = plan, e = DateTime.Today.AddDays(days) }, tx);
                tx.Commit();
                return Results.Json(new { success = true, message = "تم إضافة المتجر" });
            }
            catch (Exception ex) { tx.Rollback(); return Results.Json(new { success = false, message = ex.Message }); }
        });

        app.MapPost("/api/stores/update", async (HttpContext ctx, Db db, StoreUpdateRequest req) =>
        {
            if (Auth.RequireRole(ctx, out _, "superadmin") is IResult r) return r;
            var storeId = req.store_id;
            var storeName = (req.store_name ?? "").Trim();
            var ownerName = (req.owner_name ?? "").Trim();
            var phone = (req.phone ?? "").Trim();
            var address = (req.address ?? "").Trim();
            var username = (req.username ?? "").Trim();
            var password = req.password ?? "";
            var plan = req.plan ?? "trial";
            DateTime? expiry = DateTime.TryParse(req.expiry_date, out var p) ? p : null;
            var active = req.is_active;

            if (storeId == 0 || storeName == "" || username == "")
                return Results.Json(new { success = false, message = "أكمل البيانات المطلوبة" });

            using var conn = db.Open();
            var exists = await conn.QuerySingleOrDefaultAsync<int?>(
                "SELECT id FROM users WHERE username=@u AND store_id<>@s",
                new { u = username, s = storeId });
            if (exists != null)
                return Results.Json(new { success = false, message = "اسم المستخدم مستخدم بالفعل" });
            if (password != "" && password.Length < 4)
                return Results.Json(new { success = false, message = "كلمة المرور قصيرة" });

            using var tx = conn.BeginTransaction();
            try
            {
                await conn.ExecuteAsync(
                    "UPDATE stores SET store_name=@a, owner_name=@b, phone=@c, address=@d WHERE id=@s",
                    new { a = storeName, b = ownerName, c = phone, d = address, s = storeId }, tx);

                if (password != "")
                    await conn.ExecuteAsync(
                        "UPDATE users SET username=@u, password_hash=@p WHERE store_id=@s AND role='storeowner'",
                        new { u = username, p = BC.HashPassword(password), s = storeId }, tx);
                else
                    await conn.ExecuteAsync(
                        "UPDATE users SET username=@u WHERE store_id=@s AND role='storeowner'",
                        new { u = username, s = storeId }, tx);

                var subId = await conn.QuerySingleOrDefaultAsync<int?>(
                    "SELECT id FROM subscriptions WHERE store_id=@s", new { s = storeId }, tx);
                var ev = expiry ?? DateTime.Today;
                if (subId != null)
                    await conn.ExecuteAsync(
                        "UPDATE subscriptions SET plan=@p, expiry_date=@e, is_active=@a WHERE store_id=@s",
                        new { p = plan, e = ev, a = active ? 1 : 0, s = storeId }, tx);
                else
                    await conn.ExecuteAsync(
                        "INSERT INTO subscriptions (store_id, plan, expiry_date, is_active) VALUES (@s,@p,@e,@a)",
                        new { s = storeId, p = plan, e = ev, a = active ? 1 : 0 }, tx);

                tx.Commit();
                return Results.Json(new { success = true, message = "تم تحديث المتجر" });
            }
            catch (Exception ex) { tx.Rollback(); return Results.Json(new { success = false, message = ex.Message }); }
        });

        app.MapPost("/api/stores/delete", async (HttpContext ctx, Db db, StoreDeleteRequest req) =>
        {
            if (Auth.RequireRole(ctx, out _, "superadmin") is IResult r) return r;
            using var conn = db.Open();
            await conn.ExecuteAsync("DELETE FROM stores WHERE id=@s", new { s = req.store_id });
            return Results.Json(new { success = true, message = "تم حذف المتجر" });
        });
    }

    // ================= PRODUCTS =================
    public static void MapProductsEndpoints(this WebApplication app)
    {
        app.MapGet("/api/products/list", async (HttpContext ctx, Db db) =>
        {
            if (Auth.RequireStore(ctx, out var user) is IResult r) return r;
            using var conn = db.Open();
            var rows = await conn.QueryAsync(
                "SELECT * FROM products WHERE store_id=@s ORDER BY id DESC",
                new { s = user!.store_id });
            var list = new List<Dictionary<string, object?>>();
            foreach (IDictionary<string, object> row in rows) list.Add(ToDict(row));
            return Results.Json(new { success = true, products = list });
        });

        app.MapPost("/api/products/add", async (HttpContext ctx, Db db, ProductsAddRequest req) =>
        {
            if (Auth.RequireStore(ctx, out var user) is IResult r) return r;
            var products = req.products ?? new();
            if (products.Count == 0)
                return Results.Json(new { success = false, message = "لا توجد منتجات" });

            using var conn = db.Open();
            using var tx = conn.BeginTransaction();
            try
            {
                int added = 0;
                foreach (var p in products)
                {
                    var name = (p.name ?? "").Trim();
                    if (name == "") continue;
                    if (p.price <= 0) throw new Exception("أدخل سعر بيع صحيح لكل منتج");
                    var barcode = (p.barcode ?? "").Trim();
                    if (barcode == "") barcode = Random.Shared.Next(1000, 9999).ToString();
                    await conn.ExecuteAsync(
                        "INSERT INTO products (store_id,name,category,cost,price,stock,barcode,imei) VALUES (@s,@n,@c,@co,@p,@st,@b,@i)",
                        new { s = user!.store_id, n = name, c = p.category ?? "أخرى", co = p.cost, p = p.price, st = p.stock, b = barcode, i = (p.imei ?? "").Trim() }, tx);
                    added++;
                }
                if (added == 0) throw new Exception("أدخل اسم منتج واحد على الأقل");
                tx.Commit();
                return Results.Json(new { success = true, message = $"تم إضافة {added} منتج" });
            }
            catch (Exception ex) { tx.Rollback(); return Results.Json(new { success = false, message = ex.Message }); }
        });

        app.MapPost("/api/products/delete", async (HttpContext ctx, Db db, IdRequest req) =>
        {
            if (Auth.RequireStore(ctx, out var user) is IResult r) return r;
            using var conn = db.Open();
            await conn.ExecuteAsync(
                "DELETE FROM products WHERE id=@id AND store_id=@s",
                new { id = req.id, s = user!.store_id });
            return Results.Json(new { success = true, message = "تم حذف المنتج" });
        });
    }

    // ================= INVOICES =================
    public static void MapInvoicesEndpoints(this WebApplication app)
    {
        app.MapGet("/api/invoices/list", async (HttpContext ctx, Db db) =>
        {
            if (Auth.RequireStore(ctx, out var user) is IResult r) return r;
            using var conn = db.Open();
            var invoices = (await conn.QueryAsync(
                "SELECT * FROM invoices WHERE store_id=@s ORDER BY id DESC",
                new { s = user!.store_id })).ToList();

            var result = new List<Dictionary<string, object?>>();
            foreach (IDictionary<string, object> inv in invoices)
            {
                var d = ToDict(inv);
                var invoiceId = Convert.ToInt32(d["id"]);
                var items = await conn.QueryAsync(
                    "SELECT * FROM invoice_items WHERE invoice_id=@i", new { i = invoiceId });
                var itemList = new List<Dictionary<string, object?>>();
                foreach (IDictionary<string, object> it in items) itemList.Add(ToDict(it));
                d["items"] = itemList;
                result.Add(d);
            }
            return Results.Json(new { success = true, invoices = result });
        });

        app.MapPost("/api/invoices/create", async (HttpContext ctx, Db db, InvoiceCreateRequest req) =>
        {
            if (Auth.RequireStore(ctx, out var user) is IResult r) return r;
            var items = req.items ?? new();
            if (items.Count == 0)
                return Results.Json(new { success = false, message = "السلة فارغة" });

            using var conn = db.Open();
            using var tx = conn.BeginTransaction();
            try
            {
                decimal total = 0;
                var checkedItems = new List<(int productId, string productName, decimal price, int qty, decimal line)>();

                foreach (var item in items)
                {
                    if (item.qty <= 0) throw new Exception("الكمية غير صحيحة");
                    var product = await conn.QuerySingleOrDefaultAsync(
                        "SELECT * FROM products WHERE id=@id AND store_id=@s FOR UPDATE",
                        new { id = item.id, s = user!.store_id }, tx) as IDictionary<string, object>;
                    if (product == null) throw new Exception("منتج غير موجود");

                    var stock = Convert.ToInt32(product["stock"]);
                    if (stock < item.qty) throw new Exception($"الكمية غير متوفرة: {product["name"]}");
                    var price = Convert.ToDecimal(product["price"]);
                    var line = price * item.qty;
                    total += line;
                    checkedItems.Add((Convert.ToInt32(product["id"]), product["name"]?.ToString() ?? "", price, item.qty, line));
                }

                var invoiceNo = "INV-" + Random.Shared.Next(100000, 999999);
                var invoiceId = await conn.ExecuteScalarAsync<long>(
                    "INSERT INTO invoices (store_id,invoice_no,customer_name,customer_phone,total,seller_user_id) VALUES (@s,@no,@cn,@cp,@t,@u); SELECT LAST_INSERT_ID();",
                    new
                    {
                        s = user!.store_id,
                        no = invoiceNo,
                        cn = (req.customer_name ?? "").Trim(),
                        cp = (req.customer_phone ?? "").Trim(),
                        t = total,
                        u = user.id
                    }, tx);

                foreach (var c in checkedItems)
                {
                    await conn.ExecuteAsync(
                        "INSERT INTO invoice_items (invoice_id,product_id,product_name,unit_price,quantity,line_total) VALUES (@iv,@p,@n,@pr,@q,@lt)",
                        new { iv = invoiceId, p = c.productId, n = c.productName, pr = c.price, q = c.qty, lt = c.line }, tx);
                    await conn.ExecuteAsync(
                        "UPDATE products SET stock=stock-@q WHERE id=@p",
                        new { q = c.qty, p = c.productId }, tx);
                }

                tx.Commit();
                return Results.Json(new { success = true, message = "تم إنشاء الفاتورة", invoice_no = invoiceNo });
            }
            catch (Exception ex) { tx.Rollback(); return Results.Json(new { success = false, message = ex.Message }); }
        });

        app.MapPost("/api/invoices/return", async (HttpContext ctx, Db db, InvoiceReturnRequest req) =>
        {
            if (Auth.RequireStore(ctx, out var user) is IResult r) return r;
            using var conn = db.Open();
            using var tx = conn.BeginTransaction();
            try
            {
                var inv = await conn.QuerySingleOrDefaultAsync<int?>(
                    "SELECT id FROM invoices WHERE id=@i AND store_id=@s",
                    new { i = req.invoice_id, s = user!.store_id }, tx);
                if (inv == null) throw new Exception("الفاتورة غير موجودة");

                var items = await conn.QueryAsync(
                    "SELECT product_id, quantity FROM invoice_items WHERE invoice_id=@i",
                    new { i = req.invoice_id }, tx);
                foreach (var item in items)
                {
                    int productId = Convert.ToInt32(item.product_id);
                    int qty = Convert.ToInt32(item.quantity);
                    await conn.ExecuteAsync(
                        "UPDATE products SET stock=stock+@q WHERE id=@p",
                        new { q = qty, p = productId }, tx);
                }
                await conn.ExecuteAsync("DELETE FROM invoice_items WHERE invoice_id=@i", new { i = req.invoice_id }, tx);
                await conn.ExecuteAsync("DELETE FROM invoices WHERE id=@i", new { i = req.invoice_id }, tx);
                tx.Commit();
                return Results.Json(new { success = true, message = "تم إرجاع الفاتورة" });
            }
            catch (Exception ex) { tx.Rollback(); return Results.Json(new { success = false, message = ex.Message }); }
        });
    }

    // ================= REPAIRS =================
    public static void MapRepairsEndpoints(this WebApplication app)
    {
        app.MapGet("/api/repairs/list", async (HttpContext ctx, Db db) =>
        {
            if (Auth.RequireStore(ctx, out var user) is IResult r) return r;
            using var conn = db.Open();
            var rows = await conn.QueryAsync(
                "SELECT * FROM repairs WHERE store_id=@s ORDER BY id DESC",
                new { s = user!.store_id });
            var list = new List<Dictionary<string, object?>>();
            foreach (IDictionary<string, object> row in rows) list.Add(ToDict(row));
            return Results.Json(new { success = true, repairs = list });
        });

        app.MapPost("/api/repairs/add", async (HttpContext ctx, Db db, RepairAddRequest req) =>
        {
            if (Auth.RequireStore(ctx, out var user) is IResult r) return r;
            var customer = (req.customer_name ?? "").Trim();
            var device = (req.device ?? "").Trim();
            if (customer == "" || device == "")
                return Results.Json(new { success = false, message = "أكمل البيانات" });
            using var conn = db.Open();
            await conn.ExecuteAsync(
                "INSERT INTO repairs (store_id,customer_name,customer_phone,device,issue) VALUES (@s,@c,@p,@d,@i)",
                new { s = user!.store_id, c = customer, p = (req.customer_phone ?? "").Trim(), d = device, i = (req.issue ?? "").Trim() });
            return Results.Json(new { success = true, message = "تم إضافة طلب الصيانة" });
        });

        app.MapPost("/api/repairs/advance", async (HttpContext ctx, Db db, IdRequest req) =>
        {
            if (Auth.RequireStore(ctx, out var user) is IResult r) return r;
            using var conn = db.Open();
            var status = await conn.QuerySingleOrDefaultAsync<string>(
                "SELECT status FROM repairs WHERE id=@id AND store_id=@s",
                new { id = req.id, s = user!.store_id });
            if (status == null)
                return Results.Json(new { success = false, message = "الطلب غير موجود" });
            var steps = new[] { "received", "in_progress", "repaired", "delivered" };
            var idx = Array.IndexOf(steps, status);
            var next = steps[Math.Min(idx + 1, 3)];
            await conn.ExecuteAsync("UPDATE repairs SET status=@st WHERE id=@id", new { st = next, id = req.id });
            return Results.Json(new { success = true, message = "تم تحديث الحالة" });
        });
    }

    // ================= SETTINGS =================
    public static void MapSettingsEndpoints(this WebApplication app)
    {
        app.MapGet("/api/settings/get", async (HttpContext ctx, Db db) =>
        {
            if (Auth.RequireStore(ctx, out var user) is IResult r) return r;
            using var conn = db.Open();
            var store = await conn.QuerySingleOrDefaultAsync(
                "SELECT * FROM stores WHERE id=@s", new { s = user!.store_id }) as IDictionary<string, object>;
            return Results.Json(new { success = true, store = store == null ? null : ToDict(store) });
        });

        app.MapPost("/api/settings/save", async (HttpContext ctx, Db db, SettingsSaveRequest req) =>
        {
            if (Auth.RequireStore(ctx, out var user) is IResult r) return r;
            var storeName = (req.store_name ?? "").Trim();
            if (storeName == "")
                return Results.Json(new { success = false, message = "اسم المتجر مطلوب" });
            using var conn = db.Open();
            await conn.ExecuteAsync(
                "UPDATE stores SET store_name=@n, phone=@p, address=@a WHERE id=@s",
                new { n = storeName, p = (req.phone ?? "").Trim(), a = (req.address ?? "").Trim(), s = user!.store_id });
            return Results.Json(new { success = true, message = "تم حفظ الإعدادات" });
        });
    }

    // ================= STAFF =================
    public static void MapStaffEndpoints(this WebApplication app)
    {
        app.MapGet("/api/staff/list", async (HttpContext ctx, Db db) =>
        {
            if (Auth.RequireStore(ctx, out var user) is IResult r) return r;
            using var conn = db.Open();
            var rows = await conn.QueryAsync(
                "SELECT id,name,username,role,is_active FROM users WHERE store_id=@s AND role IN ('cashier','technician') ORDER BY id DESC",
                new { s = user!.store_id });
            var list = new List<Dictionary<string, object?>>();
            foreach (IDictionary<string, object> row in rows) list.Add(ToDict(row));
            return Results.Json(new { success = true, staff = list });
        });

        app.MapPost("/api/staff/add", async (HttpContext ctx, Db db, StaffAddRequest req) =>
        {
            if (Auth.RequireStore(ctx, out var user) is IResult r) return r;
            var name = (req.name ?? "").Trim();
            var username = (req.username ?? "").Trim();
            var password = req.password ?? "";
            var role = req.role ?? "cashier";
            if (name == "" || username == "" || password == "")
                return Results.Json(new { success = false, message = "أكمل البيانات" });
            if (role != "cashier" && role != "technician")
                return Results.Json(new { success = false, message = "وظيفة غير صحيحة" });
            if (password.Length < 4)
                return Results.Json(new { success = false, message = "كلمة المرور قصيرة" });

            using var conn = db.Open();
            var exists = await conn.QuerySingleOrDefaultAsync<int?>(
                "SELECT id FROM users WHERE username=@u", new { u = username });
            if (exists != null)
                return Results.Json(new { success = false, message = "اسم المستخدم موجود" });

            await conn.ExecuteAsync(
                "INSERT INTO users (store_id,username,password_hash,role,name,is_active) VALUES (@s,@u,@p,@r,@n,1)",
                new { s = user!.store_id, u = username, p = BC.HashPassword(password), r = role, n = name });
            return Results.Json(new { success = true, message = "تم إضافة المستخدم" });
        });

        app.MapPost("/api/staff/toggle", async (HttpContext ctx, Db db, IdRequest req) =>
        {
            if (Auth.RequireStore(ctx, out var user) is IResult r) return r;
            using var conn = db.Open();
            await conn.ExecuteAsync(
                "UPDATE users SET is_active=1-is_active WHERE id=@id AND store_id=@s AND role IN ('cashier','technician')",
                new { id = req.id, s = user!.store_id });
            return Results.Json(new { success = true, message = "تم تحديث الحالة" });
        });

        app.MapPost("/api/staff/reset_password", async (HttpContext ctx, Db db, StaffResetRequest req) =>
        {
            if (Auth.RequireStore(ctx, out var user) is IResult r) return r;
            var password = req.password ?? "";
            if (password.Length < 4)
                return Results.Json(new { success = false, message = "كلمة المرور قصيرة" });
            using var conn = db.Open();
            await conn.ExecuteAsync(
                "UPDATE users SET password_hash=@p WHERE id=@id AND store_id=@s AND role IN ('cashier','technician')",
                new { p = BC.HashPassword(password), id = req.id, s = user!.store_id });
            return Results.Json(new { success = true, message = "تم تغيير كلمة المرور" });
        });

        app.MapPost("/api/staff/delete", async (HttpContext ctx, Db db, IdRequest req) =>
        {
            if (Auth.RequireStore(ctx, out var user) is IResult r) return r;
            using var conn = db.Open();
            await conn.ExecuteAsync(
                "DELETE FROM users WHERE id=@id AND store_id=@s AND role IN ('cashier','technician')",
                new { id = req.id, s = user!.store_id });
            return Results.Json(new { success = true, message = "تم حذف المستخدم" });
        });
    }
}