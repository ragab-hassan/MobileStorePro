using System.Text.Json.Serialization;

namespace MobileStorePro;

public class UserRow
{
    public int id { get; set; }
    public int? store_id { get; set; }
    public string username { get; set; } = "";
    [JsonIgnore] public string password_hash { get; set; } = "";
    public string role { get; set; } = "";
    public string? name { get; set; }
    public int is_active { get; set; }
    [JsonIgnore] public DateTime? created_at { get; set; }
}

public class SubscriptionRow
{
    public int id { get; set; }
    public int store_id { get; set; }
    public string plan { get; set; } = "";
    public DateTime expiry_date { get; set; }
    public int is_active { get; set; }
}

public record LoginRequest(string? username, string? password);
public record IdRequest(int id);
public record InvoiceReturnRequest(int invoice_id);
public record ProductItem(string? name, string? category, decimal cost, decimal price, int stock, string? barcode, string? imei);
public record ProductsAddRequest(List<ProductItem>? products);
public record CartItem(int id, string? name, decimal price, int qty);
public record InvoiceCreateRequest(string? customer_name, string? customer_phone, List<CartItem>? items);
public record RepairAddRequest(string? customer_name, string? customer_phone, string? device, string? issue);
public record StoreAddRequest(string? store_name, string? owner_name, string? phone, string? address, string? username, string? password, string? plan);
public record StoreUpdateRequest(int store_id, string? store_name, string? owner_name, string? phone, string? address, string? username, string? password, string? plan, string? expiry_date, bool is_active);
public record StoreDeleteRequest(int store_id);
public record SettingsSaveRequest(string? store_name, string? phone, string? address);
public record StaffAddRequest(string? name, string? username, string? password, string? role);
public record StaffResetRequest(int id, string? password);