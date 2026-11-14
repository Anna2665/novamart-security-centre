PERMISSIONS: dict[str, set[str]] = {
    "admin": {"view", "sim:run", "sim:configure", "crypto:use", "sig:use", "db:read", "db:write", "db:tamper", "pii:read",
              "export:bulk", "incident:manage", "backup:manage", "backup:restore", "users:manage", "settings:manage",
              "audit:read", "system:reset"},
    "analyst": {"view", "sim:run", "sim:configure", "crypto:use", "sig:use", "db:read", "incident:manage", "backup:manage",
                "backup:restore", "audit:read"},
    "viewer": {"view", "audit:read", "db:read"},
    "customer": {"shop:buy", "shop:review"},  # storefront customers: no access to any staff function
}
ALL_PERMISSIONS = sorted(set().union(*PERMISSIONS.values()))
DESCRIPTIONS = {
    "view": "See dashboards", "sim:run": "Run attack simulations", "sim:configure": "Toggle defences",
    "crypto:use": "Use cryptography labs", "sig:use": "Use signature labs", "db:read": "Read tables (PII masked)",
    "db:write": "Authorised record updates", "db:tamper": "Run tamper simulation", "pii:read": "Decrypt customer PII",
    "export:bulk": "Bulk data export", "incident:manage": "Operate incidents", "backup:manage": "Create/verify backups",
    "backup:restore": "Restore from backup", "users:manage": "Manage users/roles", "settings:manage": "Change settings",
    "audit:read": "Read audit logs", "system:reset": "Reset the platform",
    "shop:buy": "Place orders in the store", "shop:review": "Write product reviews",
}


def can(role: str, perm: str) -> bool:
    return perm in PERMISSIONS.get(role, set())


# Service identities used by the simulated attacks (never granted to humans)
SERVICE_PERMISSIONS = {"catalog-service": {"products:read"}, "checkout-service": {"products:read", "orders:create", "payments:capture"}}

# DB-level grants (least privilege): what the application's database account may do per table
DB_GRANTS = {"app_rw": {"products": {"SELECT"}, "orders": {"SELECT", "INSERT"}, "payments": {"SELECT", "INSERT"}, "customers": {"SELECT"}}}

# Network zone policy when segmentation is ON (deny by default). Key = (source zone, destination zone)
ZONE_POLICY = {("Internet", "Edge"): True, ("Edge", "DMZ"): True, ("DMZ", "App"): True, ("Management", "App"): True,
               ("App", "Data"): True, ("App", "PCI"): True, ("Data", "Isolated"): True}


def zone_allowed(src: str, dst: str) -> bool:
    return ZONE_POLICY.get((src, dst), False)


def service_can(identity: str, perm: str) -> bool:
    return perm in SERVICE_PERMISSIONS.get(identity, set())


def db_can(account: str, table: str, op: str) -> bool:
    return op in DB_GRANTS.get(account, {}).get(table, set())
