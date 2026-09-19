//! Tenant registry: which tenants exist and which hosts belong to which
//! tenant (ARCHITECTURE.md §21.5). Pure logic over its own SQLite file
//! (`tenants.db`), same per-subsystem-store pattern as `osiris-auth`.

mod store;

pub use store::{SqliteTenantStore, Tenant, TenantStore, TenantStoreError};
