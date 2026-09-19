import { NavLink, Outlet } from "react-router-dom";
import { useAuthStore } from "../store/authStore";
import { NAV_ITEMS } from "./navItems";

export function Shell() {
  const tenantId = useAuthStore((s) => s.tenantId);
  const tenantName = useAuthStore((s) => s.tenantName);
  const items = NAV_ITEMS.filter((item) => !(tenantId && item.platformOnly));
  return (
    <div>
      <nav aria-label="main">
        <div>OSIRIS</div>
        {tenantId && <div>{tenantName ?? "Tenant"}</div>}
        <ul>
          {items.map((item) =>
            item.enabled ? (
              <li key={item.path}>
                <NavLink to={item.path} end={item.path === "/"}>
                  {item.label}
                </NavLink>
              </li>
            ) : (
              <li key={item.path} aria-disabled="true">
                {item.label}
              </li>
            )
          )}
        </ul>
      </nav>
      <main>
        <Outlet />
      </main>
    </div>
  );
}
