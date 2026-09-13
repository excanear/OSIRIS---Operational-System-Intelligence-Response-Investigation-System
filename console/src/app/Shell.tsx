import { NavLink, Outlet } from "react-router-dom";
import { NAV_ITEMS } from "./navItems";

export function Shell() {
  return (
    <div>
      <nav aria-label="main">
        <div>OSIRIS</div>
        <ul>
          {NAV_ITEMS.map((item) =>
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
