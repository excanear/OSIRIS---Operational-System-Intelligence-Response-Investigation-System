import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Outlet, Route, Routes } from "react-router-dom";
import { ErrorBoundary } from "./app/ErrorBoundary";
import { Shell } from "./app/Shell";
import { Alerts } from "./screens/alerts/Alerts";
import { ContainerDetailScreen } from "./screens/containers/ContainerDetailScreen";
import { ContainerList } from "./screens/containers/ContainerList";
import { FileDetailScreen } from "./screens/files/FileDetailScreen";
import { FileList } from "./screens/files/FileList";
import { EntityGraph } from "./screens/graph/EntityGraph";
import { EvidenceList } from "./screens/evidence/EvidenceList";
import { IncidentDetailScreen } from "./screens/incidents/IncidentDetailScreen";
import { IncidentList } from "./screens/incidents/IncidentList";
import { LiveEvents } from "./screens/live/LiveEvents";
import { NetworkDetailScreen } from "./screens/network/NetworkDetailScreen";
import { NetworkList } from "./screens/network/NetworkList";
import { Overview } from "./screens/overview/Overview";
import { ProcessDetailScreen } from "./screens/processes/ProcessDetailScreen";
import { ProcessList } from "./screens/processes/ProcessList";
import { Sensors } from "./screens/sensors/Sensors";
import { Login } from "./screens/auth/Login";
import { ThreatHunting } from "./screens/hunting/ThreatHunting";
import { Timeline } from "./screens/timeline/Timeline";
import { useAuthStore } from "./store/authStore";

const queryClient = new QueryClient();

function RequireAuth() {
  const token = useAuthStore((s) => s.token);
  return token ? <Outlet /> : <Navigate to="/login" replace />;
}

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <ErrorBoundary>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route element={<RequireAuth />}>
              <Route element={<Shell />}>
                <Route path="/" element={<Overview />} />
                <Route path="/live-events" element={<LiveEvents />} />
                <Route path="/processes" element={<ProcessList />} />
                <Route path="/processes/:processKey" element={<ProcessDetailScreen />} />
                <Route path="/files" element={<FileList />} />
                <Route path="/files/:fileId" element={<FileDetailScreen />} />
                <Route path="/network" element={<NetworkList />} />
                <Route path="/network/:ip" element={<NetworkDetailScreen />} />
                <Route path="/containers" element={<ContainerList />} />
                <Route path="/containers/:containerId" element={<ContainerDetailScreen />} />
                <Route path="/timeline" element={<Timeline />} />
                <Route path="/alerts" element={<Alerts />} />
                <Route path="/incidents" element={<IncidentList />} />
                <Route path="/incidents/:incidentId" element={<IncidentDetailScreen />} />
                <Route path="/hunting" element={<ThreatHunting />} />
                <Route path="/graph" element={<EntityGraph />} />
                <Route path="/evidence" element={<EvidenceList />} />
                <Route path="/sensors" element={<Sensors />} />
              </Route>
            </Route>
          </Routes>
        </ErrorBoundary>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
