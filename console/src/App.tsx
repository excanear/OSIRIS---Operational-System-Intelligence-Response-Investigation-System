import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { ErrorBoundary } from "./app/ErrorBoundary";
import { Shell } from "./app/Shell";
import { Alerts } from "./screens/alerts/Alerts";
import { ComingSoon } from "./screens/ComingSoon";
import { EntityGraph } from "./screens/graph/EntityGraph";
import { EvidenceList } from "./screens/evidence/EvidenceList";
import { IncidentDetailScreen } from "./screens/incidents/IncidentDetailScreen";
import { IncidentList } from "./screens/incidents/IncidentList";
import { LiveEvents } from "./screens/live/LiveEvents";
import { Overview } from "./screens/overview/Overview";
import { ProcessDetailScreen } from "./screens/processes/ProcessDetailScreen";
import { ProcessList } from "./screens/processes/ProcessList";
import { Sensors } from "./screens/sensors/Sensors";
import { ThreatHunting } from "./screens/hunting/ThreatHunting";
import { Timeline } from "./screens/timeline/Timeline";

const queryClient = new QueryClient();

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <ErrorBoundary>
          <Routes>
            <Route element={<Shell />}>
              <Route path="/" element={<Overview />} />
              <Route path="/live-events" element={<LiveEvents />} />
              <Route path="/processes" element={<ProcessList />} />
              <Route path="/processes/:processKey" element={<ProcessDetailScreen />} />
              <Route path="/files" element={<ComingSoon label="Filesystem" />} />
              <Route path="/network" element={<ComingSoon label="Network" />} />
              <Route path="/containers" element={<ComingSoon label="Containers" />} />
              <Route path="/timeline" element={<Timeline />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/incidents" element={<IncidentList />} />
              <Route path="/incidents/:incidentId" element={<IncidentDetailScreen />} />
              <Route path="/hunting" element={<ThreatHunting />} />
              <Route path="/graph" element={<EntityGraph />} />
              <Route path="/evidence" element={<EvidenceList />} />
              <Route path="/sensors" element={<Sensors />} />
            </Route>
          </Routes>
        </ErrorBoundary>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
