import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { ErrorBoundary } from "./app/ErrorBoundary";
import { Shell } from "./app/Shell";
import { ComingSoon } from "./screens/ComingSoon";

const queryClient = new QueryClient();

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <ErrorBoundary>
          <Routes>
            <Route element={<Shell />}>
              <Route path="/" element={<ComingSoon label="Overview" />} />
              <Route path="/live-events" element={<ComingSoon label="Live Events" />} />
              <Route path="/processes" element={<ComingSoon label="Process Explorer" />} />
              <Route path="/files" element={<ComingSoon label="Filesystem" />} />
              <Route path="/network" element={<ComingSoon label="Network" />} />
              <Route path="/containers" element={<ComingSoon label="Containers" />} />
              <Route path="/timeline" element={<ComingSoon label="Timeline" />} />
              <Route path="/alerts" element={<ComingSoon label="Alerts" />} />
              <Route path="/incidents" element={<ComingSoon label="Incidents" />} />
              <Route path="/hunting" element={<ComingSoon label="Threat Hunting" />} />
              <Route path="/graph" element={<ComingSoon label="Entity Graph" />} />
              <Route path="/evidence" element={<ComingSoon label="Evidence" />} />
              <Route path="/sensors" element={<ComingSoon label="Sensors" />} />
            </Route>
          </Routes>
        </ErrorBoundary>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
