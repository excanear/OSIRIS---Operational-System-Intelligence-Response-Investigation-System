// The .oql files under hunts/ (repo root) are the CLI's own saved hunt
// templates (osiris-cli's `hunts::template`, embedded there via
// `include_str!`). Importing the same files here via Vite's `?raw` suffix
// keeps one source of truth between the CLI and the Console.
import containerStartedInRemoteSession from "../../../../hunts/container-started-in-remote-session.oql?raw";
import networkDownloadThenWrite from "../../../../hunts/network-download-then-write.oql?raw";
import shellWroteFileToWebRoot from "../../../../hunts/shell-wrote-file-to-web-root.oql?raw";

export interface HuntTemplate {
  name: string;
  label: string;
  query: string;
}

export const HUNT_TEMPLATES: HuntTemplate[] = [
  {
    name: "network-download-then-write",
    label: "Network download then write",
    query: networkDownloadThenWrite.trim(),
  },
  {
    name: "shell-wrote-file-to-web-root",
    label: "Shell wrote file to web root",
    query: shellWroteFileToWebRoot.trim(),
  },
  {
    name: "container-started-in-remote-session",
    label: "Container started in remote session",
    query: containerStartedInRemoteSession.trim(),
  },
];
