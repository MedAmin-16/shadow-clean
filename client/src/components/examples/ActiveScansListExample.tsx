import { ActiveScansList } from "../ActiveScansList";

// todo: remove mock functionality
const mockScans = [
  { id: "1", projectName: "Production API", status: "running" as const, progress: 65 },
  { id: "2", projectName: "Staging Environment", status: "pending" as const },
  { id: "3", projectName: "Internal Tools", status: "complete" as const },
];

export default function ActiveScansListExample() {
  return <ActiveScansList scans={mockScans} />;
}
