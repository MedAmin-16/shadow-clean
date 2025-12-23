import { TwinStatusWidget } from "../TwinStatusWidget";

export default function TwinStatusWidgetExample() {
  return (
    <TwinStatusWidget
      projectName="Production API"
      status="active"
      lastScanTime="15 min ago"
      assetsCount={12}
    />
  );
}
