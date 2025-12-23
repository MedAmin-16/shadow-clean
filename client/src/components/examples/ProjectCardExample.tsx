import { ProjectCard } from "../ProjectCard";

export default function ProjectCardExample() {
  return (
    <ProjectCard
      id="1"
      name="Production API"
      assetCount={12}
      lastScanDate="2 hours ago"
      securityScore={74}
      onClick={() => console.log("Project clicked")}
    />
  );
}
