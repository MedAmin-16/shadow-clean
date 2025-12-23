import { SecurityScoreCard } from "../SecurityScoreCard";

export default function SecurityScoreCardExample() {
  return (
    <SecurityScoreCard
      score={74}
      trend="up"
      trendValue={5}
      lastScan="2 hours ago"
    />
  );
}
