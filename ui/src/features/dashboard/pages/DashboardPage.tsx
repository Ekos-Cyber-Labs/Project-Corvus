import { useConsole } from "../hooks/useConsole";
import { PageHeader } from "../../../components/layout/PageHeader";
import { Skeleton } from "../../../components/ui/Skeleton";
import { ErrorState } from "../../../components/ui/ErrorState";
import { EmptyState } from "../../../components/ui/EmptyState";
import { StatCards } from "../components/StatCards";
import { SeverityDist } from "../components/SeverityDist";
import { ActivityChart } from "../components/ActivityChart";
import { RecentVerdicts } from "../components/RecentVerdicts";
import { SweepStatusCard } from "../components/SweepStatusCard";
import { formatClock } from "../utils/dashboard";
import pageStyles from "./DashboardPage.module.css";
export function DashboardPage() {
  const { dashboard, sweep, state, updatedAt, retry } = useConsole();
  const subtitle = `Last 24 hours · Updated ${formatClock(updatedAt)}`;
  return (
    <main className={pageStyles.page}>
      <PageHeader title="Dashboard" subtitle={subtitle}>
        <p className={pageStyles.actions}>
          <button type="button" disabled title="Run corvus sweep from the host">Sweep now</button>
        </p>
      </PageHeader>
      {state === "loading" ? (
        <div aria-live="polite" className={pageStyles.loading}>
          <div className={pageStyles.row1}><Skeleton /><Skeleton /><Skeleton /><Skeleton /></div>
          <div className={pageStyles.row2}><Skeleton /><Skeleton /></div>
          <div className={pageStyles.row3}><Skeleton /><Skeleton /></div>
        </div>
      ) : state === "error" || !dashboard ? (
        <ErrorState message="Could not load the dashboard. Check that the API and database are running, then reload." onRetry={retry} />
      ) : dashboard.totals.incidents === 0 ? (
        <EmptyState title="No incidents yet" message="The sweep has not run yet. Start it with corvus sweep, then reload this page." />
      ) : (
        <>
          <StatCards dashboard={dashboard} sweep={sweep} />
          <div className={pageStyles.row2}>
            <SeverityDist dashboard={dashboard} />
            <ActivityChart dashboard={dashboard} />
          </div>
          <div className={pageStyles.row3}>
            <RecentVerdicts recent={dashboard.recent} />
            <SweepStatusCard sweep={sweep} dashboard={dashboard} />
          </div>
        </>
      )}
    </main>
  );
}
