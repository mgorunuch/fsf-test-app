import { useSuspenseQuery } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import { Suspense } from "react"

import { MetricsService } from "@/client"
import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { PERMISSIONS, requirePermission } from "@/lib/permissions"

function getMetricsQueryOptions() {
  return {
    queryFn: async () => (await MetricsService.readMetrics()).data,
    queryKey: ["metrics"],
  }
}

export const Route = createFileRoute("/_layout/metrics")({
  component: Metrics,
  beforeLoad: async () => {
    // metrics:read lets both admin and manager view the page; anyone else
    // (e.g. a member navigating directly) is redirected home.
    await requirePermission(PERMISSIONS.metricsRead)
  },
  head: () => ({
    meta: [
      {
        title: "Metrics - FastAPI Template",
      },
    ],
  }),
})

function MetricCard({ title, value }: { title: string; value: number }) {
  return (
    <Card>
      <CardHeader>
        <CardDescription>{title}</CardDescription>
        <CardTitle className="text-3xl tabular-nums">{value}</CardTitle>
      </CardHeader>
    </Card>
  )
}

function MetricsContent() {
  const { data: metrics } = useSuspenseQuery(getMetricsQueryOptions())
  const rolesEntries = Object.entries(metrics.users_per_role)

  return (
    <div className="flex flex-col gap-6">
      <div className="grid gap-4 sm:grid-cols-2">
        <MetricCard title="Total users" value={metrics.total_users} />
        <MetricCard title="Active users" value={metrics.active_users} />
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Users per role</CardTitle>
          <CardDescription>
            How many users hold each role in the system.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {rolesEntries.length === 0 ? (
            <p className="text-muted-foreground text-sm">No roles found.</p>
          ) : (
            <ul className="flex flex-col gap-2">
              {rolesEntries.map(([role, count]) => (
                <li
                  key={role}
                  className="flex items-center justify-between border-b py-2 last:border-b-0"
                >
                  <Badge
                    variant={role === "admin" ? "default" : "secondary"}
                    className="capitalize"
                  >
                    {role}
                  </Badge>
                  <span className="font-medium tabular-nums">{count}</span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function MetricsPending() {
  return (
    <div className="flex flex-col gap-6">
      <div className="grid gap-4 sm:grid-cols-2">
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-24 w-full" />
      </div>
      <Skeleton className="h-48 w-full" />
    </div>
  )
}

function Metrics() {
  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Metrics</h1>
        <p className="text-muted-foreground">An overview of system usage.</p>
      </div>
      <Suspense fallback={<MetricsPending />}>
        <MetricsContent />
      </Suspense>
    </div>
  )
}
