import { useCallback, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Activity,
  AlertTriangle,
  Gauge,
  GitBranch,
  Network,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react'
import { api } from '../api'
import { useDataLoader } from '../hooks/useDataLoader'
import type { RelayRouteStats } from '../types'
import StatCard from './StatCard'
import StateShell from './StateShell'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { cn } from '@/lib/utils'

const WINDOW_OPTIONS = [
  { hours: 24, labelKey: 'promptFilter.routing.windows.day' },
  { hours: 24 * 7, labelKey: 'promptFilter.routing.windows.week' },
  { hours: 24 * 30, labelKey: 'promptFilter.routing.windows.month' },
] as const

const EMPTY_STATS: RelayRouteStats = {
  window_hours: 24,
  route_attempts: 0,
  logical_routes: 0,
  cyb_rule: 0,
  probe: 0,
  oauth_overflow: 0,
  relay_continuation: 0,
  cyb_feedback: 0,
  retries: 0,
  same_group_switches: 0,
  group_exhausted: 0,
  detector_misses: 0,
  relay_cyber_policies: 0,
  route_violations: 0,
  state_fallbacks: 0,
}

const numberFormatter = new Intl.NumberFormat()

type DetailItem = {
  key: keyof RelayRouteStats
  label: string
  description: string
  tone?: 'default' | 'warning' | 'danger'
}

function DetailGrid({
  stats,
  items,
}: {
  stats: RelayRouteStats
  items: DetailItem[]
}) {
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {items.map((item) => (
        <div
          key={item.key}
          className={cn(
            'rounded-xl border border-border/80 bg-muted/25 p-4',
            item.tone === 'warning' && 'border-amber-500/20 bg-amber-500/5',
            item.tone === 'danger' && 'border-destructive/20 bg-destructive/5',
          )}
        >
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="text-sm font-semibold text-foreground">{item.label}</div>
              <div className="mt-1 text-xs leading-relaxed text-muted-foreground">
                {item.description}
              </div>
            </div>
            <div className="shrink-0 text-xl font-bold tabular-nums text-foreground">
              {numberFormatter.format(Number(stats[item.key]))}
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

export default function RelayRouteStatsPanel() {
  const { t } = useTranslation()
  const [windowHours, setWindowHours] = useState(24)
  const loadStats = useCallback(
    () => api.getRelayRouteStats(windowHours),
    [windowHours],
  )
  const {
    data: stats,
    loading,
    error,
    reload,
  } = useDataLoader<RelayRouteStats>({
    initialData: EMPTY_STATS,
    load: loadStats,
  })

  const routeSources: DetailItem[] = [
    {
      key: 'cyb_rule',
      label: t('promptFilter.routing.metrics.cybRule'),
      description: t('promptFilter.routing.metricHints.cybRule'),
    },
    {
      key: 'probe',
      label: t('promptFilter.routing.metrics.probe'),
      description: t('promptFilter.routing.metricHints.probe'),
    },
    {
      key: 'oauth_overflow',
      label: t('promptFilter.routing.metrics.oauthOverflow'),
      description: t('promptFilter.routing.metricHints.oauthOverflow'),
    },
    {
      key: 'relay_continuation',
      label: t('promptFilter.routing.metrics.relayContinuation'),
      description: t('promptFilter.routing.metricHints.relayContinuation'),
    },
    {
      key: 'cyb_feedback',
      label: t('promptFilter.routing.metrics.cybFeedback'),
      description: t('promptFilter.routing.metricHints.cybFeedback'),
    },
  ]
  const healthSignals: DetailItem[] = [
    {
      key: 'group_exhausted',
      label: t('promptFilter.routing.metrics.groupExhausted'),
      description: t('promptFilter.routing.metricHints.groupExhausted'),
      tone: 'warning',
    },
    {
      key: 'detector_misses',
      label: t('promptFilter.routing.metrics.detectorMisses'),
      description: t('promptFilter.routing.metricHints.detectorMisses'),
      tone: 'warning',
    },
    {
      key: 'relay_cyber_policies',
      label: t('promptFilter.routing.metrics.relayCyberPolicies'),
      description: t('promptFilter.routing.metricHints.relayCyberPolicies'),
    },
    {
      key: 'route_violations',
      label: t('promptFilter.routing.metrics.routeViolations'),
      description: t('promptFilter.routing.metricHints.routeViolations'),
      tone: 'danger',
    },
    {
      key: 'state_fallbacks',
      label: t('promptFilter.routing.metrics.stateFallbacks'),
      description: t('promptFilter.routing.metricHints.stateFallbacks'),
      tone: 'warning',
    },
  ]

  return (
    <div className="space-y-5">
      <Card className="gap-0">
        <CardContent className="flex flex-col gap-4 p-4 sm:flex-row sm:items-center sm:justify-between sm:p-5">
          <div>
            <h2 className="text-base font-bold text-foreground">
              {t('promptFilter.routing.title')}
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">
              {t('promptFilter.routing.description')}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="inline-flex rounded-lg border border-border bg-muted/50 p-0.5">
              {WINDOW_OPTIONS.map((option) => (
                <button
                  key={option.hours}
                  type="button"
                  onClick={() => setWindowHours(option.hours)}
                  aria-pressed={windowHours === option.hours}
                  className={cn(
                    'rounded-md px-3 py-1.5 text-xs font-medium transition-all duration-200',
                    windowHours === option.hours
                      ? 'border border-border bg-background text-foreground shadow-sm'
                      : 'text-muted-foreground hover:text-foreground',
                  )}
                >
                  {t(option.labelKey)}
                </button>
              ))}
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void reload()}
              disabled={loading}
            >
              <RefreshCw className={cn('size-3.5', loading && 'animate-spin')} />
              {t('common.refresh')}
            </Button>
          </div>
        </CardContent>
      </Card>

      <StateShell
        variant="section"
        loading={loading}
        error={error}
        onRetry={() => void reload()}
        loadingTitle={t('promptFilter.routing.loadingTitle')}
        loadingDescription={t('promptFilter.routing.loadingDescription')}
        errorTitle={t('promptFilter.routing.errorTitle')}
      >
        <div className="space-y-5">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard
              icon={<GitBranch />}
              iconClass="purple"
              label={t('promptFilter.routing.metrics.logicalRoutes')}
              value={numberFormatter.format(stats.logical_routes)}
              sub={t('promptFilter.routing.metricHints.logicalRoutes')}
            />
            <StatCard
              icon={<Activity />}
              iconClass="blue"
              label={t('promptFilter.routing.metrics.routeAttempts')}
              value={numberFormatter.format(stats.route_attempts)}
              sub={t('promptFilter.routing.metricHints.routeAttempts')}
            />
            <StatCard
              icon={<RefreshCw />}
              iconClass="amber"
              label={t('promptFilter.routing.metrics.retries')}
              value={numberFormatter.format(stats.retries)}
              sub={t('promptFilter.routing.metricHints.retries')}
            />
            <StatCard
              icon={<Network />}
              iconClass="green"
              label={t('promptFilter.routing.metrics.sameGroupSwitches')}
              value={numberFormatter.format(stats.same_group_switches)}
              sub={t('promptFilter.routing.metricHints.sameGroupSwitches')}
            />
          </div>

          <div className="grid gap-5 xl:grid-cols-2">
            <Card>
              <CardHeader className="border-b border-border/70">
                <div className="flex items-center gap-3">
                  <div className="flex size-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
                    <Gauge className="size-5" />
                  </div>
                  <div>
                    <CardTitle>{t('promptFilter.routing.sourcesTitle')}</CardTitle>
                    <CardDescription className="mt-1">
                      {t('promptFilter.routing.sourcesDescription')}
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <DetailGrid stats={stats} items={routeSources} />
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="border-b border-border/70">
                <div className="flex items-center gap-3">
                  <div className="flex size-10 items-center justify-center rounded-xl bg-amber-500/10 text-amber-600 dark:text-amber-400">
                    {stats.route_violations > 0 || stats.group_exhausted > 0
                      ? <AlertTriangle className="size-5" />
                      : <ShieldAlert className="size-5" />}
                  </div>
                  <div>
                    <CardTitle>{t('promptFilter.routing.healthTitle')}</CardTitle>
                    <CardDescription className="mt-1">
                      {t('promptFilter.routing.healthDescription')}
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <DetailGrid stats={stats} items={healthSignals} />
              </CardContent>
            </Card>
          </div>
        </div>
      </StateShell>
    </div>
  )
}
