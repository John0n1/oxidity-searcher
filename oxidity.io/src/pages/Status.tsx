import { AlertCircle, CheckCircle2, Clock, LoaderCircle, XCircle } from 'lucide-react';
import { usePublicData } from '../hooks/usePublicData';
import { formatRelativeTime } from '../lib/formatters';

function statusBadge(status: 'operational' | 'degraded' | 'outage') {
  if (status === 'operational') {
    return {
      icon: CheckCircle2,
      chip: 'bg-emerald-50 text-emerald-700',
      label: 'Operational',
      iconClass: 'text-emerald-500',
    };
  }

  if (status === 'degraded') {
    return {
      icon: AlertCircle,
      chip: 'bg-amber-50 text-amber-700',
      label: 'Degraded',
      iconClass: 'text-amber-500',
    };
  }

  return {
    icon: XCircle,
    chip: 'bg-red-50 text-red-700',
    label: 'Outage',
    iconClass: 'text-red-500',
  };
}

export function Status() {
  const { result, loading, error } = usePublicData();
  const services = result?.data.services ?? [];
  const incidents = result?.data.incidents ?? [];
  const overall = result?.source === 'degraded'
    ? 'degraded'
    : services.some((service) => service.status === 'outage')
    ? 'outage'
    : services.some((service) => service.status === 'degraded')
      ? 'degraded'
      : 'operational';
  const overallUi = statusBadge(overall);

  return (
    <div className="bg-page min-h-screen py-12">
      <div className="mx-auto max-w-3xl px-4 sm:px-6 lg:px-8">
        <div className="mb-8 flex items-center justify-between bg-white rounded-2xl p-6 shadow-sm ring-1 ring-zinc-200">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-zinc-900">System Status</h1>
            <p className="mt-1 text-sm text-zinc-500">
              {result
                ? result.source === 'degraded'
                  ? `Updated ${formatRelativeTime(result.data.generatedAt)} (degraded)`
                  : `Updated ${formatRelativeTime(result.data.generatedAt)}`
                : error
                  ? `Live status unavailable: ${error}`
                  : 'Waiting for status data...'}
            </p>
          </div>
          <div className={`flex items-center gap-2 px-4 py-2 rounded-full text-sm font-medium border ${overallUi.chip}`}>
            <overallUi.icon className={`w-4 h-4 ${overallUi.iconClass}`} />
            {overallUi.label}
          </div>
        </div>

        <div className="bg-white rounded-2xl shadow-sm ring-1 ring-zinc-200 overflow-hidden">
          {result?.source === 'degraded' && (
            <div className="border-b border-amber-200 bg-amber-50 px-6 py-4 text-sm text-amber-800">
              {error || 'Public telemetry is currently unavailable or too sparse to publish.'}
            </div>
          )}
          <ul role="list" className="divide-y divide-zinc-200">
            {services.map((service) => {
              const ui = statusBadge(service.status);
              return (
                <li key={service.name} className="px-6 py-5 flex items-center justify-between hover:bg-zinc-50 transition-colors">
                  <div className="flex items-center gap-3">
                    <ui.icon className={`w-5 h-5 ${ui.iconClass}`} />
                    <span className="text-sm font-medium text-zinc-900">{service.name}</span>
                  </div>
                  <div className="flex items-center gap-4">
                    <span className="text-sm text-zinc-500">{service.uptimePct.toFixed(2)}% uptime</span>
                    <span className="text-sm text-zinc-500">{service.latencyMs.toFixed(0)}ms</span>
                    <span className={`text-xs font-medium px-2.5 py-1 rounded-full ${ui.chip}`}>{ui.label}</span>
                  </div>
                </li>
              );
            })}
          </ul>
          {!loading && services.length === 0 && (
            <div className="px-6 py-8 text-sm text-zinc-500 border-t border-zinc-200">
              No live service telemetry is available right now.
            </div>
          )}
          {loading && (
            <div className="px-6 py-4 text-sm text-zinc-500 border-t border-zinc-200 inline-flex items-center gap-2">
              <LoaderCircle className="h-4 w-4 animate-spin" />
              Refreshing status data
            </div>
          )}
        </div>

        <div className="mt-8 bg-white rounded-2xl p-6 shadow-sm ring-1 ring-zinc-200">
          <h2 className="text-lg font-semibold text-zinc-900 mb-4 flex items-center gap-2">
            <Clock className="w-5 h-5 text-zinc-500" />
            Past Incidents
          </h2>
          {incidents.length === 0 ? (
            <div className="text-sm text-zinc-500 py-4 text-center border-2 border-dashed border-zinc-200 rounded-lg">
              No incidents reported in the last 30 days.
            </div>
          ) : (
            <ul className="divide-y divide-zinc-200 rounded-lg border border-zinc-200">
              {incidents.map((incident) => (
                <li key={incident.id} className="p-4 text-sm">
                  <div className="font-medium text-zinc-900">{incident.title}</div>
                  <div className="mt-1 text-zinc-500">Impact: {incident.impact}</div>
                  <div className="text-zinc-500">Started: {new Date(incident.startedAt).toLocaleString()}</div>
                  {incident.resolvedAt && <div className="text-zinc-500">Resolved: {new Date(incident.resolvedAt).toLocaleString()}</div>}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
