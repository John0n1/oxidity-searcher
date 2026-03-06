import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  CheckCircle2,
  Clock,
  Download,
  Key,
  Lock,
  LoaderCircle,
  LogOut,
  Webhook,
  XCircle,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { APP_CONFIG, loadPartnerData } from '../lib/publicData';
import { usePartnerData } from '../hooks/usePartnerData';
import { formatCompactNumber, formatEth, formatRelativeTime, formatUsd, shortHash } from '../lib/formatters';
import {
  clearPartnerSession,
  isPartnerSessionExpired,
  readPartnerSession,
  savePartnerSession,
  type PartnerSession,
} from '../lib/partnerSession';

const statuses = ['all', 'Included', 'Pending', 'Failed', 'Dropped'] as const;
const paths = ['all', 'Sponsored', 'Private only', 'Pass-through'] as const;
const PARTNER_SESSION_TTL_HOURS = 12;

function buildSession(email: string, accessToken: string): PartnerSession {
  return {
    email,
    accessToken,
    accountType: 'Partner',
    expiresAt: new Date(Date.now() + PARTNER_SESSION_TTL_HOURS * 60 * 60 * 1000).toISOString(),
  };
}

export function Dashboard() {
  const [session, setSession] = useState<PartnerSession | null>(() => {
    const restored = readPartnerSession();
    if (!restored) {
      return null;
    }
    if (isPartnerSessionExpired(restored)) {
      clearPartnerSession();
      return null;
    }
    return restored;
  });
  const [loginEmail, setLoginEmail] = useState('');
  const [loginAccessToken, setLoginAccessToken] = useState('');
  const [loginSubmitting, setLoginSubmitting] = useState(false);
  const [loginError, setLoginError] = useState('');
  const [activeTab, setActiveTab] = useState<'transactions' | 'policy'>('transactions');
  const [statusFilter, setStatusFilter] = useState<(typeof statuses)[number]>('all');
  const [pathFilter, setPathFilter] = useState<(typeof paths)[number]>('all');
  const { result, loading, error } = usePartnerData(session?.accessToken ?? null);

  useEffect(() => {
    if (!session) {
      return;
    }
    if (isPartnerSessionExpired(session)) {
      clearPartnerSession();
      setSession(null);
      setLoginError('Session expired. Please sign in again.');
    }
  }, [session]);

  useEffect(() => {
    if (!session || !error) {
      return;
    }
    if (error.toLowerCase().includes('unauthorized')) {
      clearPartnerSession();
      setSession(null);
      setLoginError('Session invalid or expired. Please sign in again.');
    }
  }, [error, session]);

  const signOut = () => {
    clearPartnerSession();
    setSession(null);
    setLoginAccessToken('');
    setLoginError('');
  };

  const signIn = async () => {
    const normalizedEmail = loginEmail.trim().toLowerCase();
    const normalizedToken = loginAccessToken.trim();

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      setLoginError('Enter a valid work email address.');
      return;
    }
    if (!normalizedToken) {
      setLoginError('Partner access token is required.');
      return;
    }

    setLoginSubmitting(true);
    try {
      await loadPartnerData(normalizedToken);
      const nextSession = buildSession(normalizedEmail, normalizedToken);
      savePartnerSession(nextSession);
      setSession(nextSession);
      setLoginError('');
      setLoginAccessToken('');
    } catch (err) {
      setLoginError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoginSubmitting(false);
    }
  };

  const transactions = result?.data.transactions ?? [];

  const filteredTransactions = useMemo(() => {
    return transactions.filter((tx) => {
      const statusMatches = statusFilter === 'all' || tx.status === statusFilter;
      const pathMatches = pathFilter === 'all' || tx.path === pathFilter;
      return statusMatches && pathMatches;
    });
  }, [pathFilter, statusFilter, transactions]);

  const txGasCoveredUsd = transactions.reduce((sum, tx) => sum + tx.gasCoveredUsd, 0);
  const coverageCapUsedEth = txGasCoveredUsd / 2400;
  const capEth = result?.data.policy.perDayGasCapEth ?? 0.5;

  if (!session) {
    return (
      <div className="bg-page min-h-screen py-16">
        <div className="mx-auto max-w-xl px-4 sm:px-6 lg:px-8">
          <div className="rounded-2xl bg-white p-8 shadow-sm ring-1 ring-zinc-200">
            <div className="mb-6 flex items-center gap-3">
              <div className="rounded-lg bg-zinc-900 p-2 text-white">
                <Lock className="h-5 w-5" />
              </div>
              <div>
                <h1 className="text-xl font-semibold text-zinc-900">Partner Dashboard Access</h1>
                <p className="text-sm text-zinc-500">Sign in with your partner credentials.</p>
              </div>
            </div>

            <form
              className="space-y-4"
              onSubmit={(event) => {
                event.preventDefault();
                void signIn();
              }}
            >
              <label className="block text-sm">
                <span className="mb-1 block font-medium text-zinc-700">Work Email</span>
                <input
                  id="partner-login-email"
                  name="partner_login_email"
                  autoComplete="email"
                  type="email"
                  value={loginEmail}
                  onChange={(event) => setLoginEmail(event.target.value)}
                  placeholder="name@company.com"
                  className="w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm"
                />
              </label>
              <label className="block text-sm">
                <span className="mb-1 block font-medium text-zinc-700">Partner Access Token</span>
                <input
                  id="partner-login-token"
                  name="partner_login_token"
                  autoComplete="off"
                  type="password"
                  value={loginAccessToken}
                  onChange={(event) => setLoginAccessToken(event.target.value)}
                  placeholder="Paste access token"
                  className="w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm"
                />
              </label>
              <div className="mt-6 flex flex-wrap gap-3">
                <button
                  type="submit"
                  disabled={loginSubmitting}
                  className="inline-flex items-center rounded-md bg-zinc-900 px-4 py-2 text-sm font-semibold text-white hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {loginSubmitting ? 'Signing in...' : 'Sign In'}
                </button>
                <Link
                  to="/partners?requested=dashboard"
                  className="inline-flex items-center rounded-md border border-zinc-300 bg-white px-4 py-2 text-sm font-semibold text-zinc-900 hover:bg-zinc-50"
                >
                  Request Access
                </Link>
                <a
                  href={`mailto:${APP_CONFIG.supportEmail}?subject=${encodeURIComponent('Partner dashboard access request')}`}
                  className="inline-flex items-center rounded-md border border-zinc-300 bg-white px-4 py-2 text-sm font-semibold text-zinc-900 hover:bg-zinc-50"
                >
                  Email Ops
                </a>
              </div>
            </form>

            {loginError && <p className="mt-4 text-sm text-red-600">{loginError}</p>}
          </div>
        </div>
      </div>
    );
  }

  const exportCsv = () => {
    const header = ['txHash', 'status', 'path', 'submittedAt', 'gasCoveredUsd', 'mevRebateUsd', 'netToUserUsd'];
    const lines = filteredTransactions.map((tx) =>
      [tx.txHash, tx.status, tx.path, tx.submittedAt, tx.gasCoveredUsd, tx.mevRebateUsd, tx.netToUserUsd].join(','),
    );
    const csv = [header.join(','), ...lines].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `mitander-dashboard-${new Date().toISOString().slice(0, 19)}.csv`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="bg-page min-h-screen py-8">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="md:flex md:items-center md:justify-between mb-8">
          <div className="min-w-0 flex-1">
            <h2 className="text-2xl font-bold leading-7 text-zinc-900 sm:truncate sm:text-3xl sm:tracking-tight">Dashboard</h2>
            <p className="mt-1 text-sm text-zinc-500">
              {result
                ? `Live data from ${result.endpoint}`
                : error
                  ? `Live data unavailable: ${error}`
                  : 'Waiting for live data...'}
            </p>
          </div>
          <div className="mt-4 flex md:ml-4 md:mt-0 gap-3">
            <button
              onClick={signOut}
              className="inline-flex items-center gap-x-1.5 rounded-md border border-zinc-300 bg-white px-3 py-2 text-sm font-semibold text-zinc-700 hover:bg-zinc-50"
            >
              <LogOut className="-ml-0.5 h-4 w-4 text-zinc-500" aria-hidden="true" />
              Sign Out
            </button>
            <button className="inline-flex items-center gap-x-1.5 rounded-md bg-white px-3 py-2 text-sm font-semibold text-zinc-900 shadow-sm ring-1 ring-inset ring-zinc-300 hover:bg-zinc-50">
              <Webhook className="-ml-0.5 h-4 w-4 text-zinc-400" aria-hidden="true" />
              Webhooks
            </button>
            <button
              onClick={exportCsv}
              className="inline-flex items-center gap-x-1.5 rounded-md bg-zinc-900 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-zinc-800"
            >
              <Download className="-ml-0.5 h-4 w-4" aria-hidden="true" />
              Export CSV
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3 mb-8">
          <div className="bg-white rounded-xl p-6 shadow-sm ring-1 ring-zinc-200">
            <div className="flex items-center gap-3 text-zinc-500 mb-2">
              <Key className="w-4 h-4" />
              <h3 className="text-sm font-medium">Account Type</h3>
            </div>
            <p className="text-2xl font-semibold text-zinc-900">{session.accountType}</p>
            <p className="text-sm text-zinc-500 mt-1">
              {session.email} · Endpoint: {APP_CONFIG.rpcUrl}
            </p>
          </div>
          <div className="bg-white rounded-xl p-6 shadow-sm ring-1 ring-zinc-200">
            <div className="flex items-center gap-3 text-zinc-500 mb-2">
              <Activity className="w-4 h-4" />
              <h3 className="text-sm font-medium">Monthly Usage</h3>
            </div>
            <p className="text-2xl font-semibold text-zinc-900">
              {result ? formatCompactNumber(result.data.stats.sponsoredTxCount) : '--'} / 5M
            </p>
            <div className="w-full bg-zinc-100 rounded-full h-1.5 mt-3">
              <div
                className="bg-emerald-500 h-1.5 rounded-full"
                style={{ width: `${Math.min(100, ((result?.data.stats.sponsoredTxCount ?? 0) / 5_000_000) * 100)}%` }}
              />
            </div>
          </div>
          <div className="bg-white rounded-xl p-6 shadow-sm ring-1 ring-zinc-200">
            <div className="flex items-center gap-3 text-zinc-500 mb-2">
              <Clock className="w-4 h-4" />
              <h3 className="text-sm font-medium">Coverage Cap</h3>
            </div>
            <p className="text-2xl font-semibold text-zinc-900">
              {formatEth(coverageCapUsedEth)} / {formatEth(capEth)}
            </p>
            <div className="w-full bg-zinc-100 rounded-full h-1.5 mt-3">
              <div className="bg-blue-500 h-1.5 rounded-full" style={{ width: `${Math.min(100, (coverageCapUsedEth / capEth) * 100)}%` }} />
            </div>
          </div>
        </div>

        <div className="mb-6 flex flex-wrap items-center gap-3">
          <div className="inline-flex rounded-lg bg-zinc-200 p-1">
            <button
              className={`px-3 py-1.5 text-sm rounded-md ${activeTab === 'transactions' ? 'bg-white text-zinc-900 shadow' : 'text-zinc-600'}`}
              onClick={() => setActiveTab('transactions')}
            >
              Transactions
            </button>
            <button
              className={`px-3 py-1.5 text-sm rounded-md ${activeTab === 'policy' ? 'bg-white text-zinc-900 shadow' : 'text-zinc-600'}`}
              onClick={() => setActiveTab('policy')}
            >
              Policy
            </button>
          </div>

          {activeTab === 'transactions' && (
            <>
              <select
                id="dashboard-path-filter"
                name="dashboard_path_filter"
                value={pathFilter}
                onChange={(event) => setPathFilter(event.target.value as (typeof paths)[number])}
                className="rounded-md border border-zinc-300 px-3 py-2 text-sm"
              >
                {paths.map((value) => (
                  <option value={value} key={value}>
                    Path: {value}
                  </option>
                ))}
              </select>
              <select
                id="dashboard-status-filter"
                name="dashboard_status_filter"
                value={statusFilter}
                onChange={(event) => setStatusFilter(event.target.value as (typeof statuses)[number])}
                className="rounded-md border border-zinc-300 px-3 py-2 text-sm"
              >
                {statuses.map((value) => (
                  <option value={value} key={value}>
                    Status: {value}
                  </option>
                ))}
              </select>
            </>
          )}

          {loading && (
            <div className="ml-auto inline-flex items-center gap-2 text-sm text-zinc-500">
              <LoaderCircle className="h-4 w-4 animate-spin" /> Refreshing
            </div>
          )}
        </div>

        {activeTab === 'transactions' && (
          <div className="bg-white shadow-sm ring-1 ring-zinc-200 sm:rounded-xl overflow-hidden">
            <div className="border-b border-zinc-200 px-4 py-5 sm:px-6 flex justify-between items-center">
              <h3 className="text-base font-semibold leading-6 text-zinc-900">Recent Transactions</h3>
              <span className="text-xs text-zinc-500">{filteredTransactions.length} shown</span>
            </div>

            {filteredTransactions.length === 0 ? (
              <div className="p-8 text-sm text-zinc-500">No transactions match current filters.</div>
            ) : (
              <ul role="list" className="divide-y divide-zinc-200">
                {filteredTransactions.map((tx) => (
                  <li key={tx.id} className="p-4 sm:px-6 hover:bg-zinc-50 transition-colors">
                    <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
                      <div className="flex items-center gap-3 flex-wrap">
                        <span className="font-mono text-sm font-medium text-zinc-900">{shortHash(tx.txHash)}</span>
                        <span
                          className={`inline-flex items-center rounded-md px-2 py-1 text-xs font-medium ring-1 ring-inset ${
                            tx.path === 'Sponsored'
                              ? 'bg-emerald-50 text-emerald-700 ring-emerald-600/20'
                              : tx.path === 'Private only'
                                ? 'bg-blue-50 text-blue-700 ring-blue-600/20'
                                : 'bg-zinc-50 text-zinc-700 ring-zinc-600/20'
                          }`}
                        >
                          {tx.path}
                        </span>
                        <span className="text-xs text-zinc-500">{formatRelativeTime(tx.submittedAt)}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-emerald-600">{formatUsd(tx.netToUserUsd)} net</span>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                      <div className="bg-zinc-50 rounded-lg p-3 ring-1 ring-zinc-200 text-sm">
                        <div className="text-zinc-500 mb-1 font-medium">Decision Reason</div>
                        <div className="text-zinc-900">{tx.reason}</div>
                      </div>
                      <div className="bg-zinc-50 rounded-lg p-3 ring-1 ring-zinc-200 text-sm grid grid-cols-3 gap-2">
                        <div>
                          <div className="text-zinc-500 mb-1">Gas Covered</div>
                          <div className="font-mono text-zinc-900">{formatUsd(tx.gasCoveredUsd)}</div>
                        </div>
                        <div>
                          <div className="text-zinc-500 mb-1">MEV Rebate</div>
                          <div className="font-mono text-emerald-600">{formatUsd(tx.mevRebateUsd)}</div>
                        </div>
                        <div>
                          <div className="text-zinc-500 mb-1">Net to User</div>
                          <div className="font-mono font-medium text-emerald-600">{formatUsd(tx.netToUserUsd)}</div>
                        </div>
                      </div>
                    </div>

                    <div className="relative">
                      <div className="absolute inset-0 flex items-center" aria-hidden="true">
                        <div className="w-full border-t border-zinc-200" />
                      </div>
                      <div className="relative flex justify-between">
                        {tx.timeline.map((step) => {
                          const Icon = step.status === 'done' ? CheckCircle2 : step.status === 'failed' ? XCircle : Clock;
                          const iconColor = step.status === 'done' ? 'text-emerald-500' : step.status === 'failed' ? 'text-red-500' : 'text-zinc-400';

                          return (
                            <div key={`${tx.id}-${step.step}`} className="flex flex-col items-center">
                              <span className="bg-white px-2">
                                <Icon className={`h-5 w-5 ${iconColor}`} aria-hidden="true" />
                              </span>
                              <span className="mt-2 text-xs font-medium text-zinc-900">{step.step}</span>
                              <span className="text-[10px] text-zinc-500">{step.time}</span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {activeTab === 'policy' && (
          <div className="bg-white rounded-xl p-6 ring-1 ring-zinc-200 space-y-5 text-sm">
            <div className="flex justify-between border-b border-zinc-200 pb-3">
              <span className="text-zinc-500">Retained Share</span>
              <span className="font-medium text-zinc-900">{((result?.data.policy.retainedBps ?? 1000) / 100).toFixed(1)}%</span>
            </div>
            <div className="flex justify-between border-b border-zinc-200 pb-3">
              <span className="text-zinc-500">Per-Tx Sponsorship Cap</span>
              <span className="font-medium text-zinc-900">{formatEth(result?.data.policy.perTxGasCapEth ?? 0.05, 4)}</span>
            </div>
            <div className="flex justify-between border-b border-zinc-200 pb-3">
              <span className="text-zinc-500">Per-Day Address Cap</span>
              <span className="font-medium text-zinc-900">{formatEth(result?.data.policy.perDayGasCapEth ?? 0.5, 4)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-zinc-500">Last Refresh</span>
              <span className="font-medium text-zinc-900">{result ? formatRelativeTime(result.data.generatedAt) : '--'}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
