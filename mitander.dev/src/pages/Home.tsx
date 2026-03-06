import { useMemo, useState } from 'react';
import {
  Activity,
  AlertCircle,
  ArrowRight,
  CheckCircle2,
  Coins,
  Copy,
  LoaderCircle,
  Server,
  ShieldCheck,
  Zap,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { motion } from 'motion/react';
import { APP_CONFIG, calculateSplit } from '../lib/publicData';
import { usePublicData } from '../hooks/usePublicData';
import { formatCompactNumber, formatEth, formatRelativeTime, formatUsd } from '../lib/formatters';

export function Home() {
  const [copied, setCopied] = useState(false);
  const [expectedMevUsd, setExpectedMevUsd] = useState(1000);
  const [gasCostUsd, setGasCostUsd] = useState(50);
  const { result, loading, error } = usePublicData();

  const policyBps = result?.data.policy.retainedBps ?? 1000;
  const breakdown = useMemo(
    () => calculateSplit(expectedMevUsd, gasCostUsd, policyBps),
    [expectedMevUsd, gasCostUsd, policyBps],
  );

  const stats = useMemo(() => {
    const data = result?.data;
    return [
      {
        id: 1,
        name: 'Sponsored tx count',
        value: data ? formatCompactNumber(data.stats.sponsoredTxCount) : '--',
        icon: Zap,
        context: 'rolling last 12 hours',
      },
      {
        id: 2,
        name: 'Gas refunded',
        value: data ? formatEth(data.stats.gasRefundedEth, 1) : '--',
        icon: Coins,
        context: 'last 12 hours',
      },
      {
        id: 3,
        name: 'Rebates returned',
        value: data ? formatUsd(data.stats.mevReturnedUsd, 0) : '--',
        icon: Activity,
        context: 'last 12 hours',
      },
      {
        id: 4,
        name: 'Avg inclusion time',
        value: data ? `${data.stats.avgInclusionSeconds.toFixed(3)}s` : '--',
        icon: Server,
        context: 'updates every 2 min',
      },
    ];
  }, [result]);

  const copyRpc = async () => {
    try {
      await navigator.clipboard.writeText(APP_CONFIG.rpcUrl);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };

  const activity = result?.data.activity ?? [];
  const publicDataDegraded = result?.source === 'degraded';

  return (
    <div className="bg-page">
      <div className="relative isolate pt-14">
        <div className="py-24 sm:py-32 lg:pb-40">
          <div className="mx-auto max-w-7xl px-6 lg:px-8">
            <div className="mx-auto max-w-2xl text-center">
              <motion.h1
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5 }}
                className="text-4xl font-semibold tracking-tight text-zinc-900 sm:text-6xl"
              >
                Private Ethereum execution that can cover gas and return real value.
              </motion.h1>
              <motion.p
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.1 }}
                className="mt-6 text-lg leading-8 text-zinc-600"
              >
                Send Ethereum transactions through private routing instead of the public mempool path. Mitander simulates each flow, applies risk and value
                policy for gas coverage eligibility, reduces avoidable MEV exposure, and reports exact settlement values your users can trust.
              </motion.p>
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.2 }}
                className="mt-10 flex items-center justify-center gap-x-6"
              >
                <button
                  onClick={copyRpc}
                  className="rounded-lg bg-zinc-900 px-5 py-3 text-sm font-semibold text-white shadow-sm hover:bg-zinc-800 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-900 flex items-center gap-2 transition-all"
                >
                  {copied ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                  {copied ? 'Copied RPC URL' : 'Copy Private RPC'}
                </button>
                <Link
                  to="/dashboard"
                  className="text-sm font-semibold leading-6 text-zinc-900 flex items-center gap-1 hover:text-zinc-600 transition-colors"
                >
                  View Dashboard <ArrowRight className="w-4 h-4" />
                </Link>
              </motion.div>
            </div>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.3 }}
              className="mt-16 flex justify-center"
            >
              <div className="rounded-xl bg-white p-2 shadow-sm ring-1 ring-zinc-200 flex items-center gap-4 max-w-md w-full">
                <div className="bg-zinc-100 rounded-lg p-2 text-zinc-500">
                  <Server className="w-5 h-5" />
                </div>
                <code className="text-sm font-mono text-zinc-800 flex-1">{APP_CONFIG.rpcUrl}</code>
                <button
                  onClick={copyRpc}
                  className="p-2 text-zinc-400 hover:text-zinc-900 transition-colors"
                  title="Copy RPC URL"
                >
                  {copied ? <CheckCircle2 className="w-5 h-5 text-emerald-500" /> : <Copy className="w-5 h-5" />}
                </button>
              </div>
            </motion.div>
          </div>
        </div>
      </div>

      <div className="mx-auto max-w-7xl px-6 lg:px-8 pb-24">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {stats.map((stat) => (
            <div key={stat.id} className="bg-white rounded-2xl p-6 shadow-sm ring-1 ring-zinc-200">
              <div className="flex items-center gap-3 text-zinc-500 mb-4">
                <stat.icon className="w-5 h-5" />
                <div>
                  <h3 className="text-sm font-medium">{stat.name}</h3>
                  <p className="text-xs text-zinc-400/90">{stat.context}</p>
                </div>
              </div>
              <p className="text-3xl font-light tracking-tight text-zinc-900">{stat.value}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="mx-auto max-w-7xl px-6 lg:px-8 pb-24">
        <div className="rounded-2xl bg-white p-8 shadow-sm ring-1 ring-zinc-200">
          <h2 className="text-2xl font-semibold tracking-tight text-zinc-900">
            Ethereum MEV Protection and Gasless Transaction Infrastructure
          </h2>
          <p className="mt-4 text-base leading-7 text-zinc-600">
            Mitander is designed for wallets, dApps, and searchers that need private Ethereum execution with predictable outcomes.
            Use it as a private mempool entrypoint, a conditional gas-coverage rail for eligible users, and a transparent execution rebate layer that turns
            transaction flow into measurable user value.
          </p>
          <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-3">
            <div className="rounded-xl border border-zinc-200 bg-zinc-50 p-4">
              <h3 className="text-sm font-semibold text-zinc-900">Private RPC for Ethereum</h3>
              <p className="mt-2 text-sm text-zinc-600">
                Keep transactions off public mempool paths to reduce sandwich and generalized frontrun risk.
              </p>
            </div>
            <div className="rounded-xl border border-zinc-200 bg-zinc-50 p-4">
              <h3 className="text-sm font-semibold text-zinc-900">Conditional Gas Coverage</h3>
              <p className="mt-2 text-sm text-zinc-600">
                Pre-trade simulation and policy checks determine whether gas can be covered or refunded for a flow.
              </p>
            </div>
            <div className="rounded-xl border border-zinc-200 bg-zinc-50 p-4">
              <h3 className="text-sm font-semibold text-zinc-900">Transparent Rebate Ledger</h3>
              <p className="mt-2 text-sm text-zinc-600">
                Dashboard records show gas coverage, retained share, and rebate amounts for each transaction.
              </p>
            </div>
          </div>
          <div className="mt-6 flex flex-wrap gap-4 text-sm font-medium">
            <Link to="/how-it-works" className="text-zinc-900 hover:text-zinc-600">
              Learn private execution flow <span aria-hidden>→</span>
            </Link>
            <Link to="/developers" className="text-zinc-900 hover:text-zinc-600">
              Read Ethereum RPC docs <span aria-hidden>→</span>
            </Link>
            <Link to="/partners" className="text-zinc-900 hover:text-zinc-600">
              Request partner integration <span aria-hidden>→</span>
            </Link>
          </div>
        </div>
      </div>

      <div className="mx-auto max-w-7xl px-6 lg:px-8 pb-24">
        <div className="rounded-2xl bg-white p-8 shadow-sm ring-1 ring-zinc-200">
          <h2 className="text-2xl font-semibold tracking-tight text-zinc-900">Deep Dive Guides</h2>
          <p className="mt-3 text-sm leading-7 text-zinc-600">
            Explore focused guides for private Ethereum RPC infrastructure, conditional gasless transaction policy, and practical MEV protection patterns.
          </p>
          <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-3">
            <Link
              to="/private-ethereum-rpc"
              className="rounded-xl border border-zinc-200 bg-zinc-50 p-4 transition-colors hover:bg-zinc-100"
            >
              <h3 className="text-sm font-semibold text-zinc-900">Private Ethereum RPC</h3>
              <p className="mt-2 text-sm text-zinc-600">
                Endpoint model, private orderflow routing, and integration checklist for production traffic.
              </p>
            </Link>
            <Link
              to="/gasless-ethereum-transactions"
              className="rounded-xl border border-zinc-200 bg-zinc-50 p-4 transition-colors hover:bg-zinc-100"
            >
              <h3 className="text-sm font-semibold text-zinc-900">Gasless Ethereum Transactions</h3>
              <p className="mt-2 text-sm text-zinc-600">
                How coverage eligibility is decided, how fallback works, and how settlement values are accounted.
              </p>
            </Link>
            <Link
              to="/mev-protection"
              className="rounded-xl border border-zinc-200 bg-zinc-50 p-4 transition-colors hover:bg-zinc-100"
            >
              <h3 className="text-sm font-semibold text-zinc-900">Ethereum MEV Protection</h3>
              <p className="mt-2 text-sm text-zinc-600">
                Risk surface breakdown and mitigation workflow for sandwich and frontrun reduction.
              </p>
            </Link>
          </div>
        </div>
      </div>

      <div className="bg-white py-24 sm:py-32 border-y border-zinc-200">
        <div className="mx-auto max-w-7xl px-6 lg:px-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-16">
            <div>
              <h2 className="text-2xl font-semibold tracking-tight text-zinc-900 mb-6">Split Estimator</h2>
              <div className="bg-zinc-50 rounded-2xl p-8 ring-1 ring-zinc-200">
                <div className="space-y-5">
                  <label className="block text-sm font-medium text-zinc-700">
                    Expected MEV Value (USD)
                    <input
                      id="split-estimator-expected-mev-usd"
                      name="split_estimator_expected_mev_usd"
                      type="number"
                      min={0}
                      step={1}
                      value={expectedMevUsd}
                      onChange={(event) => setExpectedMevUsd(Number(event.target.value) || 0)}
                      className="mt-2 w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-zinc-900"
                    />
                  </label>
                  <label className="block text-sm font-medium text-zinc-700">
                    Estimated Gas Cost (USD)
                    <input
                      id="split-estimator-estimated-gas-usd"
                      name="split_estimator_estimated_gas_usd"
                      type="number"
                      min={0}
                      step={1}
                      value={gasCostUsd}
                      onChange={(event) => setGasCostUsd(Number(event.target.value) || 0)}
                      className="mt-2 w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-zinc-900"
                    />
                  </label>
                </div>

                <div className="mt-8 space-y-4 border-t border-zinc-200 pt-6 text-sm">
                  <div className="flex justify-between">
                    <span className="text-zinc-500">Gross MEV</span>
                    <span className="font-mono text-zinc-900">{formatUsd(breakdown.gross)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-zinc-500">Gas Sponsored</span>
                    <span className="font-mono text-zinc-900">{formatUsd(breakdown.gas)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-zinc-500">Mitander Retained ({(policyBps / 100).toFixed(1)}%)</span>
                    <span className="font-mono text-zinc-900">{formatUsd(breakdown.retained)}</span>
                  </div>
                  <div className="flex justify-between border-t border-zinc-200 pt-4">
                    <span className="font-medium text-zinc-900">User Rebate</span>
                    <span className="font-mono font-medium text-emerald-600">{formatUsd(breakdown.rebate)}</span>
                  </div>
                </div>

                <div className="mt-6 rounded-lg border border-zinc-200 bg-white p-4 text-sm text-zinc-600">
                  <span className="font-medium text-zinc-900">Decision:</span>{' '}
                  {breakdown.sponsored
                    ? 'Sponsored path is eligible with the current assumptions.'
                    : 'Falls back to private-only path because net MEV does not cover gas.'}
                </div>
              </div>
            </div>

            <div>
              <h2 className="text-2xl font-semibold tracking-tight text-zinc-900 mb-6">Transparent policy behavior</h2>
              <div className="space-y-4">
                {[
                  {
                    title: 'Eligible Gas Coverage',
                    desc: 'Transactions can qualify for gas coverage based on simulation output and policy constraints.',
                  },
                  {
                    title: 'Always Private',
                    desc: 'Non-sponsored traffic still goes through private relay routing to reduce exposure.',
                  },
                  {
                    title: 'Transparent Settlement',
                    desc: 'Each transaction records gas, retained share, and user rebate as separate ledger fields.',
                  },
                  {
                    title: 'Fixed Policy Share',
                    desc: `Retained share is fixed at ${(policyBps / 100).toFixed(1)}% of net MEV after gas.`,
                  },
                ].map((policy) => (
                  <div key={policy.title} className="flex gap-4 p-4 rounded-xl hover:bg-zinc-50 transition-colors">
                    <div className="mt-1">
                      <ShieldCheck className="w-5 h-5 text-emerald-600" />
                    </div>
                    <div>
                      <h3 className="font-medium text-zinc-900">{policy.title}</h3>
                      <p className="mt-1 text-sm text-zinc-600">{policy.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
              <div className="mt-6">
                <Link to="/risk-policy" className="text-sm font-medium text-zinc-900 hover:text-zinc-600 flex items-center gap-1">
                  Read full Risk Policy <ArrowRight className="w-4 h-4" />
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="mx-auto max-w-7xl px-6 lg:px-8 py-24">
        <div className="flex items-center justify-between mb-8">
          <h2 className="text-2xl font-semibold tracking-tight text-zinc-900">Live Activity</h2>
          <div className="flex items-center gap-2 text-sm text-zinc-500 font-medium">
            {loading ? (
              <>
                <LoaderCircle className="w-4 h-4 animate-spin" />
                Refreshing
              </>
            ) : publicDataDegraded ? (
              <>
                <AlertCircle className="w-4 h-4 text-amber-500" />
                Degraded
              </>
            ) : (
              <>
                <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                Live
              </>
            )}
          </div>
        </div>

        <div className="bg-white rounded-2xl shadow-sm ring-1 ring-zinc-200 overflow-hidden">
          {publicDataDegraded && (
            <div className="border-b border-amber-200 bg-amber-50 px-6 py-4 text-sm text-amber-800">
              {error || 'Live telemetry is currently unavailable or too sparse to publish publicly.'}
            </div>
          )}
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-zinc-200">
              <thead className="bg-zinc-50">
                <tr>
                  <th scope="col" className="px-3 py-3.5 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">
                    Path
                  </th>
                  <th scope="col" className="px-3 py-3.5 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">
                    Net to User
                  </th>
                  <th scope="col" className="px-3 py-3.5 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th scope="col" className="px-3 py-3.5 text-right text-xs font-medium text-zinc-500 uppercase tracking-wider sm:pr-6">
                    Time
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-200 bg-white">
                {activity.map((tx) => (
                  <tr key={tx.id} className="hover:bg-zinc-50 transition-colors">
                    <td className="whitespace-nowrap px-3 py-4 text-sm">
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
                    </td>
                    <td className="whitespace-nowrap px-3 py-4 text-sm font-mono text-emerald-600 font-medium">
                      {formatUsd(tx.netToUserUsd)}
                    </td>
                    <td className="whitespace-nowrap px-3 py-4 text-sm text-zinc-500">{tx.status}</td>
                    <td className="whitespace-nowrap px-3 py-4 text-sm text-zinc-500 text-right sm:pr-6">
                      {formatRelativeTime(tx.timestamp)}
                    </td>
                  </tr>
                ))}
                {activity.length === 0 && !loading && (
                  <tr>
                    <td colSpan={4} className="px-6 py-8 text-center text-sm text-zinc-500">
                      No public activity is currently available.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="mx-auto max-w-7xl px-6 lg:px-8 pb-24">
        <div className="rounded-2xl bg-white p-8 shadow-sm ring-1 ring-zinc-200">
          <h2 className="text-2xl font-semibold tracking-tight text-zinc-900">FAQ: MEV, Gasless, and Private RPC</h2>
          <dl className="mt-6 space-y-6">
            <div>
              <dt className="text-base font-semibold text-zinc-900">Is this a gasless Ethereum transaction service?</dt>
              <dd className="mt-2 text-sm leading-7 text-zinc-600">
                It is conditional. Mitander can cover or refund gas for eligible transactions after simulation and policy checks.
              </dd>
            </div>
            <div>
              <dt className="text-base font-semibold text-zinc-900">Does private RPC reduce MEV risk?</dt>
              <dd className="mt-2 text-sm leading-7 text-zinc-600">
                Private routing helps reduce public mempool exposure, lowering common frontrun and sandwich surfaces.
              </dd>
            </div>
            <div>
              <dt className="text-base font-semibold text-zinc-900">Can wallets and dApps integrate this quickly?</dt>
              <dd className="mt-2 text-sm leading-7 text-zinc-600">
                Yes. Use the developer docs for RPC behavior and policy constraints, then onboard through the partner program.
              </dd>
            </div>
          </dl>
        </div>
      </div>
    </div>
  );
}
