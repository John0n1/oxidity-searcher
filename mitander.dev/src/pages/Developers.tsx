import { useState } from 'react';
import { AlertTriangle, BookOpen, CheckCircle2, Code, Copy, ShieldCheck, Terminal } from 'lucide-react';
import { Link } from 'react-router-dom';
import { APP_CONFIG } from '../lib/publicData';

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  return (
    <button
      onClick={async () => {
        await navigator.clipboard.writeText(text);
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1500);
      }}
      className="inline-flex items-center gap-2 rounded-md border border-zinc-300 bg-white px-3 py-1.5 text-xs font-medium text-zinc-700 hover:bg-zinc-50"
    >
      {copied ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  );
}

export function Developers() {
  return (
    <div className="bg-page min-h-screen py-12">
      <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8">
        <div className="mb-12">
          <h1 className="text-3xl font-bold tracking-tight text-zinc-900">Developer Documentation</h1>
          <p className="mt-4 text-lg text-zinc-600">
            Private Ethereum RPC ingress built for teams that want better execution quality, policy-based gas coverage, and transparent settlement telemetry.
          </p>
          <div className="mt-4 flex flex-wrap gap-4 text-sm font-medium">
            <Link to="/private-ethereum-rpc" className="text-zinc-900 hover:text-zinc-600">
              Private RPC architecture <span aria-hidden>→</span>
            </Link>
            <Link to="/gasless-ethereum-transactions" className="text-zinc-900 hover:text-zinc-600">
              Conditional gas coverage model <span aria-hidden>→</span>
            </Link>
            <Link to="/mev-protection" className="text-zinc-900 hover:text-zinc-600">
              MEV protection model <span aria-hidden>→</span>
            </Link>
          </div>
        </div>

        <div className="space-y-12">
          <section className="bg-white rounded-2xl p-8 shadow-sm ring-1 ring-zinc-200">
            <div className="flex items-center gap-3 mb-6">
              <Terminal className="w-6 h-6 text-zinc-900" />
              <h2 className="text-xl font-semibold text-zinc-900">RPC Endpoint</h2>
            </div>
            <div className="rounded-xl border border-zinc-200 bg-zinc-50 p-4 flex items-center justify-between gap-4">
              <code className="text-sm font-mono text-zinc-800 break-all">{APP_CONFIG.rpcUrl}</code>
              <CopyButton text={APP_CONFIG.rpcUrl} />
            </div>
            <p className="mt-4 text-sm text-zinc-600">
              JSON-RPC over HTTP `POST`. `eth_sendRawTransaction` goes through private bundle routing, while a strict safe-read allowlist is proxied to upstream chain RPC. Production access is server-to-server only and requires a partner-issued bearer token plus network allowlisting.
            </p>
            <p className="mt-2 text-sm text-zinc-600">
              Health endpoint: <code className="font-mono text-zinc-800">GET {APP_CONFIG.rpcUrl.replace(/\/$/, '')}/health</code>
            </p>
          </section>

          <section className="bg-white rounded-2xl p-8 shadow-sm ring-1 ring-zinc-200">
            <div className="flex items-center gap-3 mb-6">
              <Code className="w-6 h-6 text-zinc-900" />
              <h2 className="text-xl font-semibold text-zinc-900">Supported RPC Methods</h2>
            </div>

            <div className="overflow-hidden shadow ring-1 ring-black ring-opacity-5 sm:rounded-lg">
              <table className="min-w-full divide-y divide-zinc-300">
                <thead className="bg-zinc-50">
                  <tr>
                    <th className="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-zinc-900">Method</th>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-zinc-900">Params</th>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-zinc-900">Result</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-200 bg-white text-sm">
                  <tr>
                    <td className="whitespace-nowrap py-4 pl-4 pr-3 font-mono text-zinc-900">eth_sendRawTransaction</td>
                    <td className="px-3 py-4 text-zinc-600">Single signed raw transaction hex payload in `params[0]`.</td>
                    <td className="px-3 py-4 text-zinc-600">Transaction hash string.</td>
                  </tr>
                  <tr>
                    <td className="whitespace-nowrap py-4 pl-4 pr-3 font-mono text-zinc-900">eth_chainId</td>
                    <td className="px-3 py-4 text-zinc-600">No params required.</td>
                    <td className="px-3 py-4 text-zinc-600">Chain ID as hex string.</td>
                  </tr>
                  <tr>
                    <td className="whitespace-nowrap py-4 pl-4 pr-3 font-mono text-zinc-900">net_version</td>
                    <td className="px-3 py-4 text-zinc-600">No params required.</td>
                    <td className="px-3 py-4 text-zinc-600">Chain ID as decimal string.</td>
                  </tr>
                  <tr>
                    <td className="whitespace-nowrap py-4 pl-4 pr-3 font-mono text-zinc-900">web3_clientVersion</td>
                    <td className="px-3 py-4 text-zinc-600">No params required.</td>
                    <td className="px-3 py-4 text-zinc-600">Gateway client version string.</td>
                  </tr>
                  <tr>
                    <td className="whitespace-nowrap py-4 pl-4 pr-3 font-mono text-zinc-900">safe read passthrough</td>
                    <td className="px-3 py-4 text-zinc-600">
                      Supported methods: `eth_blockNumber`, `eth_getBlock*`, `eth_getTransaction*`, `eth_getBalance`, `eth_getCode`,
                      `eth_getStorageAt`, `eth_getTransactionCount`, `eth_call`, `eth_estimateGas`, `eth_gasPrice`,
                      `eth_feeHistory`, `eth_maxPriorityFeePerGas`, `eth_getLogs`, `eth_syncing`.
                    </td>
                    <td className="px-3 py-4 text-zinc-600">Upstream JSON-RPC result/error passthrough.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section className="bg-white rounded-2xl p-8 shadow-sm ring-1 ring-zinc-200">
            <div className="flex items-center gap-3 mb-6">
              <ShieldCheck className="w-6 h-6 text-zinc-900" />
              <h2 className="text-xl font-semibold text-zinc-900">Access, Auth, and Limits</h2>
            </div>

            <div className="overflow-hidden shadow ring-1 ring-black ring-opacity-5 sm:rounded-lg">
              <table className="min-w-full divide-y divide-zinc-300">
                <thead className="bg-zinc-50">
                  <tr>
                    <th className="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-zinc-900">Surface</th>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-zinc-900">Auth</th>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-zinc-900">Behavior</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-200 bg-white text-sm">
                  <tr>
                    <td className="whitespace-nowrap py-4 pl-4 pr-3 font-mono text-zinc-900">/rpc</td>
                    <td className="px-3 py-4 text-zinc-600">`Authorization: Bearer &lt;partner token&gt;` plus approved source CIDR.</td>
                    <td className="px-3 py-4 text-zinc-600">Method allowlist, per-method budgets, and server-side rate limits enforced at the gateway and app layers.</td>
                  </tr>
                  <tr>
                    <td className="whitespace-nowrap py-4 pl-4 pr-3 font-mono text-zinc-900">/api/public/summary</td>
                    <td className="px-3 py-4 text-zinc-600">No auth.</td>
                    <td className="px-3 py-4 text-zinc-600">Public telemetry stream for high-level stats, services, and redacted recent activity only.</td>
                  </tr>
                  <tr>
                    <td className="whitespace-nowrap py-4 pl-4 pr-3 font-mono text-zinc-900">/api/partner/summary</td>
                    <td className="px-3 py-4 text-zinc-600">`Authorization: Bearer &lt;token&gt;`</td>
                    <td className="px-3 py-4 text-zinc-600">Partner-tier detail including transaction-level ledger and policy outcomes.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section className="bg-white rounded-2xl p-8 shadow-sm ring-1 ring-zinc-200">
            <div className="flex items-center gap-3 mb-6">
              <BookOpen className="w-6 h-6 text-zinc-900" />
              <h2 className="text-xl font-semibold text-zinc-900">Decision Paths and Settlement Fields</h2>
            </div>

            <div className="overflow-hidden shadow ring-1 ring-black ring-opacity-5 sm:rounded-lg">
              <table className="min-w-full divide-y divide-zinc-300">
                <thead className="bg-zinc-50">
                  <tr>
                    <th className="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-zinc-900">Path</th>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-zinc-900">Meaning</th>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-zinc-900">Ledger Impact</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-200 bg-white text-sm">
                  <tr>
                    <td className="whitespace-nowrap py-4 pl-4 pr-3 font-medium text-zinc-900">Sponsored</td>
                    <td className="px-3 py-4 text-zinc-600">Eligible for policy-based gas coverage under current simulation/risk envelope.</td>
                    <td className="px-3 py-4 text-zinc-600">`gasCovered*` and/or `gasRefunded*` can be non-zero.</td>
                  </tr>
                  <tr>
                    <td className="whitespace-nowrap py-4 pl-4 pr-3 font-medium text-zinc-900">Private only</td>
                    <td className="px-3 py-4 text-zinc-600">Privately routed with no guaranteed gas coverage.</td>
                    <td className="px-3 py-4 text-zinc-600">Coverage fields may be zero while rebate/retained can still apply.</td>
                  </tr>
                  <tr>
                    <td className="whitespace-nowrap py-4 pl-4 pr-3 font-medium text-zinc-900">Pass-through</td>
                    <td className="px-3 py-4 text-zinc-600">Conservative fallback path with minimal intervention.</td>
                    <td className="px-3 py-4 text-zinc-600">Typically low or zero settlement distribution values.</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div className="mt-6 rounded-lg border border-zinc-200 bg-zinc-50 p-4 text-sm text-zinc-600">
              Partner summaries expose ledger fields including `gasCoveredUsd`, `gasRefundedUsd`, `retainedUsd`, `rebateUsd`, and user-net totals for dashboard reconciliation. Public summaries omit transaction hashes and ledger payloads.
            </div>
          </section>

          <section className="bg-white rounded-2xl p-8 shadow-sm ring-1 ring-zinc-200">
            <div className="flex items-center gap-3 mb-6">
              <AlertTriangle className="w-6 h-6 text-zinc-900" />
              <h2 className="text-xl font-semibold text-zinc-900">Error Codes</h2>
            </div>
            <div className="overflow-hidden shadow ring-1 ring-black ring-opacity-5 sm:rounded-lg">
              <table className="min-w-full divide-y divide-zinc-300">
                <thead className="bg-zinc-50">
                  <tr>
                    <th className="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-zinc-900">Code</th>
                    <th className="px-3 py-3.5 text-left text-sm font-semibold text-zinc-900">Description</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-200 bg-white">
                  <tr>
                    <td className="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-mono text-zinc-900">-32700</td>
                    <td className="px-3 py-4 text-sm text-zinc-500">Parse error in JSON request body.</td>
                  </tr>
                  <tr>
                    <td className="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-mono text-zinc-900">-32601</td>
                    <td className="px-3 py-4 text-sm text-zinc-500">Method not found or not allowed.</td>
                  </tr>
                  <tr>
                    <td className="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-mono text-zinc-900">-32602</td>
                    <td className="px-3 py-4 text-sm text-zinc-500">Invalid parameters for requested method.</td>
                  </tr>
                  <tr>
                    <td className="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-mono text-zinc-900">-32000</td>
                    <td className="px-3 py-4 text-sm text-zinc-500">Private submission failure from upstream relay/provider path.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section className="bg-white rounded-2xl p-8 shadow-sm ring-1 ring-zinc-200">
            <h2 className="text-xl font-semibold text-zinc-900">Policy and Legal</h2>
            <p className="mt-3 text-sm text-zinc-600">
              Integration is subject to operational policy and service terms. Review both before going to production.
            </p>
            <div className="mt-4 flex flex-wrap gap-4 text-sm font-medium">
              <Link to="/risk-policy" className="text-zinc-900 hover:text-zinc-600">
                Risk Policy <span aria-hidden>→</span>
              </Link>
              <Link to="/terms" className="text-zinc-900 hover:text-zinc-600">
                Terms of Service <span aria-hidden>→</span>
              </Link>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
