import { useState } from 'react';
import { AlertTriangle, BookOpen, CheckCircle2, Code, Copy, LockKeyhole, ShieldCheck, Terminal } from 'lucide-react';
import { Link } from 'react-router-dom';
import { APP_CONFIG } from '../lib/publicData';

const developerPaths = [
  {
    title: 'Understand the flow',
    description: 'Use the docs to understand private routing, sponsorship decisions, and what the integration changes in your product.',
  },
  {
    title: 'Try the integration',
    description: 'Request staging or preview access when you are ready to validate auth, CIDR policy, and summary behavior with real calls.',
  },
  {
    title: 'Move with confidence',
    description: 'Production access is partner-issued and structured around bearer auth, approved source ranges, and rate budgets.',
  },
];

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
          <p className="text-sm font-semibold uppercase tracking-[0.18em] text-emerald-700">Developer documentation</p>
          <h1 className="mt-4 text-4xl font-semibold tracking-tight text-zinc-900">Everything you need to start building with Oxidity</h1>
          <p className="mt-4 text-lg leading-8 text-zinc-600">
            Start here if you are evaluating the RPC, mapping the private-routing flow, or getting a team integration ready. Oxidity is designed for
            server-side Ethereum execution with optional sponsorship and partner-friendly reporting.
          </p>
          <div className="mt-5 flex flex-wrap gap-4 text-sm font-medium">
            <Link to="/pricing" className="text-zinc-900 hover:text-zinc-600">
              Pricing and packaging <span aria-hidden>→</span>
            </Link>
            <Link to="/partners?requested=docs" className="text-zinc-900 hover:text-zinc-600">
              Teams and onboarding <span aria-hidden>→</span>
            </Link>
            <Link to="/proof" className="text-zinc-900 hover:text-zinc-600">
              Proof and diligence <span aria-hidden>→</span>
            </Link>
            <Link to="/private-ethereum-rpc" className="text-zinc-900 hover:text-zinc-600">
              Private RPC architecture <span aria-hidden>→</span>
            </Link>
          </div>
        </div>

        <section className="mb-12 grid grid-cols-1 gap-4 md:grid-cols-3">
          {developerPaths.map((path) => (
            <article key={path.title} className="rounded-2xl bg-white p-6 shadow-sm ring-1 ring-zinc-200">
              <h2 className="text-lg font-semibold text-zinc-900">{path.title}</h2>
              <p className="mt-3 text-sm leading-6 text-zinc-600">{path.description}</p>
            </article>
          ))}
        </section>

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
              JSON-RPC over HTTP `POST`. `eth_sendRawTransaction` is routed through private submission infrastructure, while a safe read-method set is
              proxied to upstream chain RPC. Production access is server-side and uses a partner-issued bearer token plus approved source CIDRs.
            </p>
            <div className="mt-4 rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-800">
              Oxidity is built for protected server-side integrations. If you are still exploring from a wallet, browser, or prototype context, start
              with the docs and onboarding path and we will point you toward the right setup.
            </div>
            <p className="mt-3 text-sm text-zinc-600">
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
                    <td className="px-3 py-4 text-zinc-600">Upstream JSON-RPC result or error passthrough.</td>
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
                    <td className="px-3 py-4 text-zinc-600">Method allowlist, per-method budgets, and server-side rate limits at both gateway and app layer.</td>
                  </tr>
                  <tr>
                    <td className="whitespace-nowrap py-4 pl-4 pr-3 font-mono text-zinc-900">/api/public/summary</td>
                    <td className="px-3 py-4 text-zinc-600">No auth.</td>
                    <td className="px-3 py-4 text-zinc-600">High-level public telemetry only. Transaction hashes and detailed ledger fields are removed.</td>
                  </tr>
                  <tr>
                    <td className="whitespace-nowrap py-4 pl-4 pr-3 font-mono text-zinc-900">/api/partner/summary</td>
                    <td className="px-3 py-4 text-zinc-600">`Authorization: Bearer &lt;token&gt;`</td>
                    <td className="px-3 py-4 text-zinc-600">Partner-tier detail including transaction-level ledger and path reporting.</td>
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
                    <td className="px-3 py-4 text-zinc-600">Eligible for policy-based gas sponsorship under the current simulation and risk envelope.</td>
                    <td className="px-3 py-4 text-zinc-600">`gasCovered*` and/or `gasRefunded*` can be non-zero.</td>
                  </tr>
                  <tr>
                    <td className="whitespace-nowrap py-4 pl-4 pr-3 font-medium text-zinc-900">Private only</td>
                    <td className="px-3 py-4 text-zinc-600">Privately routed with no guaranteed gas sponsorship.</td>
                    <td className="px-3 py-4 text-zinc-600">Coverage fields may be zero while rebate and retained values can still apply.</td>
                  </tr>
                  <tr>
                    <td className="whitespace-nowrap py-4 pl-4 pr-3 font-medium text-zinc-900">Pass-through</td>
                    <td className="px-3 py-4 text-zinc-600">Conservative fallback path with minimal intervention.</td>
                    <td className="px-3 py-4 text-zinc-600">Typically low or zero distribution values.</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div className="mt-6 rounded-lg border border-zinc-200 bg-zinc-50 p-4 text-sm text-zinc-600">
              Partner summaries expose ledger fields such as `gasCoveredUsd`, `gasRefundedUsd`, `retainedUsd`, `rebateUsd`, and user-net totals for
              reconciliation. Public summaries omit transaction hashes and detailed ledger payloads.
            </div>
          </section>

          <section className="bg-white rounded-2xl p-8 shadow-sm ring-1 ring-zinc-200">
            <div className="flex items-center gap-3 mb-6">
              <LockKeyhole className="w-6 h-6 text-zinc-900" />
              <h2 className="text-xl font-semibold text-zinc-900">Before you integrate</h2>
            </div>
            <ul className="space-y-3 text-sm leading-6 text-zinc-700">
              <li>Plan on server-side usage rather than a browser-callable public endpoint.</li>
              <li>Expect production access to use bearer auth, source-network policy, and rate limits.</li>
              <li>Treat `sponsored`, `private-only`, and `pass-through` as distinct outcomes in your analytics and UX.</li>
              <li>Use the partner onboarding path when you want staging or production traffic, not just documentation.</li>
            </ul>
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
                    <td className="px-3 py-4 text-sm text-zinc-500">Private submission failure from upstream relay or provider path.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section className="bg-white rounded-2xl p-8 shadow-sm ring-1 ring-zinc-200">
            <h2 className="text-xl font-semibold text-zinc-900">Policy and legal</h2>
            <p className="mt-3 text-sm text-zinc-600">
              Integration is subject to operational policy and service terms. Review both before routing production traffic through the gateway.
            </p>
            <div className="mt-4 flex flex-wrap gap-4 text-sm font-medium">
              <Link to="/risk-policy" className="text-zinc-900 hover:text-zinc-600">
                Risk policy <span aria-hidden>→</span>
              </Link>
              <Link to="/pricing" className="text-zinc-900 hover:text-zinc-600">
                Pricing and packaging <span aria-hidden>→</span>
              </Link>
              <Link to="/partners?requested=staging" className="text-zinc-900 hover:text-zinc-600">
                Request staging access <span aria-hidden>→</span>
              </Link>
              <Link to="/terms" className="text-zinc-900 hover:text-zinc-600">
                Terms of service <span aria-hidden>→</span>
              </Link>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
