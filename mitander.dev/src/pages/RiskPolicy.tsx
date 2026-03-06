import { ShieldAlert, FileText, Ban, AlertTriangle } from 'lucide-react';

export function RiskPolicy() {
  return (
    <div className="bg-page min-h-screen py-12">
      <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8">
        <div className="mb-12">
          <h1 className="text-3xl font-bold tracking-tight text-zinc-900 flex items-center gap-3">
            <ShieldAlert className="w-8 h-8 text-zinc-900" />
            Risk Policy & Exclusions
          </h1>
          <p className="mt-4 text-lg text-zinc-600">
            Clear rules, caps, and exclusions for gas coverage and execution rebates.
          </p>
        </div>

        <div className="space-y-12">
          
          <section className="bg-white rounded-2xl p-8 shadow-sm ring-1 ring-zinc-200">
            <div className="flex items-center gap-3 mb-6">
              <FileText className="w-6 h-6 text-zinc-900" />
              <h2 className="text-xl font-semibold text-zinc-900">Eligibility Requirements</h2>
            </div>
            <div className="prose prose-zinc max-w-none text-zinc-600">
              <p>
                To be eligible for gas coverage, a transaction must meet the following criteria during simulation:
              </p>
              <ul className="list-disc pl-5 space-y-2 mt-4">
                <li><strong>Profitability:</strong> The simulated backrun must generate a net profit greater than the user's gas cost plus the Mitander 10% retained share.</li>
                <li><strong>Deterministic Execution:</strong> The transaction must not rely on highly volatile state that frequently causes simulation divergence.</li>
                <li><strong>Gas Limit:</strong> The transaction's gas limit must not exceed 2,000,000 gas.</li>
              </ul>
            </div>
          </section>

          <section className="bg-white rounded-2xl p-8 shadow-sm ring-1 ring-zinc-200">
            <div className="flex items-center gap-3 mb-6">
              <AlertTriangle className="w-6 h-6 text-zinc-900" />
              <h2 className="text-xl font-semibold text-zinc-900">Max Gas Caps</h2>
            </div>
            <div className="prose prose-zinc max-w-none text-zinc-600">
              <p>
                To protect our treasury and ensure fair usage, we enforce the following caps:
              </p>
              <ul className="list-disc pl-5 space-y-2 mt-4">
                <li><strong>Per-Transaction Cap:</strong> Maximum coverage of 0.05 ETH per transaction.</li>
                <li><strong>Per-User Daily Cap:</strong> Maximum coverage of 0.5 ETH per sender address per 24 hours.</li>
                <li><strong>API Key Tier Caps:</strong> Developer API keys have monthly coverage caps based on their subscription tier.</li>
              </ul>
              <div className="mt-6 bg-amber-50 rounded-lg p-4 ring-1 ring-amber-200 text-sm text-amber-800 flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
                <p>If a cap is reached, the transaction will fallback to the "Private only" path. It can still be protected from front-running, but gas will not be covered.</p>
              </div>
            </div>
          </section>

          <section className="bg-white rounded-2xl p-8 shadow-sm ring-1 ring-zinc-200">
            <div className="flex items-center gap-3 mb-6">
              <Ban className="w-6 h-6 text-zinc-900" />
              <h2 className="text-xl font-semibold text-zinc-900">Excluded Conditions</h2>
            </div>
            <div className="prose prose-zinc max-w-none text-zinc-600">
              <p>
                Transactions interacting with the following are explicitly excluded from coverage (error code <code>NOT_ELIGIBLE_RISK</code>):
              </p>
              <ul className="list-disc pl-5 space-y-2 mt-4">
                <li><strong>High-Tax Tokens:</strong> Tokens with transfer taxes exceeding 5%.</li>
                <li><strong>Low Liquidity Pools:</strong> DEX pools with less than $50,000 in TVL.</li>
                <li><strong>Known Malicious Contracts:</strong> Addresses flagged by our security partners as associated with scams or exploits.</li>
                <li><strong>Complex Proxies:</strong> Contracts with deeply nested or non-standard proxy patterns that prevent accurate simulation.</li>
              </ul>
            </div>
          </section>

        </div>
      </div>
    </div>
  );
}
