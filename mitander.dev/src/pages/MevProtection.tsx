import { Link } from 'react-router-dom';
import { ArrowRight, EyeOff, Radar, ShieldAlert, Workflow } from 'lucide-react';

const risks = [
  {
    title: 'Sandwich and Frontrun Exposure',
    description:
      'Public mempool propagation can leak transaction intent before inclusion. Private ingress reduces broad visibility during propagation.',
    icon: EyeOff,
  },
  {
    title: 'Path-Specific Execution Risk',
    description:
      'Some routes are more sensitive to latency and block state drift. Simulation and policy checks can filter weak candidates.',
    icon: Radar,
  },
  {
    title: 'Relay Selection Risk',
    description:
      'Single-relay dependency can reduce resilience. Multi-relay submission improves delivery probability and reduces concentration risk.',
    icon: Workflow,
  },
  {
    title: 'Economic Misalignment',
    description:
      'Opaque value capture harms trust. Settlement fields make gas coverage, retained share, and rebates auditable per transaction.',
    icon: ShieldAlert,
  },
];

export function MevProtection() {
  return (
    <div className="bg-page min-h-screen py-16 sm:py-24">
      <div className="mx-auto max-w-6xl px-6 lg:px-8">
        <div className="mx-auto max-w-3xl">
          <p className="text-sm font-semibold text-emerald-700">Ethereum MEV Protection</p>
          <h1 className="mt-3 text-4xl font-semibold tracking-tight text-zinc-900 sm:text-5xl">
            MEV protection that turns private orderflow into a strategic advantage
          </h1>
          <p className="mt-6 text-lg leading-8 text-zinc-600">
            Mitander focuses on reducing common MEV loss surfaces by routing transactions privately, simulating outcomes before submission,
            and only sponsoring when policy and expected value support the decision.
          </p>
        </div>

        <section className="mt-12 grid grid-cols-1 gap-4 md:grid-cols-2">
          {risks.map((risk) => (
            <article key={risk.title} className="rounded-2xl border border-zinc-200 bg-white p-6">
              <div className="inline-flex rounded-lg bg-zinc-900 p-2 text-white">
                <risk.icon className="h-5 w-5" />
              </div>
              <h2 className="mt-4 text-lg font-semibold text-zinc-900">{risk.title}</h2>
              <p className="mt-2 text-sm leading-6 text-zinc-600">{risk.description}</p>
            </article>
          ))}
        </section>

        <section className="mt-12 rounded-2xl border border-zinc-200 bg-white p-8">
          <h2 className="text-2xl font-semibold tracking-tight text-zinc-900">Mitander MEV mitigation model</h2>
          <ol className="mt-5 list-decimal space-y-3 pl-5 text-sm leading-6 text-zinc-700">
            <li>Ingest signed Ethereum transactions through private RPC.</li>
            <li>Run simulation and route evaluation with cost/profit policy constraints.</li>
            <li>Choose execution path: sponsored, private-only, or pass-through.</li>
            <li>Submit via private relay/builder channels and monitor inclusion outcomes.</li>
            <li>Record settlement values for reconciliation and user/partner reporting.</li>
          </ol>
          <p className="mt-5 text-sm leading-6 text-zinc-600">
            No single control eliminates all MEV risk. This model is built to materially reduce avoidable exposure and make outcomes measurable.
          </p>
        </section>

        <section className="mt-12 rounded-2xl border border-zinc-200 bg-zinc-900 p-8 text-white">
          <h2 className="text-2xl font-semibold">Move from public mempool defaults to private execution</h2>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-zinc-300">
            Teams integrating private RPC can improve execution hygiene while keeping deterministic policy and transparent settlement behavior.
          </p>
          <div className="mt-6 flex flex-wrap gap-4 text-sm font-medium">
            <Link
              to="/private-ethereum-rpc"
              className="inline-flex items-center gap-2 rounded-md bg-white px-4 py-2 text-zinc-900 hover:bg-zinc-100"
            >
              Private RPC guide
              <ArrowRight className="h-4 w-4" />
            </Link>
            <Link
              to="/gasless-ethereum-transactions"
              className="inline-flex items-center gap-2 rounded-md border border-zinc-600 px-4 py-2 text-zinc-100 hover:bg-zinc-800"
            >
              Gasless policy model
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </section>
      </div>
    </div>
  );
}
