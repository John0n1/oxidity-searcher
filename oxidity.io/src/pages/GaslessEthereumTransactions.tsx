import { Link } from 'react-router-dom';
import { ArrowRight, BarChart3, Coins, ShieldCheck, Wallet } from 'lucide-react';

const rules = [
  {
    title: 'Simulation-first eligibility',
    description:
      'Every transaction path is simulated before coverage decisions. Expected net value and policy risk checks decide whether gasless treatment is allowed.',
    icon: BarChart3,
  },
  {
    title: 'Budget and cap controls',
    description:
      'Global spend controls and per-transaction limits protect treasury exposure while keeping coverage available for high-quality flow.',
    icon: ShieldCheck,
  },
  {
    title: 'Private-only fallback',
    description:
      'If coverage is not eligible, traffic can still execute privately to reduce public mempool exposure.',
    icon: Wallet,
  },
  {
    title: 'Transparent settlement',
    description:
      'Post-trade ledger fields split value into gas covered/refunded, retained share, and user rebate amounts.',
    icon: Coins,
  },
];

export function GaslessEthereumTransactions() {
  return (
    <div className="bg-page min-h-screen py-16 sm:py-24">
      <div className="mx-auto max-w-6xl px-6 lg:px-8">
        <div className="mx-auto max-w-3xl">
          <p className="text-sm font-semibold text-emerald-700">Conditional Sponsorship</p>
          <h1 className="mt-3 text-4xl font-semibold tracking-tight text-zinc-900 sm:text-5xl">
            A gasless Ethereum UX that stays selective, explainable, and commercially sane
          </h1>
          <p className="mt-6 text-lg leading-8 text-zinc-600">
            Oxidity does not promise universal gasless execution. Instead, it applies deterministic policy to cover or refund gas
            when simulated outcomes support it, while maintaining private execution as the default safety path.
          </p>
        </div>

        <section className="mt-12 grid grid-cols-1 gap-4 md:grid-cols-2">
          {rules.map((rule) => (
            <article key={rule.title} className="rounded-2xl border border-zinc-200 bg-white p-6">
              <div className="inline-flex rounded-lg bg-zinc-900 p-2 text-white">
                <rule.icon className="h-5 w-5" />
              </div>
              <h2 className="mt-4 text-lg font-semibold text-zinc-900">{rule.title}</h2>
              <p className="mt-2 text-sm leading-6 text-zinc-600">{rule.description}</p>
            </article>
          ))}
        </section>

        <section className="mt-12 rounded-2xl border border-zinc-200 bg-white p-8">
          <h2 className="text-2xl font-semibold tracking-tight text-zinc-900">What users and partners can expect</h2>
          <ul className="mt-5 list-disc space-y-3 pl-5 text-sm leading-6 text-zinc-700">
            <li>Coverage is policy-driven, not random, and tied to measurable simulated outcomes.</li>
            <li>Transactions that are not coverage-eligible can still benefit from private orderflow routing.</li>
            <li>Each included transaction can be reconciled with production ledger fields for rebate and retained value.</li>
            <li>Risk controls can stop coverage while keeping private submission available.</li>
          </ul>
        </section>

        <section className="mt-12 rounded-2xl border border-zinc-200 bg-zinc-900 p-8 text-white">
          <h2 className="text-2xl font-semibold">Ship a lower-friction UX without pretending economics do not matter</h2>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-zinc-300">
            Use private execution plus selective sponsorship to offer lower-friction transactions while preserving transparent value split, policy boundaries, and a business model that can survive real volume.
          </p>
          <div className="mt-6 flex flex-wrap gap-4 text-sm font-medium">
            <Link
              to="/risk-policy"
              className="inline-flex items-center gap-2 rounded-md bg-white px-4 py-2 text-zinc-900 hover:bg-zinc-100"
            >
              Review risk policy
              <ArrowRight className="h-4 w-4" />
            </Link>
            <Link
              to="/pricing"
              className="inline-flex items-center gap-2 rounded-md border border-zinc-600 px-4 py-2 text-zinc-100 hover:bg-zinc-800"
            >
              See pricing
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </section>
      </div>
    </div>
  );
}
