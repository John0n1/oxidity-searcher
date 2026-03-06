import { Link } from 'react-router-dom';
import { ArrowRight, Lock, Network, Server, ShieldCheck } from 'lucide-react';
import { APP_CONFIG } from '../lib/publicData';

const pillars = [
  {
    title: 'Private mempool entry',
    description:
      'Transactions are submitted through private infrastructure instead of default public gossip paths, reducing broad pre-trade visibility.',
    icon: Lock,
  },
  {
    title: 'Multi-relay delivery',
    description:
      'Orderflow can be routed to multiple private submission paths, improving resilience relative to single-relay dependence.',
    icon: Network,
  },
  {
    title: 'Policy-aware routing',
    description:
      'Simulation and policy checks decide whether a flow is sponsored, private-only, or conservative pass-through.',
    icon: ShieldCheck,
  },
  {
    title: 'Protected RPC compatibility',
    description:
      'The gateway supports `eth_sendRawTransaction` plus a safe read-method set behind bearer auth, network policy, and rate budgets.',
    icon: Server,
  },
];

const realities = [
  'This is not an open public RPC for anonymous traffic.',
  'Production integrations are server-to-server and partner-issued.',
  'Private routing improves execution hygiene but does not eliminate all execution risk.',
  'Commercial onboarding matters because sponsorship and reporting are part of the product, not side effects.',
];

export function PrivateEthereumRpc() {
  return (
    <div className="bg-page min-h-screen py-16 sm:py-24">
      <div className="mx-auto max-w-6xl px-6 lg:px-8">
        <div className="mx-auto max-w-3xl">
          <p className="text-sm font-semibold text-emerald-700">Private Ethereum RPC</p>
          <h1 className="mt-3 text-4xl font-semibold tracking-tight text-zinc-900 sm:text-5xl">
            A private Ethereum RPC designed for production teams, not anonymous public traffic
          </h1>
          <p className="mt-6 text-lg leading-8 text-zinc-600">
            Oxidity provides a protected private Ethereum RPC endpoint for teams that care about execution quality, policy control, and settlement
            visibility. The operating model is explicit: authenticated access, governed budgets, and reporting that works for real businesses.
          </p>

          <div className="mt-8 rounded-xl border border-zinc-200 bg-white p-4 sm:p-5">
            <p className="text-xs font-medium uppercase tracking-[0.14em] text-zinc-500">Endpoint</p>
            <code className="mt-2 block break-all font-mono text-sm text-zinc-900 sm:text-base">{APP_CONFIG.rpcUrl}</code>
            <p className="mt-3 text-sm text-zinc-600">Production usage requires partner-issued bearer auth and approved source ranges.</p>
          </div>
        </div>

        <section className="mt-12 grid grid-cols-1 gap-4 md:grid-cols-2">
          {pillars.map((pillar) => (
            <article key={pillar.title} className="rounded-2xl border border-zinc-200 bg-white p-6">
              <div className="inline-flex rounded-lg bg-zinc-900 p-2 text-white">
                <pillar.icon className="h-5 w-5" />
              </div>
              <h2 className="mt-4 text-lg font-semibold text-zinc-900">{pillar.title}</h2>
              <p className="mt-2 text-sm leading-6 text-zinc-600">{pillar.description}</p>
            </article>
          ))}
        </section>

        <section className="mt-12 grid grid-cols-1 gap-6 lg:grid-cols-[1.05fr_0.95fr]">
          <div className="rounded-2xl border border-zinc-200 bg-white p-8">
            <h2 className="text-2xl font-semibold tracking-tight text-zinc-900">Integration checklist</h2>
            <ol className="mt-5 list-decimal space-y-3 pl-5 text-sm leading-6 text-zinc-700">
              <li>Review the docs and confirm your product can integrate server-to-server.</li>
              <li>Request staging or production onboarding before routing live traffic.</li>
              <li>Use signed raw transaction payloads through `eth_sendRawTransaction`.</li>
              <li>Handle `sponsored`, `private-only`, and `pass-through` as distinct product outcomes.</li>
              <li>Track settlement fields such as gas covered, gas refunded, retained share, and rebates in your own analytics layer.</li>
            </ol>
          </div>
          <div className="rounded-2xl bg-zinc-900 p-8 text-white">
            <h2 className="text-2xl font-semibold">Important realities</h2>
            <ul className="mt-5 space-y-3 text-sm leading-6 text-zinc-300">
              {realities.map((item) => (
                <li key={item} className="flex items-start gap-3">
                  <ArrowRight className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section className="mt-12 rounded-2xl border border-zinc-200 bg-zinc-900 p-8 text-white">
          <h2 className="text-2xl font-semibold">Need private RPC at production volume?</h2>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-zinc-300">
            Start with documentation if you are still evaluating. Move to onboarding when you are ready to discuss traffic shape, support expectations,
            and commercial fit.
          </p>
          <div className="mt-6 flex flex-wrap gap-4 text-sm font-medium">
            <Link
              to="/developers"
              className="inline-flex items-center gap-2 rounded-md bg-white px-4 py-2 text-zinc-900 hover:bg-zinc-100"
            >
              Read docs
              <ArrowRight className="h-4 w-4" />
            </Link>
            <Link
              to="/partners?requested=staging"
              className="inline-flex items-center gap-2 rounded-md border border-zinc-600 px-4 py-2 text-zinc-100 hover:bg-zinc-800"
            >
              Request onboarding
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </section>
      </div>
    </div>
  );
}
