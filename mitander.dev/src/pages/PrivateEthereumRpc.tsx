import { Link } from 'react-router-dom';
import { ArrowRight, Lock, Network, Server, ShieldCheck } from 'lucide-react';
import { APP_CONFIG } from '../lib/publicData';

const pillars = [
  {
    title: 'Private Mempool Entry',
    description:
      'Transactions are submitted to private infrastructure instead of public gossip paths, reducing broad mempool visibility.',
    icon: Lock,
  },
  {
    title: 'Multi-Relay Delivery',
    description:
      'Orderflow can be relayed to multiple private builders/relays, improving inclusion quality under variable market conditions.',
    icon: Network,
  },
  {
    title: 'Policy-Aware Routing',
    description:
      'Simulation and policy checks decide whether traffic is sponsored, private-only, or pass-through.',
    icon: ShieldCheck,
  },
  {
    title: 'Production RPC Compatibility',
    description:
      'JSON-RPC ingress supports `eth_sendRawTransaction` private flow and baseline compatibility methods behind bearer auth, network policy, and strict budgets.',
    icon: Server,
  },
];

export function PrivateEthereumRpc() {
  return (
    <div className="bg-page min-h-screen py-16 sm:py-24">
      <div className="mx-auto max-w-6xl px-6 lg:px-8">
        <div className="mx-auto max-w-3xl">
          <p className="text-sm font-semibold text-emerald-700">Private Ethereum RPC</p>
          <h1 className="mt-3 text-4xl font-semibold tracking-tight text-zinc-900 sm:text-5xl">
            Private Ethereum RPC that gives orderflow a real execution edge
          </h1>
          <p className="mt-6 text-lg leading-8 text-zinc-600">
            Mitander provides a private Ethereum RPC endpoint designed for MEV-aware execution. Integrations can send signed
            transactions without exposing orderflow directly to the public mempool path, while still keeping full settlement visibility.
          </p>

          <div className="mt-8 rounded-xl border border-zinc-200 bg-white p-4 sm:p-5">
            <p className="text-xs font-medium uppercase tracking-[0.14em] text-zinc-500">RPC endpoint</p>
            <code className="mt-2 block text-sm sm:text-base font-mono text-zinc-900 break-all">{APP_CONFIG.rpcUrl}</code>
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

        <section className="mt-12 rounded-2xl border border-zinc-200 bg-white p-8">
          <h2 className="text-2xl font-semibold tracking-tight text-zinc-900">Integration checklist</h2>
          <ol className="mt-5 list-decimal space-y-3 pl-5 text-sm leading-6 text-zinc-700">
            <li>Request partner onboarding before pointing production traffic to `rpc.mitander.dev`.</li>
            <li>Use signed raw transaction payloads through `eth_sendRawTransaction`.</li>
            <li>Send bearer-authenticated traffic from approved network ranges only.</li>
            <li>Handle policy outcomes using summary telemetry (`sponsored`, `private-only`, `pass-through`).</li>
            <li>Track settlement fields (`gas covered`, `gas refunded`, `retained`, `rebate`) in your own analytics layer.</li>
          </ol>
          <div className="mt-6 flex flex-wrap gap-4 text-sm font-medium">
            <Link to="/developers" className="text-zinc-900 hover:text-zinc-600">
              Read developer docs <span aria-hidden>→</span>
            </Link>
            <Link to="/mev-protection" className="text-zinc-900 hover:text-zinc-600">
              MEV protection model <span aria-hidden>→</span>
            </Link>
            <Link to="/how-it-works" className="text-zinc-900 hover:text-zinc-600">
              End-to-end flow <span aria-hidden>→</span>
            </Link>
          </div>
        </section>

        <section className="mt-12 rounded-2xl border border-zinc-200 bg-zinc-900 p-8 text-white">
          <h2 className="text-2xl font-semibold">Need private RPC at production volume?</h2>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-zinc-300">
            Partner onboarding includes rate limits, policy envelope details, and telemetry mapping so teams can ship a faster, higher-quality execution path.
          </p>
          <Link
            to="/partners"
            className="mt-6 inline-flex items-center gap-2 rounded-md bg-white px-4 py-2 text-sm font-semibold text-zinc-900 hover:bg-zinc-100"
          >
            Request partner onboarding
            <ArrowRight className="h-4 w-4" />
          </Link>
        </section>
      </div>
    </div>
  );
}
