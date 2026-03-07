import {
  ArrowRight,
  Briefcase,
  Chrome,
  Download,
  ShieldCheck,
  Smartphone,
  Sparkles,
  WalletCards,
  Zap,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { walletEnv } from '@/lib/env';

const featureCards = [
  {
    icon: ShieldCheck,
    title: 'Feels like a wallet first',
    body: 'Clear onboarding, local key storage, and a calmer Ethereum experience than raw RPC tooling gives most users.',
  },
  {
    icon: Zap,
    title: 'Smarter execution underneath',
    body: 'Protected routing, selective sponsorship, and future reporting are built into the product story without turning every feature into buzzwords.',
  },
  {
    icon: Briefcase,
    title: 'A serious path for teams',
    body: 'Start as a user-facing wallet surface, then graduate into business onboarding, controls, and partner infrastructure.',
  },
];

export function LandingPage() {
  return (
    <div className="min-h-screen bg-[#f5f8ff] text-slate-950">
      <div className="mx-auto flex max-w-7xl flex-col px-5 pb-16 pt-6 sm:px-8 lg:px-10">
        <header className="flex items-center justify-between rounded-full border border-slate-200/80 bg-white/85 px-5 py-3 shadow-[0_10px_30px_rgba(37,99,235,0.08)] backdrop-blur">
          <div className="flex items-center gap-3">
            <img src="/brand-mark.svg" alt="Oxidity Wallet" className="h-9 w-9" />
            <div>
              <div className="text-sm font-semibold tracking-tight">Oxidity Wallet</div>
              <div className="text-[11px] uppercase tracking-[0.18em] text-slate-500">Private Ethereum Wallet</div>
            </div>
          </div>
          <div className="hidden items-center gap-6 text-sm text-slate-600 md:flex">
            <a href="#downloads" className="hover:text-slate-950">Downloads</a>
            <a href="#business" className="hover:text-slate-950">Business</a>
            <a href={walletEnv.statusUrl} className="hover:text-slate-950">Status</a>
            <Link
              to="/app"
              className="rounded-full bg-slate-950 px-4 py-2 font-medium text-white transition-colors hover:bg-slate-800"
            >
              Open App
            </Link>
          </div>
        </header>

        <section className="grid gap-10 px-1 pb-16 pt-16 lg:grid-cols-[minmax(0,1.15fr)_420px] lg:items-center">
          <div>
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-blue-200 bg-blue-50 px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-blue-700">
              Self-custody wallet for people and teams
            </div>
            <h1 className="max-w-3xl text-5xl font-semibold leading-[0.95] tracking-tight text-slate-950 sm:text-6xl">
              A friendlier Ethereum wallet, with a stronger execution layer behind it.
            </h1>
            <p className="mt-6 max-w-2xl text-lg leading-8 text-slate-600">
              Oxidity Wallet is built for everyday self-custody first. It also gives product teams a path into protected routing, business onboarding, and partner infrastructure when the wallet needs to do more than hold assets.
            </p>
            <div id="downloads" className="mt-8 flex flex-wrap gap-3">
              <a
                href={walletEnv.downloadExtensionUrl}
                className="inline-flex items-center gap-2 rounded-2xl bg-blue-600 px-5 py-3 text-sm font-semibold text-white shadow-[0_12px_32px_rgba(37,99,235,0.28)] transition-transform hover:-translate-y-0.5 hover:bg-blue-500"
              >
                <Chrome className="h-4 w-4" />
                Download Extension
              </a>
              <a
                href={walletEnv.downloadAndroidUrl}
                className="inline-flex items-center gap-2 rounded-2xl border border-slate-300 bg-white px-5 py-3 text-sm font-semibold text-slate-950 transition-colors hover:border-slate-400 hover:bg-slate-50"
              >
                <Smartphone className="h-4 w-4" />
                Android Preview APK
              </a>
              <Link
                to="/app"
                className="inline-flex items-center gap-2 rounded-2xl border border-slate-300 bg-slate-950 px-5 py-3 text-sm font-semibold text-white transition-colors hover:bg-slate-800"
              >
                Try the Wallet Shell
                <ArrowRight className="h-4 w-4" />
              </Link>
            </div>
            <div className="mt-6 flex flex-wrap gap-4 text-sm text-slate-500">
              <span>Local encrypted vault</span>
              <span>Private-ready routing</span>
              <span>Extension + Android targets</span>
              <span>Business onboarding</span>
            </div>
          </div>

          <div className="relative">
            <div className="absolute inset-0 rounded-[36px] bg-[radial-gradient(circle_at_top,_rgba(59,130,246,0.24),_transparent_58%)] blur-2xl" />
            <div className="relative rounded-[36px] border border-slate-200 bg-white p-5 shadow-[0_30px_80px_rgba(15,23,42,0.12)]">
              <div className="rounded-[28px] bg-slate-950 p-5 text-white">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-xs uppercase tracking-[0.18em] text-slate-500">Oxidity Wallet</div>
                    <div className="mt-1 text-lg font-semibold">Private execution active</div>
                  </div>
                  <img src="/brand-mark.svg" alt="" className="h-10 w-10" />
                </div>
                <div className="mt-8 rounded-3xl border border-white/10 bg-white/5 p-5">
                    <div className="text-sm text-slate-400">Portfolio</div>
                    <div className="mt-2 text-4xl font-semibold">$0.00</div>
                    <div className="mt-6 grid gap-3 text-sm sm:grid-cols-3">
                      <div className="rounded-2xl border border-white/10 bg-white/5 p-3">
                      <div className="text-slate-500">Vault</div>
                      <div className="mt-1 font-semibold">Local only</div>
                      </div>
                      <div className="rounded-2xl border border-white/10 bg-white/5 p-3">
                      <div className="text-slate-500">Execution</div>
                      <div className="mt-1 font-semibold">Private-ready</div>
                      </div>
                      <div className="rounded-2xl border border-white/10 bg-white/5 p-3">
                      <div className="text-slate-500">Platforms</div>
                      <div className="mt-1 font-semibold">3 targets</div>
                      </div>
                    </div>
                  </div>
                <div className="mt-4 rounded-3xl border border-blue-500/20 bg-blue-500/10 p-4 text-sm text-blue-100">
                  Start in the browser, move into the extension for desktop signing, or use the Android wrapper when you want the same wallet shell on mobile.
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="mb-5 grid gap-4 rounded-[32px] border border-slate-200 bg-white/80 p-5 shadow-[0_18px_50px_rgba(15,23,42,0.05)] md:grid-cols-3">
          {[
            { label: 'Self-custody', value: 'Keys stay local' },
            { label: 'Execution', value: 'Private-ready by design' },
            { label: 'Team path', value: 'Business onboarding available' },
          ].map((item) => (
            <div key={item.label} className="rounded-[24px] border border-slate-200 bg-slate-50 px-4 py-4">
              <div className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">{item.label}</div>
              <div className="mt-2 text-lg font-semibold tracking-tight text-slate-950">{item.value}</div>
            </div>
          ))}
        </section>

        <section className="grid gap-5 md:grid-cols-3">
          {featureCards.map((card) => (
            <div
              key={card.title}
              className="rounded-[28px] border border-slate-200 bg-white p-6 shadow-[0_18px_50px_rgba(15,23,42,0.06)]"
            >
              <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-blue-50 text-blue-600">
                <card.icon className="h-5 w-5" />
              </div>
              <h2 className="mt-5 text-xl font-semibold tracking-tight">{card.title}</h2>
              <p className="mt-3 text-sm leading-7 text-slate-600">{card.body}</p>
            </div>
          ))}
        </section>

        <section className="mt-14 grid gap-5 lg:grid-cols-2">
          <div className="rounded-[36px] border border-slate-200 bg-white p-8 shadow-[0_18px_60px_rgba(15,23,42,0.06)]">
            <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-blue-50 text-blue-600">
              <WalletCards className="h-5 w-5" />
            </div>
            <h2 className="mt-5 text-3xl font-semibold tracking-tight text-slate-950">For individual users</h2>
            <p className="mt-4 text-base leading-8 text-slate-600">
              Download the extension or Android wrapper, keep keys on-device, and use a wallet that is designed to grow into better execution instead of pretending the infrastructure layer does not matter.
            </p>
            <div className="mt-6 flex flex-wrap gap-3">
              <a
                href={walletEnv.downloadExtensionUrl}
                className="inline-flex items-center gap-2 rounded-2xl bg-slate-950 px-5 py-3 text-sm font-semibold text-white transition-colors hover:bg-slate-800"
              >
                Browser extension
                <ArrowRight className="h-4 w-4" />
              </a>
              <a
                href={walletEnv.downloadAndroidUrl}
                className="inline-flex items-center gap-2 rounded-2xl border border-slate-300 bg-slate-50 px-5 py-3 text-sm font-semibold text-slate-950 transition-colors hover:bg-white"
              >
                Android preview APK
                <Download className="h-4 w-4" />
              </a>
            </div>
          </div>

          <div className="rounded-[36px] border border-slate-200 bg-[linear-gradient(135deg,#eff6ff_0%,#ffffff_48%,#eefdf8_100%)] p-8 shadow-[0_18px_60px_rgba(37,99,235,0.08)]">
            <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-white text-blue-600 shadow-sm">
              <Sparkles className="h-5 w-5" />
            </div>
            <h2 className="mt-5 text-3xl font-semibold tracking-tight text-slate-950">For wallet and product teams</h2>
            <p className="mt-4 text-base leading-8 text-slate-600">
              Use Oxidity Wallet as a front door, then step deeper into protected routing, private submission, selective sponsorship, and the reporting layer a business actually needs to operate.
            </p>
            <div className="mt-6 flex flex-wrap gap-3">
              <a
                href={walletEnv.businessUrl}
                className="inline-flex items-center gap-2 rounded-2xl bg-slate-950 px-5 py-3 text-sm font-semibold text-white transition-colors hover:bg-slate-800"
              >
                Talk to the wallet team
                <ArrowRight className="h-4 w-4" />
              </a>
              <a
                href={walletEnv.docsUrl}
                className="inline-flex items-center gap-2 rounded-2xl border border-slate-300 bg-white px-5 py-3 text-sm font-semibold text-slate-950 transition-colors hover:bg-slate-50"
              >
                Developer docs
                <Chrome className="h-4 w-4" />
              </a>
            </div>
          </div>
        </section>

        <section
          id="business"
          className="mt-14 rounded-[36px] border border-slate-200 bg-[linear-gradient(135deg,#eff6ff_0%,#ffffff_48%,#eefdf8_100%)] p-8 shadow-[0_18px_60px_rgba(37,99,235,0.08)]"
        >
          <div className="grid gap-10 lg:grid-cols-[minmax(0,1.1fr)_320px] lg:items-center">
            <div>
              <div className="text-xs font-semibold uppercase tracking-[0.18em] text-blue-700">For teams</div>
              <h2 className="mt-3 text-3xl font-semibold tracking-tight text-slate-950">
                A wallet surface that can grow into production infrastructure.
              </h2>
              <p className="mt-4 max-w-2xl text-base leading-8 text-slate-600">
                Start with the same interface users already see, then move deeper into Oxidity’s partner stack for protected RPC, selective sponsorship, reporting, and operational controls.
              </p>
            </div>
            <div className="rounded-[28px] border border-slate-200 bg-white p-5">
              <div className="text-sm font-semibold text-slate-950">Business actions</div>
              <div className="mt-4 space-y-3">
                <a
                  href={walletEnv.businessUrl}
                  className="flex items-center justify-between rounded-2xl bg-slate-950 px-4 py-3 text-sm font-semibold text-white transition-colors hover:bg-slate-800"
                >
                  Talk to wallet team
                  <ArrowRight className="h-4 w-4" />
                </a>
                <a
                  href={walletEnv.docsUrl}
                  className="flex items-center justify-between rounded-2xl border border-slate-300 px-4 py-3 text-sm font-semibold text-slate-950 transition-colors hover:bg-slate-50"
                >
                  Developer docs
                  <Download className="h-4 w-4" />
                </a>
              </div>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
