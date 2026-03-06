import { useMemo, useState } from 'react';
import {
  Activity,
  AlertCircle,
  ArrowRight,
  BadgeCheck,
  Building2,
  CircleGauge,
  Coins,
  LoaderCircle,
  LockKeyhole,
  ShieldCheck,
  Sparkles,
  WalletCards,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { motion } from 'motion/react';
import { calculateSplit } from '../lib/publicData';
import { usePublicData } from '../hooks/usePublicData';
import { formatEth, formatRelativeTime, formatUsd } from '../lib/formatters';
import { proofCaseStudies, proofCategories } from '../lib/proof';

const audiences = [
  {
    title: 'Solo developers',
    description:
      'Learn the API surface, understand how routing works, and get comfortable with the product before you send real traffic.',
    cta: 'Explore docs',
    href: '/developers',
    icon: Sparkles,
  },
  {
    title: 'Wallets and dApps',
    description:
      'Offer smoother Ethereum transactions with private routing, selective sponsorship, and reporting that still feels clear to ops and finance.',
    cta: 'See plans',
    href: '/pricing',
    icon: WalletCards,
  },
  {
    title: 'Companies and desks',
    description:
      'Move into production with onboarding, access controls, and a service model that feels steady enough to build around.',
    cta: 'Talk to us',
    href: '/partners',
    icon: Building2,
  },
];

const pillars = [
  {
    title: 'Protect execution',
    description:
      'Orderflow is routed through authenticated private infrastructure instead of defaulting to public mempool exposure.',
    icon: LockKeyhole,
  },
  {
    title: 'Sponsor selectively',
    description:
      'Coverage decisions follow simulation and policy, so the user experience can improve without turning the business model into guesswork.',
    icon: CircleGauge,
  },
  {
    title: 'Reconcile outcomes',
    description:
      'Settlement fields separate coverage, rebates, retained share, and path decisions so partners can explain outcomes cleanly.',
    icon: Coins,
  },
  {
    title: 'Built for lasting partnerships',
    description:
      'The product is designed around recurring access, clear limits, and transparent economics instead of short-lived promotional behavior.',
    icon: ShieldCheck,
  },
];

const trustLinks = [
  {
    title: 'Production access is structured',
    description: 'Bearer auth, network policy, rate limiting, and guided onboarding are part of the service, not an afterthought.',
    href: '/developers',
  },
  {
    title: 'Status is public',
    description: 'Visitors can inspect service health and degraded states without relying on vague trust language.',
    href: '/status',
  },
  {
    title: 'Risk policy is visible',
    description: 'Coverage and private-only routing follow published policy instead of hidden one-off exceptions.',
    href: '/risk-policy',
  },
  {
    title: 'The business model is clear',
    description: 'Oxidity is sold as execution infrastructure with recurring revenue and measured sponsorship, not a free-gas gimmick.',
    href: '/pricing',
  },
];

const planPreview = [
  {
    name: 'Developer Sandbox',
    price: 'Free preview',
    description: 'Best for solo builders and evaluation work.',
  },
  {
    name: 'Growth',
    price: 'Platform fee + usage',
    description: 'Best for startups shipping production flows.',
  },
  {
    name: 'Business',
    price: 'Minimum monthly commit',
    description: 'Best for wallets, dApps, and searchers operating at scale.',
  },
  {
    name: 'Enterprise',
    price: 'Custom contract',
    description: 'Best for large-volume teams with support and SLA requirements.',
  },
];

const modelPrinciples = [
  'Recurring platform access for production use and support',
  'Traffic envelopes and limits agreed before scale becomes a problem',
  'Selective sponsorship only when policy and economics line up',
  'Reporting that makes value flow legible to operators and finance',
];

export function Home() {
  const [expectedMevUsd, setExpectedMevUsd] = useState(1000);
  const [gasCostUsd, setGasCostUsd] = useState(50);
  const { result, loading, error } = usePublicData();

  const policyBps = result?.data.policy.retainedBps ?? 1000;
  const breakdown = useMemo(
    () => calculateSplit(expectedMevUsd, gasCostUsd, policyBps),
    [expectedMevUsd, gasCostUsd, policyBps],
  );

  const services = result?.data.services ?? [];
  const activity = result?.data.activity ?? [];
  const publicDataDegraded = result?.source === 'degraded';
  const policy = result?.data.policy;

  return (
    <div className="bg-page">
      <section className="relative isolate pt-16">
        <div className="py-24 sm:py-28 lg:py-32">
          <div className="mx-auto max-w-7xl px-6 lg:px-8">
            <div className="grid grid-cols-1 gap-12 lg:grid-cols-[1.15fr_0.85fr] lg:items-end">
              <div className="max-w-3xl">
                <motion.p
                  initial={{ opacity: 0, y: 18 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.45 }}
                  className="text-sm font-semibold uppercase tracking-[0.2em] text-emerald-700"
                >
                  Private Ethereum execution, made practical
                </motion.p>
                <motion.h1
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.5, delay: 0.05 }}
                  className="mt-5 text-4xl font-semibold tracking-tight text-zinc-900 sm:text-6xl"
                >
                  Private routing, selective sponsorship, and reporting that feels ready for real use.
                </motion.h1>
                <motion.p
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.5, delay: 0.1 }}
                  className="mt-6 max-w-2xl text-lg leading-8 text-zinc-600"
                >
                  Oxidity gives builders and teams a cleaner way to send Ethereum transactions: keep sensitive flow out of the public mempool, apply
                  sponsorship where it genuinely helps, and understand the outcome without digging through opaque rebate math.
                </motion.p>
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.5, delay: 0.15 }}
                  className="mt-10 flex flex-wrap items-center gap-4"
                >
                  <Link
                    to="/developers"
                    className="inline-flex items-center gap-2 rounded-xl bg-zinc-900 px-5 py-3 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-zinc-800"
                  >
                    Explore the platform
                    <ArrowRight className="h-4 w-4" />
                  </Link>
                  <Link
                    to="/partners?requested=production"
                    className="inline-flex items-center gap-2 rounded-xl border border-zinc-300 bg-white px-5 py-3 text-sm font-semibold text-zinc-900 transition-colors hover:bg-zinc-50"
                  >
                    Talk about production
                    <ArrowRight className="h-4 w-4" />
                  </Link>
                  <Link
                    to="/pricing"
                    className="text-sm font-semibold text-zinc-700 transition-colors hover:text-zinc-900"
                  >
                    View pricing and packaging <span aria-hidden>→</span>
                  </Link>
                </motion.div>
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.5, delay: 0.2 }}
                  className="mt-8 flex flex-wrap gap-3 text-sm text-zinc-600"
                >
                  <span className="rounded-full border border-zinc-200 bg-white px-3 py-1.5">Authenticated production ingress</span>
                  <span className="rounded-full border border-zinc-200 bg-white px-3 py-1.5">Policy-based gas sponsorship</span>
                  <span className="rounded-full border border-zinc-200 bg-white px-3 py-1.5">Partner settlement reporting</span>
                  <span className="rounded-full border border-zinc-200 bg-white px-3 py-1.5">Public status and docs</span>
                </motion.div>
              </div>

              <motion.div
                initial={{ opacity: 0, y: 22 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.55, delay: 0.18 }}
                className="rounded-[28px] border border-zinc-200 bg-white/95 p-7 shadow-sm"
              >
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-[0.16em] text-zinc-500">Operational snapshot</p>
                    <h2 className="mt-2 text-2xl font-semibold text-zinc-900">
                      {publicDataDegraded ? 'Public telemetry degraded' : 'Live public summary'}
                    </h2>
                  </div>
                  <div
                    className={`inline-flex items-center gap-2 rounded-full px-3 py-1.5 text-xs font-medium ${
                      publicDataDegraded ? 'bg-amber-50 text-amber-700 ring-1 ring-amber-200' : 'bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200'
                    }`}
                  >
                    {loading ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <Activity className="h-4 w-4" />}
                    {loading ? 'Refreshing' : publicDataDegraded ? 'Degraded' : 'Live'}
                  </div>
                </div>

                <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <div className="rounded-2xl border border-zinc-200 bg-zinc-50 p-4">
                    <p className="text-xs font-semibold uppercase tracking-[0.16em] text-zinc-500">Policy caps</p>
                    <p className="mt-2 text-sm text-zinc-700">
                      {policy ? `${formatEth(policy.perTxGasCapEth, 2)} / tx` : '--'} and {policy ? `${formatEth(policy.perDayGasCapEth, 2)} / day` : '--'}
                    </p>
                  </div>
                  <div className="rounded-2xl border border-zinc-200 bg-zinc-50 p-4">
                    <p className="text-xs font-semibold uppercase tracking-[0.16em] text-zinc-500">Updated</p>
                    <p className="mt-2 text-sm text-zinc-700">
                      {result ? formatRelativeTime(result.data.generatedAt) : 'Waiting for public summary'}
                    </p>
                  </div>
                </div>

                <div className="mt-5 space-y-3">
                  {(services.length > 0 ? services : [{ name: 'Status feed', status: publicDataDegraded ? 'degraded' : 'operational', uptimePct: 0, latencyMs: 0 }]).map(
                    (service) => (
                      <div key={service.name} className="flex items-center justify-between rounded-2xl border border-zinc-200 px-4 py-3">
                        <span className="text-sm font-medium text-zinc-900">{service.name}</span>
                        <span
                          className={`rounded-full px-2.5 py-1 text-xs font-medium ${
                            service.status === 'operational'
                              ? 'bg-emerald-50 text-emerald-700'
                              : service.status === 'degraded'
                                ? 'bg-amber-50 text-amber-700'
                                : 'bg-red-50 text-red-700'
                          }`}
                        >
                          {service.status}
                        </span>
                      </div>
                    ),
                  )}
                </div>

                {publicDataDegraded && (
                  <div className="mt-5 rounded-2xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-800">
                    {error || 'Public telemetry is available but intentionally sparse right now.'}
                  </div>
                )}
              </motion.div>
            </div>
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-6 pb-24 lg:px-8">
        <div className="rounded-[30px] border border-zinc-200 bg-white p-8 shadow-sm sm:p-10">
          <div className="max-w-3xl">
            <p className="text-sm font-semibold uppercase tracking-[0.18em] text-emerald-700">Choose your path</p>
            <h2 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-900">One product, different entry points</h2>
            <p className="mt-4 text-base leading-7 text-zinc-600">
              First-time visitors should not have to guess whether Oxidity is meant for them. Start from the path that matches your operating model.
            </p>
          </div>
          <div className="mt-8 grid grid-cols-1 gap-5 lg:grid-cols-3">
            {audiences.map((audience) => (
              <Link
                key={audience.title}
                to={audience.href}
                className="group rounded-3xl border border-zinc-200 bg-zinc-50 p-6 transition-all hover:-translate-y-0.5 hover:bg-white hover:shadow-sm"
              >
                <div className="inline-flex rounded-2xl bg-zinc-900 p-3 text-white">
                  <audience.icon className="h-5 w-5" />
                </div>
                <h3 className="mt-5 text-xl font-semibold text-zinc-900">{audience.title}</h3>
                <p className="mt-3 text-sm leading-6 text-zinc-600">{audience.description}</p>
                <div className="mt-6 inline-flex items-center gap-2 text-sm font-semibold text-zinc-900">
                  {audience.cta}
                  <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
                </div>
              </Link>
            ))}
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-6 pb-24 lg:px-8">
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-2 xl:grid-cols-4">
          {pillars.map((pillar) => (
            <article key={pillar.title} className="rounded-3xl border border-zinc-200 bg-white p-7 shadow-sm">
              <div className="inline-flex rounded-2xl bg-zinc-900 p-3 text-white">
                <pillar.icon className="h-5 w-5" />
              </div>
              <h2 className="mt-5 text-xl font-semibold text-zinc-900">{pillar.title}</h2>
              <p className="mt-3 text-sm leading-6 text-zinc-600">{pillar.description}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-6 pb-24 lg:px-8">
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1.02fr_0.98fr]">
          <div className="rounded-[30px] border border-zinc-200 bg-white p-8 shadow-sm">
            <p className="text-sm font-semibold uppercase tracking-[0.18em] text-emerald-700">Commercial discipline</p>
            <h2 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-900">A model that can actually last</h2>
            <p className="mt-4 text-base leading-7 text-zinc-600">
              Teams trust infrastructure more quickly when the economics are visible. Oxidity is built around recurring access, measured sponsorship,
              and production guardrails that still feel understandable from the first visit.
            </p>
            <ul className="mt-8 space-y-4 text-sm leading-6 text-zinc-700">
              {modelPrinciples.map((principle) => (
                <li key={principle} className="flex items-start gap-3">
                  <BadgeCheck className="mt-0.5 h-5 w-5 shrink-0 text-emerald-600" />
                  <span>{principle}</span>
                </li>
              ))}
            </ul>
            <div className="mt-8 flex flex-wrap gap-3">
              <Link
                to="/pricing"
                className="inline-flex items-center gap-2 rounded-xl bg-zinc-900 px-4 py-2.5 text-sm font-semibold text-white hover:bg-zinc-800"
              >
                See pricing
                <ArrowRight className="h-4 w-4" />
              </Link>
              <Link
                to="/risk-policy"
                className="inline-flex items-center gap-2 rounded-xl border border-zinc-300 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-900 hover:bg-zinc-50"
              >
                Review policy
                <ArrowRight className="h-4 w-4" />
              </Link>
            </div>
          </div>

          <div className="rounded-[30px] border border-zinc-200 bg-white p-8 shadow-sm">
            <h2 className="text-2xl font-semibold tracking-tight text-zinc-900">Example economics</h2>
            <p className="mt-3 text-sm leading-6 text-zinc-600">
              This estimator explains the commercial shape of the product. It is not a promise of blanket sponsorship, just a quick way to see how the
              policy can stay helpful without becoming reckless.
            </p>
            <div className="mt-8 grid grid-cols-1 gap-5 sm:grid-cols-2">
              <label className="block text-sm font-medium text-zinc-700">
                Expected value (USD)
                <input
                  id="split-estimator-expected-mev-usd"
                  name="split_estimator_expected_mev_usd"
                  type="number"
                  min={0}
                  step={1}
                  value={expectedMevUsd}
                  onChange={(event) => setExpectedMevUsd(Number(event.target.value) || 0)}
                  className="mt-2 w-full rounded-xl border border-zinc-300 bg-white px-3 py-2.5 text-zinc-900"
                />
              </label>
              <label className="block text-sm font-medium text-zinc-700">
                Estimated gas cost (USD)
                <input
                  id="split-estimator-estimated-gas-usd"
                  name="split_estimator_estimated_gas_usd"
                  type="number"
                  min={0}
                  step={1}
                  value={gasCostUsd}
                  onChange={(event) => setGasCostUsd(Number(event.target.value) || 0)}
                  className="mt-2 w-full rounded-xl border border-zinc-300 bg-white px-3 py-2.5 text-zinc-900"
                />
              </label>
            </div>
            <div className="mt-8 space-y-4 border-t border-zinc-200 pt-6 text-sm">
              <div className="flex justify-between">
                <span className="text-zinc-500">Gross value</span>
                <span className="font-mono text-zinc-900">{formatUsd(breakdown.gross)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-zinc-500">Gas sponsored</span>
                <span className="font-mono text-zinc-900">{formatUsd(breakdown.gas)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-zinc-500">Oxidity retained ({(policyBps / 100).toFixed(1)}%)</span>
                <span className="font-mono text-zinc-900">{formatUsd(breakdown.retained)}</span>
              </div>
              <div className="flex justify-between border-t border-zinc-200 pt-4">
                <span className="font-medium text-zinc-900">User rebate</span>
                <span className="font-mono font-medium text-emerald-600">{formatUsd(breakdown.rebate)}</span>
              </div>
            </div>
            <div className="mt-6 rounded-2xl border border-zinc-200 bg-zinc-50 p-4 text-sm text-zinc-600">
              <span className="font-medium text-zinc-900">Decision:</span>{' '}
              {breakdown.sponsored
                ? 'This example can support sponsorship under the current assumptions.'
                : 'This example is better kept private-only because sponsorship would not be healthy here.'}
            </div>
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-6 pb-24 lg:px-8">
        <div className="rounded-[30px] border border-zinc-200 bg-white p-8 shadow-sm">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-3xl">
              <p className="text-sm font-semibold uppercase tracking-[0.18em] text-emerald-700">Trust surfaces</p>
            <h2 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-900">Reliability is a product feature</h2>
            <p className="mt-4 text-base leading-7 text-zinc-600">
              Trust should not depend on a sales call. Oxidity works better when visitors can see the docs, policy, status, and commercial posture
              before they ever fill in a form.
            </p>
            </div>
            <Link to="/status" className="text-sm font-semibold text-zinc-900 hover:text-zinc-600">
              Open live status <span aria-hidden>→</span>
            </Link>
          </div>
          <div className="mt-8 grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-4">
            {trustLinks.map((item) => (
              <Link
                key={item.title}
                to={item.href}
                className="rounded-2xl border border-zinc-200 bg-zinc-50 p-5 transition-colors hover:bg-white"
              >
                <h3 className="text-base font-semibold text-zinc-900">{item.title}</h3>
                <p className="mt-3 text-sm leading-6 text-zinc-600">{item.description}</p>
              </Link>
            ))}
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-6 pb-24 lg:px-8">
        <div className="rounded-[30px] border border-zinc-200 bg-white p-8 shadow-sm">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-3xl">
              <p className="text-sm font-semibold uppercase tracking-[0.18em] text-emerald-700">Proof surfaces</p>
              <h2 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-900">Buyers trust what they can verify</h2>
              <p className="mt-4 text-base leading-7 text-zinc-600">
                Infrastructure buyers care about what they can inspect quickly: the teams you support, the controls you expose, and whether the whole
                thing still looks sensible after a few minutes of scrutiny.
              </p>
            </div>
            <Link to="/proof" className="text-sm font-semibold text-zinc-900 hover:text-zinc-600">
              Open proof and diligence <span aria-hidden>→</span>
            </Link>
          </div>

          <div className="mt-8 grid grid-cols-2 gap-4 md:grid-cols-4">
            {proofCategories.map((category) => (
              <div key={category} className="rounded-2xl border border-zinc-200 bg-zinc-50 px-4 py-4 text-center text-sm font-semibold text-zinc-900">
                {category}
              </div>
            ))}
          </div>

          <div className="mt-8 grid grid-cols-1 gap-5 xl:grid-cols-3">
            {proofCaseStudies.map((study) => (
              <article key={study.title} className="rounded-3xl border border-zinc-200 bg-zinc-50 p-6">
                <p className="text-xs font-semibold uppercase tracking-[0.16em] text-emerald-700">{study.profile}</p>
                <h3 className="mt-3 text-xl font-semibold text-zinc-900">{study.title}</h3>
                <p className="mt-3 text-sm leading-6 text-zinc-700">{study.headline}</p>
                <ul className="mt-5 space-y-3 text-sm leading-6 text-zinc-600">
                  {study.shifts.slice(0, 2).map((item) => (
                    <li key={item} className="flex items-start gap-3">
                      <BadgeCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-6 pb-24 lg:px-8">
        <div className="rounded-[30px] border border-zinc-200 bg-white p-8 shadow-sm">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-3xl">
              <p className="text-sm font-semibold uppercase tracking-[0.18em] text-emerald-700">Packaging preview</p>
              <h2 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-900">Designed to convert without hiding the business model</h2>
            </div>
            <Link to="/pricing" className="text-sm font-semibold text-zinc-900 hover:text-zinc-600">
              Full pricing page <span aria-hidden>→</span>
            </Link>
          </div>
          <div className="mt-8 grid grid-cols-1 gap-5 xl:grid-cols-4">
            {planPreview.map((plan) => (
              <div key={plan.name} className="rounded-2xl border border-zinc-200 bg-zinc-50 p-5">
                <h3 className="text-lg font-semibold text-zinc-900">{plan.name}</h3>
                <p className="mt-2 text-sm font-semibold text-emerald-700">{plan.price}</p>
                <p className="mt-3 text-sm leading-6 text-zinc-600">{plan.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-6 pb-24 lg:px-8">
        <div className="rounded-[34px] border border-sky-200 bg-[linear-gradient(135deg,rgba(255,255,255,0.96),rgba(240,249,255,0.94),rgba(236,253,245,0.92))] p-8 shadow-sm sm:p-10">
          <div className="max-w-3xl">
            <p className="text-sm font-semibold uppercase tracking-[0.18em] text-emerald-700">Ready to move</p>
            <h2 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-900">Start in the lane that matches how you work</h2>
            <p className="mt-4 text-base leading-7 text-zinc-600">
              Oxidity should feel easy to explore as a solo builder and credible enough to buy for production. Choose the next step that matches where
              you are right now.
            </p>
          </div>
          <div className="mt-8 grid grid-cols-1 gap-5 lg:grid-cols-[1.1fr_0.9fr]">
            <Link
              to="/developers"
              className="group rounded-[28px] border border-white/80 bg-white/80 p-6 shadow-sm transition-all hover:-translate-y-0.5 hover:shadow-md"
            >
              <div className="flex items-center justify-between gap-4">
                <div>
                  <p className="text-sm font-semibold uppercase tracking-[0.16em] text-sky-700">For builders</p>
                  <h3 className="mt-2 text-2xl font-semibold text-zinc-900">Read the docs and test the shape of the API</h3>
                </div>
                <ArrowRight className="h-5 w-5 text-zinc-400 transition-transform group-hover:translate-x-1 group-hover:text-zinc-900" />
              </div>
              <p className="mt-4 max-w-2xl text-sm leading-7 text-zinc-600">
                Start with the RPC surface, partner summary model, and private-routing flow. It is the fastest way to understand whether Oxidity fits your
                product before you ask for staged or production access.
              </p>
            </Link>
            <div className="space-y-4">
              <Link
                to="/partners?requested=staging"
                className="group block rounded-[28px] border border-sky-200 bg-white/85 p-6 shadow-sm transition-all hover:-translate-y-0.5 hover:shadow-md"
              >
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <p className="text-sm font-semibold uppercase tracking-[0.16em] text-emerald-700">For teams</p>
                    <h3 className="mt-2 text-xl font-semibold text-zinc-900">Start onboarding for staging or production</h3>
                  </div>
                  <ArrowRight className="h-5 w-5 text-zinc-400 transition-transform group-hover:translate-x-1 group-hover:text-zinc-900" />
                </div>
                <p className="mt-3 text-sm leading-6 text-zinc-600">
                  Share your traffic shape, timeline, and what you want the service to do for your users.
                </p>
              </Link>
              <div className="rounded-[28px] border border-emerald-200 bg-emerald-50/90 p-6">
                <div className="flex items-center gap-2 text-sm font-medium text-emerald-800">
                  {loading ? <LoaderCircle className="h-4 w-4 animate-spin" /> : publicDataDegraded ? <AlertCircle className="h-4 w-4 text-amber-500" /> : <Activity className="h-4 w-4 text-emerald-600" />}
                  Public service feed
                </div>
                <div className="mt-4 space-y-3">
                  {activity.slice(0, 2).map((entry) => (
                    <div key={entry.id} className="rounded-2xl border border-emerald-100 bg-white/80 p-4">
                      <div className="flex items-center justify-between gap-4">
                        <span className="text-sm font-medium text-zinc-900">{entry.path}</span>
                        <span className="text-xs text-zinc-500">{formatRelativeTime(entry.timestamp)}</span>
                      </div>
                      <p className="mt-2 text-sm text-zinc-600">
                        Status: {entry.status} • Net to user: {formatUsd(entry.netToUserUsd)}
                      </p>
                    </div>
                  ))}
                  {activity.length === 0 && (
                    <div className="rounded-2xl border border-emerald-100 bg-white/80 p-4 text-sm text-zinc-600">
                      No public activity is published right now. Use the status page for current service health and degradations.
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
