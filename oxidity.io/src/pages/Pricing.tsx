import { ArrowRight, BadgeCheck, Building2, LockKeyhole, ShieldCheck, Sparkles } from 'lucide-react';
import { Link } from 'react-router-dom';

const plans = [
  {
    name: 'Developer Sandbox',
    audience: 'Solo developers and early-stage builders',
    pricing: 'Free preview',
    summary:
      'Start with docs, integration guidance, and a low-risk path to validate whether private execution belongs in your product.',
    features: [
      'Documentation-first onboarding',
      'Preview integration support',
      'Rate-limited evaluation path',
      'Best for prototypes and architecture validation',
    ],
  },
  {
    name: 'Growth',
    audience: 'Startups shipping production user flow',
    pricing: 'Platform fee + usage envelope',
    summary:
      'Production access for teams that need private routing, policy-based sponsorship, and partner reporting without enterprise overhead.',
    features: [
      'Authenticated production ingress',
      'Partner summary access',
      'Commercial policy envelope',
      'Email support and rollout guidance',
    ],
    featured: true,
  },
  {
    name: 'Business',
    audience: 'Wallets, dApps, searchers, and execution teams',
    pricing: 'Monthly minimum commit',
    summary:
      'A governed operating model for teams that need onboarding, commercial predictability, and higher production confidence.',
    features: [
      'Onboarding and traffic review',
      'Higher throughput and tighter controls',
      'Settlement reporting alignment',
      'Commercial review for sponsored flow',
    ],
  },
  {
    name: 'Enterprise',
    audience: 'Large-volume partners and infrastructure operators',
    pricing: 'Custom contract',
    summary:
      'Designed for teams that need custom controls, support expectations, and a commercial structure that can survive real volume.',
    features: [
      'SLA and escalation path',
      'Custom policy and reporting design',
      'Dedicated onboarding and rollout planning',
      'Contractual support and minimums',
    ],
  },
];

const revenueModel = [
  {
    title: 'Platform fee first',
    description: 'The core business is recurring access and operational support, not speculative one-off value capture.',
    icon: Building2,
  },
  {
    title: 'Usage stays governed',
    description: 'Production access scales with agreed traffic envelopes, rate limits, and policy boundaries.',
    icon: LockKeyhole,
  },
  {
    title: 'Sponsorship stays selective',
    description: 'Gas sponsorship is conditional and capped. It is part of the operating model, not a blanket growth subsidy.',
    icon: ShieldCheck,
  },
  {
    title: 'Success share is optional',
    description: 'For some partners, retained-share economics can complement the base fee. It does not replace durable recurring revenue.',
    icon: Sparkles,
  },
];

const fitSignals = [
  'You want better execution quality without exposing orderflow to the public mempool by default.',
  'You care about policy controls, reporting, and a credible commercial model.',
  'You can integrate server-to-server infrastructure and operate with bearer auth plus network allowlisting.',
  'You want a partner that behaves like infrastructure, not a short-lived promotional feature.',
];

export function Pricing() {
  return (
    <div className="bg-page min-h-screen py-16 sm:py-24">
      <div className="mx-auto max-w-7xl px-6 lg:px-8">
        <div className="mx-auto max-w-3xl text-center">
          <p className="text-sm font-semibold uppercase tracking-[0.18em] text-emerald-700">Pricing & Packaging</p>
          <h1 className="mt-4 text-4xl font-semibold tracking-tight text-zinc-900 sm:text-5xl">
            Packaging designed for adoption and stable revenue
          </h1>
          <p className="mt-6 text-lg leading-8 text-zinc-600">
            Oxidity is sold as execution infrastructure, not as a free-gas promotion. The commercial model is built around recurring access,
            governed traffic, and selective sponsorship that stays economically sane.
          </p>
        </div>

        <section className="mt-14 grid grid-cols-1 gap-5 xl:grid-cols-4">
          {plans.map((plan) => (
            <article
              key={plan.name}
              className={`rounded-3xl p-7 shadow-sm ring-1 ${
                plan.featured
                  ? 'bg-zinc-900 text-white ring-zinc-900'
                  : 'bg-white text-zinc-900 ring-zinc-200'
              }`}
            >
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className={`text-xs font-semibold uppercase tracking-[0.16em] ${plan.featured ? 'text-emerald-300' : 'text-emerald-700'}`}>
                    {plan.audience}
                  </p>
                  <h2 className="mt-3 text-2xl font-semibold">{plan.name}</h2>
                </div>
                {plan.featured && (
                  <span className="rounded-full border border-white/20 bg-white/10 px-3 py-1 text-xs font-medium">
                    Recommended
                  </span>
                )}
              </div>
              <p className={`mt-5 text-sm font-semibold ${plan.featured ? 'text-white' : 'text-zinc-900'}`}>{plan.pricing}</p>
              <p className={`mt-4 text-sm leading-6 ${plan.featured ? 'text-zinc-200' : 'text-zinc-600'}`}>{plan.summary}</p>
              <ul className={`mt-6 space-y-3 text-sm ${plan.featured ? 'text-zinc-100' : 'text-zinc-700'}`}>
                {plan.features.map((feature) => (
                  <li key={feature} className="flex items-start gap-3">
                    <BadgeCheck className={`mt-0.5 h-4 w-4 shrink-0 ${plan.featured ? 'text-emerald-300' : 'text-emerald-600'}`} />
                    <span>{feature}</span>
                  </li>
                ))}
              </ul>
            </article>
          ))}
        </section>

        <section className="mt-16 rounded-3xl border border-zinc-200 bg-white p-8 sm:p-10">
          <div className="max-w-3xl">
            <h2 className="text-2xl font-semibold tracking-tight text-zinc-900">How the business works</h2>
            <p className="mt-3 text-sm leading-7 text-zinc-600">
              Reliability is not only technical. Partners need to believe the economics survive contact with production. Oxidity’s model is designed to
              avoid the usual trap of offering broad sponsorship without a durable revenue floor.
            </p>
          </div>
          <div className="mt-8 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
            {revenueModel.map((item) => (
              <div key={item.title} className="rounded-2xl border border-zinc-200 bg-zinc-50 p-5">
                <div className="inline-flex rounded-xl bg-zinc-900 p-2 text-white">
                  <item.icon className="h-5 w-5" />
                </div>
                <h3 className="mt-4 text-base font-semibold text-zinc-900">{item.title}</h3>
                <p className="mt-2 text-sm leading-6 text-zinc-600">{item.description}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="mt-16 grid grid-cols-1 gap-6 lg:grid-cols-[1.1fr_0.9fr]">
          <div className="rounded-3xl border border-zinc-200 bg-white p-8">
            <h2 className="text-2xl font-semibold tracking-tight text-zinc-900">Good fit signals</h2>
            <ul className="mt-6 space-y-4 text-sm leading-6 text-zinc-700">
              {fitSignals.map((signal) => (
                <li key={signal} className="flex items-start gap-3">
                  <BadgeCheck className="mt-0.5 h-5 w-5 shrink-0 text-emerald-600" />
                  <span>{signal}</span>
                </li>
              ))}
            </ul>
          </div>
          <div className="rounded-3xl bg-zinc-900 p-8 text-white">
            <h2 className="text-2xl font-semibold">Ready to scope an integration?</h2>
            <p className="mt-4 text-sm leading-7 text-zinc-300">
              Start with the documentation if you are evaluating the model, or go straight to onboarding if you already know your traffic profile and
              commercial constraints.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Link
                to="/developers"
                className="inline-flex items-center gap-2 rounded-xl bg-white px-4 py-2.5 text-sm font-semibold text-zinc-900 hover:bg-zinc-100"
              >
                Read docs
                <ArrowRight className="h-4 w-4" />
              </Link>
              <Link
                to="/partners?requested=production"
                className="inline-flex items-center gap-2 rounded-xl border border-zinc-700 px-4 py-2.5 text-sm font-semibold text-zinc-100 hover:bg-zinc-800"
              >
                Request access
                <ArrowRight className="h-4 w-4" />
              </Link>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
