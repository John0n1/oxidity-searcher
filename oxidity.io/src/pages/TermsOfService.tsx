import { FileText, Scale, ShieldCheck, Wallet } from 'lucide-react';
import { APP_CONFIG } from '../lib/publicData';

const EFFECTIVE_DATE = 'March 5, 2026';

export function TermsOfService() {
  return (
    <div className="bg-page min-h-screen py-12">
      <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8">
        <div className="mb-10">
          <h1 className="text-3xl font-bold tracking-tight text-zinc-900 flex items-center gap-3">
            <FileText className="w-8 h-8 text-zinc-900" />
            Terms of Service
          </h1>
          <p className="mt-3 text-base text-zinc-600">
            Effective date: {EFFECTIVE_DATE}
          </p>
        </div>

        <div className="space-y-8">
          <section className="rounded-2xl border border-zinc-200 bg-white p-8 shadow-sm">
            <h2 className="text-xl font-semibold text-zinc-900">1. Scope of Service</h2>
            <p className="mt-3 text-sm leading-7 text-zinc-600">
              Oxidity provides private Ethereum transaction routing, policy-based sponsorship decisions, and execution settlement reporting. Services may include
              public informational endpoints and partner-only access tiers with additional capabilities.
            </p>
          </section>

          <section className="rounded-2xl border border-zinc-200 bg-white p-8 shadow-sm">
            <h2 className="text-xl font-semibold text-zinc-900">2. Acceptable Use</h2>
            <ul className="mt-4 list-disc pl-5 space-y-2 text-sm leading-7 text-zinc-600">
              <li>Do not submit malicious, fraudulent, or unlawful transaction flow.</li>
              <li>Do not attempt to bypass authentication, quotas, or policy controls.</li>
              <li>Do not abuse endpoint capacity with denial-of-service style traffic.</li>
              <li>Use bearer tokens and partner credentials only for the account they were issued to.</li>
            </ul>
          </section>

          <section className="rounded-2xl border border-zinc-200 bg-white p-8 shadow-sm">
              <h2 className="text-xl font-semibold text-zinc-900 flex items-center gap-2">
              <ShieldCheck className="h-5 w-5 text-zinc-800" />
              3. Policy-Based Sponsorship
            </h2>
            <p className="mt-3 text-sm leading-7 text-zinc-600">
              Sponsorship is conditional. Eligibility is determined by live simulation, risk controls, and operating caps. A request can be routed privately without
              being eligible for sponsorship.
            </p>
            <p className="mt-3 text-sm leading-7 text-zinc-600">
              Oxidity may change policy thresholds, safety controls, and spend limits to maintain system integrity.
            </p>
          </section>

          <section className="rounded-2xl border border-zinc-200 bg-white p-8 shadow-sm">
            <h2 className="text-xl font-semibold text-zinc-900 flex items-center gap-2">
              <Wallet className="h-5 w-5 text-zinc-800" />
              4. Settlement and Rebates
            </h2>
            <p className="mt-3 text-sm leading-7 text-zinc-600">
              Where applicable, settlement reporting includes gas covered/refunded, retained share, and rebate amounts. These values are based on included transaction
              outcomes and service-side accounting logic.
            </p>
            <p className="mt-3 text-sm leading-7 text-zinc-600">
              Timing of settlement visibility and any payout rails may vary by endpoint tier and operational conditions.
            </p>
          </section>

          <section className="rounded-2xl border border-zinc-200 bg-white p-8 shadow-sm">
            <h2 className="text-xl font-semibold text-zinc-900 flex items-center gap-2">
              <Scale className="h-5 w-5 text-zinc-800" />
              5. No Inclusion or Profit Guarantee
            </h2>
            <p className="mt-3 text-sm leading-7 text-zinc-600">
              Private routing and policy evaluation are best-effort services. Inclusion time, execution quality, value capture, and net outcome are not guaranteed under
              all market conditions.
            </p>
          </section>

          <section className="rounded-2xl border border-zinc-200 bg-white p-8 shadow-sm">
            <h2 className="text-xl font-semibold text-zinc-900">6. Suspension and Termination</h2>
            <p className="mt-3 text-sm leading-7 text-zinc-600">
              Access can be suspended or terminated for abuse, policy violations, security concerns, or sustained harmful traffic patterns. Emergency controls may be
              applied without prior notice to protect infrastructure and users.
            </p>
          </section>

          <section className="rounded-2xl border border-zinc-200 bg-white p-8 shadow-sm">
            <h2 className="text-xl font-semibold text-zinc-900">7. Contact</h2>
            <p className="mt-3 text-sm leading-7 text-zinc-600">
              Questions about these terms can be sent to{' '}
              <a href={`mailto:${APP_CONFIG.supportEmail}`} className="font-medium text-zinc-900 hover:text-zinc-700">
                {APP_CONFIG.supportEmail}
              </a>
              .
            </p>
          </section>
        </div>
      </div>
    </div>
  );
}
