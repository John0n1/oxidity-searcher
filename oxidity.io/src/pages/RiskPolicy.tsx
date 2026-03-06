import { AlertTriangle, Ban, FileText, ShieldAlert } from 'lucide-react';

const principles = [
  'Simulation-first decisions before any sponsorship path is chosen.',
  'No blanket promise that every transaction will be gas-sponsored.',
  'Private-only fallback remains available when sponsorship is not justified.',
  'Settlement reporting must explain where value went after execution.',
];

const exclusions = [
  'Flows that cannot be simulated with enough confidence to support a policy decision.',
  'Transactions whose contract behavior, proxy behavior, or route complexity is outside the supported safety envelope.',
  'Traffic that breaches spend limits, abuse thresholds, or operational policy.',
  'Addresses, routes, or patterns that are blocked for security, compliance, or abuse-control reasons.',
];

export function RiskPolicy() {
  return (
    <div className="bg-page min-h-screen py-12">
      <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8">
        <div className="mb-12">
          <h1 className="flex items-center gap-3 text-3xl font-bold tracking-tight text-zinc-900">
            <ShieldAlert className="h-8 w-8 text-zinc-900" />
            Risk Policy & Sponsorship Guardrails
          </h1>
          <p className="mt-4 text-lg text-zinc-600">
            Oxidity is built around controlled execution, not unbounded incentives. This page explains the principles behind sponsorship, fallback, and
            exclusion decisions.
          </p>
        </div>

        <div className="space-y-12">
          <section className="rounded-2xl bg-white p-8 shadow-sm ring-1 ring-zinc-200">
            <div className="mb-6 flex items-center gap-3">
              <FileText className="h-6 w-6 text-zinc-900" />
              <h2 className="text-xl font-semibold text-zinc-900">Core principles</h2>
            </div>
            <ul className="space-y-3 text-sm leading-6 text-zinc-700">
              {principles.map((principle) => (
                <li key={principle} className="flex items-start gap-3">
                  <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" />
                  <span>{principle}</span>
                </li>
              ))}
            </ul>
          </section>

          <section className="rounded-2xl bg-white p-8 shadow-sm ring-1 ring-zinc-200">
            <div className="mb-6 flex items-center gap-3">
              <AlertTriangle className="h-6 w-6 text-zinc-900" />
              <h2 className="text-xl font-semibold text-zinc-900">Current public guardrails</h2>
            </div>
            <div className="prose prose-zinc max-w-none text-zinc-600">
              <p>
                Publicly disclosed baseline policy currently caps coverage at <strong>0.05 ETH per transaction</strong> and <strong>0.5 ETH per day</strong>.
                These values are guardrails, not promises of eligibility.
              </p>
              <div className="mt-6 rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-800">
                If a flow is not eligible for sponsorship, the system can still keep it on a <strong>private-only</strong> route when policy allows.
              </div>
            </div>
          </section>

          <section className="rounded-2xl bg-white p-8 shadow-sm ring-1 ring-zinc-200">
            <div className="mb-6 flex items-center gap-3">
              <Ban className="h-6 w-6 text-zinc-900" />
              <h2 className="text-xl font-semibold text-zinc-900">Excluded or blocked conditions</h2>
            </div>
            <ul className="space-y-3 text-sm leading-6 text-zinc-700">
              {exclusions.map((item) => (
                <li key={item} className="flex items-start gap-3">
                  <Ban className="mt-0.5 h-4 w-4 shrink-0 text-red-500" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </section>

          <section className="rounded-2xl bg-zinc-900 p-8 text-white shadow-sm">
            <h2 className="text-xl font-semibold">Commercial interpretation</h2>
            <p className="mt-3 text-sm leading-6 text-zinc-300">
              Sponsorship is part of a disciplined operating model. The objective is not to maximize subsidized volume at any cost. The objective is to
              protect execution quality while keeping the economics and support burden sustainable.
            </p>
          </section>
        </div>
      </div>
    </div>
  );
}
