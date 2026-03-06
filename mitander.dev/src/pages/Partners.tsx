import { useState } from 'react';
import { ArrowRight, Send, Shield, Users, Zap } from 'lucide-react';
import { Link } from 'react-router-dom';
import { APP_CONFIG } from '../lib/publicData';

type PartnerType = 'wallet' | 'dapp' | 'searcher';

export function Partners() {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [org, setOrg] = useState('');
  const [partnerType, setPartnerType] = useState<PartnerType>('wallet');
  const [notes, setNotes] = useState('');
  const [error, setError] = useState('');
  const [submitted, setSubmitted] = useState(false);

  const submit = () => {
    if (!name.trim() || !email.trim() || !org.trim()) {
      setError('Name, email, and organization are required.');
      return;
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setError('Please provide a valid email address.');
      return;
    }

    const subject = encodeURIComponent(`Partner onboarding request: ${org}`);
    const body = encodeURIComponent(
      [
        `Name: ${name}`,
        `Email: ${email}`,
        `Organization: ${org}`,
        `Partner type: ${partnerType}`,
        `Notes: ${notes || '-'}`,
      ].join('\n'),
    );

    window.location.href = `mailto:${APP_CONFIG.supportEmail}?subject=${subject}&body=${body}`;
    setError('');
    setSubmitted(true);
  };

  return (
    <div className="bg-page min-h-screen py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-6 lg:px-8">
        <div className="mx-auto max-w-2xl lg:text-center">
          <h2 className="text-base font-semibold leading-7 text-emerald-600">Partner Program</h2>
          <p className="mt-2 text-3xl font-bold tracking-tight text-zinc-900 sm:text-4xl">Integrate Mitander</p>
          <p className="mt-6 text-lg leading-8 text-zinc-600">
            Wallets, dApps, and searchers can forward private orderflow to our RPC and unlock conditional gas coverage + rebate sharing for users.
          </p>
        </div>

        <div className="mx-auto mt-16 max-w-2xl sm:mt-20 lg:mt-24 lg:max-w-none">
          <dl className="grid max-w-xl grid-cols-1 gap-x-8 gap-y-16 lg:max-w-none lg:grid-cols-3">
            <div className="flex flex-col bg-white rounded-2xl p-8 shadow-sm ring-1 ring-zinc-200">
              <dt className="flex items-center gap-x-3 text-base font-semibold leading-7 text-zinc-900">
                <div className="h-10 w-10 flex items-center justify-center rounded-lg bg-zinc-900">
                  <Shield className="h-6 w-6 text-white" aria-hidden="true" />
                </div>
                Wallets
              </dt>
              <dd className="mt-4 flex flex-auto flex-col text-base leading-7 text-zinc-600">
                <p className="flex-auto">Default private RPC routing with conditional gas coverage and transparent settlement receipts.</p>
                <p className="mt-6">
                  <Link to="/developers" className="text-sm font-semibold leading-6 text-emerald-600 flex items-center gap-1">
                    Integration Guide <ArrowRight className="w-4 h-4" />
                  </Link>
                </p>
              </dd>
            </div>
            <div className="flex flex-col bg-white rounded-2xl p-8 shadow-sm ring-1 ring-zinc-200">
              <dt className="flex items-center gap-x-3 text-base font-semibold leading-7 text-zinc-900">
                <div className="h-10 w-10 flex items-center justify-center rounded-lg bg-zinc-900">
                  <Zap className="h-6 w-6 text-white" aria-hidden="true" />
                </div>
                dApps & DEXs
              </dt>
              <dd className="mt-4 flex flex-auto flex-col text-base leading-7 text-zinc-600">
                <p className="flex-auto">Forward swap/orderflow through private ingress and expose coverage eligibility upfront to users.</p>
                <p className="mt-6">
                  <Link to="/how-it-works" className="text-sm font-semibold leading-6 text-emerald-600 flex items-center gap-1">
                    Flow Details <ArrowRight className="w-4 h-4" />
                  </Link>
                </p>
              </dd>
            </div>
            <div className="flex flex-col bg-white rounded-2xl p-8 shadow-sm ring-1 ring-zinc-200">
              <dt className="flex items-center gap-x-3 text-base font-semibold leading-7 text-zinc-900">
                <div className="h-10 w-10 flex items-center justify-center rounded-lg bg-zinc-900">
                  <Users className="h-6 w-6 text-white" aria-hidden="true" />
                </div>
                Searchers
              </dt>
              <dd className="mt-4 flex flex-auto flex-col text-base leading-7 text-zinc-600">
                <p className="flex-auto">Low-latency private submission with deterministic policy decisions and rebate-friendly settlement rails.</p>
                <p className="mt-6">
                  <Link to="/dashboard" className="text-sm font-semibold leading-6 text-emerald-600 flex items-center gap-1">
                    View Dashboard <ArrowRight className="w-4 h-4" />
                  </Link>
                </p>
              </dd>
            </div>
          </dl>
        </div>

        <div className="mt-16 rounded-2xl bg-white p-8 shadow-sm ring-1 ring-zinc-200 max-w-3xl mx-auto">
          <h3 className="text-lg font-semibold text-zinc-900">Request onboarding</h3>
          <p className="mt-1 text-sm text-zinc-600">We’ll respond with integration steps, policy envelope, and staging access details.</p>

          <div className="mt-6 grid grid-cols-1 sm:grid-cols-2 gap-4">
            <input
              id="onboarding-name"
              name="name"
              autoComplete="name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="Your name"
              className="rounded-lg border border-zinc-300 px-3 py-2 text-sm"
            />
            <input
              id="onboarding-email"
              name="email"
              autoComplete="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="Work email"
              className="rounded-lg border border-zinc-300 px-3 py-2 text-sm"
            />
            <input
              id="onboarding-organization"
              name="organization"
              autoComplete="organization"
              value={org}
              onChange={(event) => setOrg(event.target.value)}
              placeholder="Organization"
              className="rounded-lg border border-zinc-300 px-3 py-2 text-sm"
            />
            <select
              id="onboarding-partner-type"
              name="partner_type"
              value={partnerType}
              onChange={(event) => setPartnerType(event.target.value as PartnerType)}
              className="rounded-lg border border-zinc-300 px-3 py-2 text-sm"
            >
              <option value="wallet">Wallet</option>
              <option value="dapp">dApp/DEX</option>
              <option value="searcher">Searcher</option>
            </select>
            <textarea
              id="onboarding-notes"
              name="notes"
              value={notes}
              onChange={(event) => setNotes(event.target.value)}
              placeholder="What volume or use case are you planning to route?"
              className="sm:col-span-2 rounded-lg border border-zinc-300 px-3 py-2 text-sm min-h-28"
            />
          </div>

          {error && <p className="mt-4 text-sm text-red-600">{error}</p>}
          {submitted && !error && <p className="mt-4 text-sm text-emerald-600">Draft email opened. Send it to start onboarding.</p>}

          <div className="mt-6">
            <button
              onClick={submit}
              className="inline-flex items-center gap-2 rounded-md bg-zinc-900 px-4 py-2 text-sm font-semibold text-white hover:bg-zinc-800"
            >
              <Send className="h-4 w-4" />
              Submit Request
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
