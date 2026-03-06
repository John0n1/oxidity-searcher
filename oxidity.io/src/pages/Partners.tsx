import { useMemo, useState } from 'react';
import { ArrowRight, Building2, CheckCircle2, CircleGauge, Copy, Send, Shield, Users } from 'lucide-react';
import { Link, useSearchParams } from 'react-router-dom';
import { APP_CONFIG } from '../lib/publicData';
import { submitOnboardingRequest } from '../lib/onboarding';
import { diligenceItems, proofCaseStudies } from '../lib/proof';

type TeamType = 'wallet' | 'dapp' | 'searcher' | 'infra';
type VolumeBand = 'under-10k' | '10k-100k' | '100k-1m' | '1m-plus';
type JourneyStage = 'researching' | 'integrating' | 'staging' | 'migrating';
type Timeline = 'exploring' | '30-days' | 'this-quarter' | 'immediate';
type RequestedTrack = 'docs' | 'staging' | 'production' | 'dashboard';
type PrimaryNeed = 'protected-routing' | 'selective-sponsorship' | 'reporting' | 'migration';

const teamProfiles = [
  {
    title: 'Wallets',
    description: 'Improve execution quality for end users while keeping sponsorship and settlement reporting commercially legible.',
    icon: Shield,
  },
  {
    title: 'dApps and protocols',
    description: 'Route high-value user flows privately and apply sponsorship only where the economics and support model are defensible.',
    icon: CircleGauge,
  },
  {
    title: 'Searchers and execution teams',
    description: 'Operate with authenticated infrastructure, policy boundaries, and reporting that works for both operators and finance.',
    icon: Users,
  },
];

const onboardingSteps = [
  {
    title: 'Traffic and fit review',
    description: 'We look at use case, expected traffic, current pain points, and whether Oxidity is the right operating model for the job.',
  },
  {
    title: 'Staging validation',
    description: 'Auth, CIDR policy, summary behavior, and partner workflow are tested before production access is discussed as real.',
  },
  {
    title: 'Commercial and policy alignment',
    description: 'We agree on sponsorship boundaries, reporting expectations, and what a healthy rollout should look like.',
  },
  {
    title: 'Production cutover',
    description: 'Production access is issued when the controls, support expectations, and traffic shape are clear enough to operate responsibly.',
  },
];

const commercialModel = [
  'Platform fee for production access and support',
  'Usage envelopes and rate limits matched to your traffic profile',
  'Optional retained-share economics for sponsored flow where appropriate',
  'Minimum commitments for higher-touch business and enterprise deployments',
];

const goodFit = [
  'You want infrastructure, not a marketing gimmick.',
  'You can integrate server-to-server and handle partner auth correctly.',
  'You care about reporting, auditability, and disciplined sponsorship.',
  'You want a product that can survive commercial scrutiny.',
];

const notFit = [
  'You need a fully open public RPC with no onboarding.',
  'You want broad unbounded gas sponsorship as a default.',
  'You cannot operate bearer auth and source-network controls.',
  'You are looking for anonymous or disposable infrastructure.',
];

function normalizeRequestedTrack(value: string | null): RequestedTrack {
  if (value === 'docs' || value === 'staging' || value === 'production' || value === 'dashboard') {
    return value;
  }
  return 'production';
}

function recommendationFor(
  requestedTrack: RequestedTrack,
  teamType: TeamType,
  volumeBand: VolumeBand,
  journeyStage: JourneyStage,
  timeline: Timeline,
  primaryNeed: PrimaryNeed,
) {
  if (requestedTrack === 'dashboard') {
    return {
      label: 'Partner reporting review',
      response: 'Expect a token and dashboard workflow discussion before broader onboarding.',
      checklist: ['Work email and organization', 'Partner summary use case', 'Why transaction-level reporting matters'],
    };
  }

  if (requestedTrack === 'docs' || journeyStage === 'researching' || timeline === 'exploring') {
    return {
      label: 'Developer sandbox',
      response: 'Start with docs, architecture validation, and a low-friction scoping reply.',
      checklist: ['What flow you want to protect', 'Whether you need sponsorship or private-only routing', 'What success looks like'],
    };
  }

  if (requestedTrack === 'staging' || journeyStage === 'integrating' || journeyStage === 'staging') {
    return {
      label: 'Staging validation',
      response: 'Expect a staged auth and CIDR review before production traffic is accepted.',
      checklist: ['Source IP ranges', 'Expected RPC methods', 'How your product handles path outcomes'],
    };
  }

  if (volumeBand === '1m-plus' || teamType === 'infra') {
    return {
      label: 'Business / enterprise onboarding',
      response: 'Expect traffic review, policy design, and a higher-touch production rollout plan.',
      checklist: ['Traffic envelope and peak load', 'Support expectations', 'Reporting and sponsorship boundaries'],
    };
  }

  if (primaryNeed === 'reporting') {
    return {
      label: 'Partner reporting onboarding',
      response: 'Expect a discussion focused on partner summary detail, exports, and finance-readable outputs.',
      checklist: ['Who consumes reporting', 'Required fields or exports', 'How often the data needs to update'],
    };
  }

  return {
    label: 'Production onboarding',
    response: 'Expect a traffic and commercial fit review followed by staging validation.',
    checklist: ['Monthly transaction band', 'Primary protected routes', 'Target rollout window'],
  };
}

export function Partners() {
  const [searchParams] = useSearchParams();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [org, setOrg] = useState('');
  const [teamType, setTeamType] = useState<TeamType>('wallet');
  const [volumeBand, setVolumeBand] = useState<VolumeBand>('10k-100k');
  const [journeyStage, setJourneyStage] = useState<JourneyStage>('integrating');
  const [timeline, setTimeline] = useState<Timeline>('this-quarter');
  const [requestedTrack, setRequestedTrack] = useState<RequestedTrack>(normalizeRequestedTrack(searchParams.get('requested')));
  const [primaryNeed, setPrimaryNeed] = useState<PrimaryNeed>('protected-routing');
  const [notes, setNotes] = useState('');
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [submittedRequestId, setSubmittedRequestId] = useState<number | null>(null);
  const [submittedAt, setSubmittedAt] = useState('');

  const recommendation = useMemo(
    () => recommendationFor(requestedTrack, teamType, volumeBand, journeyStage, timeline, primaryNeed),
    [journeyStage, primaryNeed, requestedTrack, teamType, timeline, volumeBand],
  );

  const intakePacket = useMemo(
    () =>
      [
        'Oxidity onboarding request',
        `Recommended path: ${recommendation.label}`,
        `Response expectation: ${recommendation.response}`,
        '',
        `Name: ${name || '-'}`,
        `Email: ${email || '-'}`,
        `Organization: ${org || '-'}`,
        `Team type: ${teamType}`,
        `Monthly transaction band: ${volumeBand}`,
        `Current stage: ${journeyStage}`,
        `Timeline: ${timeline}`,
        `Requested track: ${requestedTrack}`,
        `Primary need: ${primaryNeed}`,
        `Notes: ${notes || '-'}`,
        '',
        'Suggested prep:',
        ...recommendation.checklist.map((item) => `- ${item}`),
      ].join('\n'),
    [email, journeyStage, name, notes, org, primaryNeed, recommendation, requestedTrack, teamType, timeline, volumeBand],
  );

  const validate = () => {
    if (!name.trim() || !email.trim() || !org.trim()) {
      setError('Name, email, and organization are required.');
      return false;
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setError('Please provide a valid email address.');
      return false;
    }

    setError('');
    return true;
  };

  const submitRequest = async () => {
    if (!validate()) {
      return;
    }

    setSubmitting(true);
    try {
      const response = await submitOnboardingRequest({
        name: name.trim(),
        email: email.trim(),
        organization: org.trim(),
        teamType,
        volumeBand,
        journeyStage,
        timeline,
        requestedTrack,
        primaryNeed,
        recommendedPath: recommendation.label,
        notes: notes.trim(),
        sourcePage: typeof window === 'undefined' ? undefined : window.location.href,
        intakePacket,
      });
      setError('');
      setSubmittedRequestId(response.requestId);
      setSubmittedAt(response.createdAt);
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : String(submitError));
    } finally {
      setSubmitting(false);
    }
  };

  const copyPacket = async () => {
    if (!validate()) {
      return;
    }

    await navigator.clipboard.writeText(intakePacket);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className="bg-page min-h-screen py-16 sm:py-24">
      <div className="mx-auto max-w-7xl px-6 lg:px-8">
        <div className="mx-auto max-w-3xl text-center">
          <p className="text-sm font-semibold uppercase tracking-[0.18em] text-emerald-700">Teams & Onboarding</p>
          <h1 className="mt-4 text-4xl font-semibold tracking-tight text-zinc-900 sm:text-5xl">
            Production onboarding for teams that want a serious operating model
          </h1>
          <p className="mt-6 text-lg leading-8 text-zinc-600">
            Oxidity is built for teams that want private Ethereum execution, policy-based sponsorship, and reporting that survives both technical and
            commercial review. This page should get you to the right next step quickly, not trap you in a vague contact form.
          </p>
        </div>

        <section className="mt-14 grid grid-cols-1 gap-5 lg:grid-cols-3">
          {teamProfiles.map((profile) => (
            <article key={profile.title} className="rounded-3xl border border-zinc-200 bg-white p-7 shadow-sm">
              <div className="inline-flex rounded-2xl bg-zinc-900 p-3 text-white">
                <profile.icon className="h-5 w-5" />
              </div>
              <h2 className="mt-5 text-xl font-semibold text-zinc-900">{profile.title}</h2>
              <p className="mt-3 text-sm leading-6 text-zinc-600">{profile.description}</p>
            </article>
          ))}
        </section>

        <section className="mt-16 grid grid-cols-1 gap-6 lg:grid-cols-[1.05fr_0.95fr]">
          <div className="rounded-3xl border border-zinc-200 bg-white p-8 shadow-sm">
            <h2 className="text-2xl font-semibold tracking-tight text-zinc-900">Onboarding flow</h2>
            <div className="mt-8 space-y-5">
              {onboardingSteps.map((step, index) => (
                <div key={step.title} className="flex gap-4 rounded-2xl border border-zinc-200 bg-zinc-50 p-5">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-zinc-900 text-sm font-semibold text-white">
                    {index + 1}
                  </div>
                  <div>
                    <h3 className="text-base font-semibold text-zinc-900">{step.title}</h3>
                    <p className="mt-2 text-sm leading-6 text-zinc-600">{step.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-3xl bg-zinc-900 p-8 text-white shadow-sm">
            <div className="inline-flex rounded-2xl bg-white/10 p-3">
              <Building2 className="h-5 w-5" />
            </div>
            <h2 className="mt-5 text-2xl font-semibold">Commercial model</h2>
            <p className="mt-3 text-sm leading-7 text-zinc-300">
              The goal is stable revenue and predictable service quality. Oxidity is not sold as unbounded free execution.
            </p>
            <ul className="mt-6 space-y-4 text-sm leading-6 text-zinc-200">
              {commercialModel.map((item) => (
                <li key={item} className="flex items-start gap-3">
                  <ArrowRight className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
            <div className="mt-8 flex flex-wrap gap-3">
              <Link
                to="/pricing"
                className="inline-flex items-center gap-2 rounded-xl bg-white px-4 py-2.5 text-sm font-semibold text-zinc-900 hover:bg-zinc-100"
              >
                View pricing
                <ArrowRight className="h-4 w-4" />
              </Link>
              <Link
                to="/proof"
                className="inline-flex items-center gap-2 rounded-xl border border-zinc-700 px-4 py-2.5 text-sm font-semibold text-zinc-100 hover:bg-zinc-800"
              >
                Review proof
                <ArrowRight className="h-4 w-4" />
              </Link>
            </div>
          </div>
        </section>

        <section className="mt-16 grid grid-cols-1 gap-6 lg:grid-cols-2">
          <div className="rounded-3xl border border-zinc-200 bg-white p-8 shadow-sm">
            <h2 className="text-2xl font-semibold tracking-tight text-zinc-900">Good fit</h2>
            <ul className="mt-6 space-y-4 text-sm leading-6 text-zinc-700">
              {goodFit.map((item) => (
                <li key={item} className="flex items-start gap-3">
                  <ArrowRight className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
          <div className="rounded-3xl border border-zinc-200 bg-white p-8 shadow-sm">
            <h2 className="text-2xl font-semibold tracking-tight text-zinc-900">Not a fit</h2>
            <ul className="mt-6 space-y-4 text-sm leading-6 text-zinc-700">
              {notFit.map((item) => (
                <li key={item} className="flex items-start gap-3">
                  <ArrowRight className="mt-0.5 h-4 w-4 shrink-0 text-red-500" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section className="mt-16 grid grid-cols-1 gap-6 xl:grid-cols-[1.08fr_0.92fr]">
          <div id="request-access" className="rounded-3xl border border-zinc-200 bg-white p-8 shadow-sm">
            <h2 className="text-2xl font-semibold tracking-tight text-zinc-900">Request onboarding</h2>
            <p className="mt-3 text-sm leading-6 text-zinc-600">
              This form submits directly into Oxidity’s backend intake queue. That makes the first response faster and more useful for both sides.
            </p>

            <div className="mt-8 grid grid-cols-1 gap-4 sm:grid-cols-2">
              <input
                id="onboarding-name"
                name="name"
                autoComplete="name"
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="Your name"
                className="rounded-xl border border-zinc-300 px-3 py-2.5 text-sm"
              />
              <input
                id="onboarding-email"
                name="email"
                autoComplete="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="Work email"
                className="rounded-xl border border-zinc-300 px-3 py-2.5 text-sm"
              />
              <input
                id="onboarding-organization"
                name="organization"
                autoComplete="organization"
                value={org}
                onChange={(event) => setOrg(event.target.value)}
                placeholder="Organization"
                className="rounded-xl border border-zinc-300 px-3 py-2.5 text-sm"
              />
              <select
                id="onboarding-team-type"
                name="team_type"
                value={teamType}
                onChange={(event) => setTeamType(event.target.value as TeamType)}
                className="rounded-xl border border-zinc-300 px-3 py-2.5 text-sm"
              >
                <option value="wallet">Wallet</option>
                <option value="dapp">dApp / Protocol</option>
                <option value="searcher">Searcher / Desk</option>
                <option value="infra">Infra / Other</option>
              </select>
              <select
                id="onboarding-volume-band"
                name="volume_band"
                value={volumeBand}
                onChange={(event) => setVolumeBand(event.target.value as VolumeBand)}
                className="rounded-xl border border-zinc-300 px-3 py-2.5 text-sm"
              >
                <option value="under-10k">Under 10k tx / month</option>
                <option value="10k-100k">10k to 100k tx / month</option>
                <option value="100k-1m">100k to 1m tx / month</option>
                <option value="1m-plus">1m+ tx / month</option>
              </select>
              <select
                id="onboarding-journey-stage"
                name="journey_stage"
                value={journeyStage}
                onChange={(event) => setJourneyStage(event.target.value as JourneyStage)}
                className="rounded-xl border border-zinc-300 px-3 py-2.5 text-sm"
              >
                <option value="researching">Researching</option>
                <option value="integrating">Actively integrating</option>
                <option value="staging">Need staging validation</option>
                <option value="migrating">Migrating existing flow</option>
              </select>
              <select
                id="onboarding-timeline"
                name="timeline"
                value={timeline}
                onChange={(event) => setTimeline(event.target.value as Timeline)}
                className="rounded-xl border border-zinc-300 px-3 py-2.5 text-sm"
              >
                <option value="exploring">Just exploring</option>
                <option value="30-days">Within 30 days</option>
                <option value="this-quarter">This quarter</option>
                <option value="immediate">Immediate need</option>
              </select>
              <select
                id="onboarding-requested-track"
                name="requested_track"
                value={requestedTrack}
                onChange={(event) => setRequestedTrack(event.target.value as RequestedTrack)}
                className="rounded-xl border border-zinc-300 px-3 py-2.5 text-sm"
              >
                <option value="docs">Docs / evaluation</option>
                <option value="staging">Staging access</option>
                <option value="production">Production onboarding</option>
                <option value="dashboard">Dashboard / reporting</option>
              </select>
              <select
                id="onboarding-primary-need"
                name="primary_need"
                value={primaryNeed}
                onChange={(event) => setPrimaryNeed(event.target.value as PrimaryNeed)}
                className="rounded-xl border border-zinc-300 px-3 py-2.5 text-sm sm:col-span-2"
              >
                <option value="protected-routing">Protected routing</option>
                <option value="selective-sponsorship">Selective sponsorship</option>
                <option value="reporting">Reporting and partner summary</option>
                <option value="migration">Migration from another provider</option>
              </select>
              <textarea
                id="onboarding-notes"
                name="notes"
                value={notes}
                onChange={(event) => setNotes(event.target.value)}
                placeholder="Traffic profile, protected routes, current pain points, or rollout blockers"
                className="min-h-32 rounded-xl border border-zinc-300 px-3 py-2.5 text-sm sm:col-span-2"
              />
            </div>

            {error && <p className="mt-4 text-sm text-red-600">{error}</p>}
            {copied && !error && <p className="mt-4 text-sm text-emerald-600">Intake packet copied to clipboard.</p>}
            {submittedRequestId !== null && !error && (
              <div className="mt-4 rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-800">
                <p className="font-semibold text-emerald-900">Request submitted</p>
                <p className="mt-1">
                  Reference #{submittedRequestId} recorded at {submittedAt || 'now'}.
                </p>
                <p className="mt-1">
                  We will respond according to the recommended path above. If you need to coordinate immediately, the copy packet and direct email paths are still available.
                </p>
                {APP_CONFIG.bookingUrl && (
                  <a
                    href={APP_CONFIG.bookingUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="mt-3 inline-flex items-center gap-2 rounded-xl bg-emerald-700 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-800"
                  >
                    Book intro call
                    <ArrowRight className="h-4 w-4" />
                  </a>
                )}
              </div>
            )}

            <div className="mt-6 flex flex-wrap gap-3">
              <button
                onClick={() => void submitRequest()}
                disabled={submitting}
                className="inline-flex items-center gap-2 rounded-xl bg-zinc-900 px-4 py-2.5 text-sm font-semibold text-white hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <Send className="h-4 w-4" />
                {submitting ? 'Submitting...' : 'Submit request'}
              </button>
              <button
                onClick={() => void copyPacket()}
                className="inline-flex items-center gap-2 rounded-xl border border-zinc-300 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-900 hover:bg-zinc-50"
              >
                {copied ? <CheckCircle2 className="h-4 w-4 text-emerald-600" /> : <Copy className="h-4 w-4" />}
                Copy intake packet
              </button>
              <a
                href={`mailto:${APP_CONFIG.supportEmail}?subject=${encodeURIComponent(`Oxidity ${recommendation.label.toLowerCase()}: ${org || 'onboarding request'}`)}`}
                className="inline-flex items-center gap-2 rounded-xl border border-zinc-300 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-900 hover:bg-zinc-50"
              >
                Email ops directly
              </a>
              <Link
                to={requestedTrack === 'docs' ? '/developers' : '/proof'}
                className="inline-flex items-center gap-2 rounded-xl border border-zinc-300 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-900 hover:bg-zinc-50"
              >
                {requestedTrack === 'docs' ? 'Read docs first' : 'Review proof first'}
              </Link>
            </div>
          </div>

          <div className="space-y-6">
            <div className="rounded-3xl bg-zinc-900 p-8 text-white shadow-sm">
              <p className="text-sm font-semibold uppercase tracking-[0.18em] text-emerald-300">Recommended next step</p>
              <h2 className="mt-4 text-3xl font-semibold">{recommendation.label}</h2>
              <p className="mt-4 text-sm leading-7 text-zinc-300">{recommendation.response}</p>
              <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-5">
                <p className="text-sm font-semibold text-white">Come prepared with</p>
                <ul className="mt-3 space-y-3 text-sm leading-6 text-zinc-200">
                  {recommendation.checklist.map((item) => (
                    <li key={item} className="flex items-start gap-3">
                      <ArrowRight className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="rounded-3xl border border-zinc-200 bg-white p-8 shadow-sm">
              <h2 className="text-2xl font-semibold tracking-tight text-zinc-900">Proof to review before buying</h2>
              <div className="mt-6 space-y-4">
                {diligenceItems.map((item) => (
                  <Link key={item.title} to={item.href} className="block rounded-2xl border border-zinc-200 bg-zinc-50 p-5 hover:bg-white">
                    <h3 className="text-base font-semibold text-zinc-900">{item.title}</h3>
                    <p className="mt-2 text-sm leading-6 text-zinc-600">{item.description}</p>
                  </Link>
                ))}
              </div>
            </div>

            <div className="rounded-3xl border border-zinc-200 bg-white p-8 shadow-sm">
              <h2 className="text-2xl font-semibold tracking-tight text-zinc-900">Representative deployment pattern</h2>
              <div className="mt-5 rounded-2xl border border-zinc-200 bg-zinc-50 p-5">
                <p className="text-xs font-semibold uppercase tracking-[0.16em] text-emerald-700">{proofCaseStudies[0].profile}</p>
                <h3 className="mt-3 text-lg font-semibold text-zinc-900">{proofCaseStudies[0].title}</h3>
                <p className="mt-3 text-sm leading-6 text-zinc-600">{proofCaseStudies[0].headline}</p>
              </div>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
