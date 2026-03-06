import { ArrowRight, BadgeCheck, Building2, FileCheck2 } from 'lucide-react';
import { Link } from 'react-router-dom';
import { diligenceItems, proofCaseStudies, proofCategories } from '../lib/proof';

export function Proof() {
  return (
    <div className="bg-page min-h-screen py-16 sm:py-24">
      <div className="mx-auto max-w-7xl px-6 lg:px-8">
        <div className="mx-auto max-w-3xl text-center">
          <p className="text-sm font-semibold uppercase tracking-[0.18em] text-emerald-700">Proof & Diligence</p>
          <h1 className="mt-4 text-4xl font-semibold tracking-tight text-zinc-900 sm:text-5xl">
            The proof should look like infrastructure, not theater
          </h1>
          <p className="mt-6 text-lg leading-8 text-zinc-600">
            Production buyers do not always want public attribution. Until named references exist, Oxidity should win trust through anonymized
            deployment patterns, explicit controls, and due-diligence surfaces that are easy to verify.
          </p>
        </div>

        <section className="mt-14 rounded-3xl border border-zinc-200 bg-white p-8 shadow-sm">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-3xl">
              <h2 className="text-2xl font-semibold tracking-tight text-zinc-900">Built for these team shapes</h2>
              <p className="mt-3 text-sm leading-7 text-zinc-600">
                The categories below are not logo substitutions. They are the buyer profiles this product is actually structured to support.
              </p>
            </div>
            <Link to="/partners?requested=production" className="text-sm font-semibold text-zinc-900 hover:text-zinc-600">
              Request production access <span aria-hidden>→</span>
            </Link>
          </div>
          <div className="mt-8 grid grid-cols-2 gap-4 md:grid-cols-4">
            {proofCategories.map((category) => (
              <div key={category} className="rounded-2xl border border-zinc-200 bg-zinc-50 px-4 py-5 text-center text-sm font-semibold text-zinc-900">
                {category}
              </div>
            ))}
          </div>
        </section>

        <section className="mt-16">
          <div className="max-w-3xl">
            <p className="text-sm font-semibold uppercase tracking-[0.18em] text-emerald-700">Anonymized deployment patterns</p>
            <h2 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-900">Representative rollouts buyers can recognize</h2>
            <p className="mt-4 text-base leading-7 text-zinc-600">
              These are intentionally anonymized. The goal is to show the operating changes Oxidity is built to support, not to invent reference-brand
              theater.
            </p>
          </div>
          <div className="mt-8 grid grid-cols-1 gap-6 xl:grid-cols-3">
            {proofCaseStudies.map((study) => (
              <article key={study.title} className="rounded-3xl border border-zinc-200 bg-white p-8 shadow-sm">
                <div className="inline-flex rounded-full bg-emerald-50 px-3 py-1 text-xs font-semibold uppercase tracking-[0.14em] text-emerald-700">
                  {study.profile}
                </div>
                <h3 className="mt-5 text-2xl font-semibold tracking-tight text-zinc-900">{study.title}</h3>
                <p className="mt-3 text-base leading-7 text-zinc-700">{study.headline}</p>
                <p className="mt-4 text-sm leading-6 text-zinc-600">{study.summary}</p>

                <div className="mt-6 rounded-2xl border border-zinc-200 bg-zinc-50 p-4">
                  <p className="text-xs font-semibold uppercase tracking-[0.14em] text-zinc-500">Operating environment</p>
                  <p className="mt-2 text-sm leading-6 text-zinc-700">{study.environment}</p>
                </div>

                <div className="mt-6">
                  <p className="text-sm font-semibold text-zinc-900">What changed</p>
                  <ul className="mt-3 space-y-3 text-sm leading-6 text-zinc-700">
                    {study.shifts.map((item) => (
                      <li key={item} className="flex items-start gap-3">
                        <BadgeCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" />
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="mt-6 border-t border-zinc-200 pt-6">
                  <p className="text-sm font-semibold text-zinc-900">Why buyers care</p>
                  <ul className="mt-3 space-y-3 text-sm leading-6 text-zinc-700">
                    {study.buyerSignals.map((item) => (
                      <li key={item} className="flex items-start gap-3">
                        <ArrowRight className="mt-0.5 h-4 w-4 shrink-0 text-zinc-500" />
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </article>
            ))}
          </div>
        </section>

        <section className="mt-16 grid grid-cols-1 gap-6 lg:grid-cols-[1.02fr_0.98fr]">
          <div className="rounded-3xl border border-zinc-200 bg-white p-8 shadow-sm">
            <div className="inline-flex rounded-2xl bg-zinc-900 p-3 text-white">
              <FileCheck2 className="h-5 w-5" />
            </div>
            <h2 className="mt-5 text-2xl font-semibold tracking-tight text-zinc-900">Due-diligence packet</h2>
            <p className="mt-3 text-sm leading-7 text-zinc-600">
              Serious buyers typically ask the same questions. The goal is to make those answers visible before a sales call is required.
            </p>
            <div className="mt-8 space-y-4">
              {diligenceItems.map((item) => (
                <Link
                  key={item.title}
                  to={item.href}
                  className="block rounded-2xl border border-zinc-200 bg-zinc-50 p-5 transition-colors hover:bg-white"
                >
                  <h3 className="text-base font-semibold text-zinc-900">{item.title}</h3>
                  <p className="mt-2 text-sm leading-6 text-zinc-600">{item.description}</p>
                </Link>
              ))}
            </div>
          </div>

          <div className="rounded-3xl bg-zinc-900 p-8 text-white shadow-sm">
            <div className="inline-flex rounded-2xl bg-white/10 p-3">
              <Building2 className="h-5 w-5" />
            </div>
            <h2 className="mt-5 text-2xl font-semibold">What stands out in a first review</h2>
            <div className="mt-6 space-y-5 text-sm leading-7 text-zinc-300">
              <div>
                <p className="font-semibold text-white">For product teams</p>
                <p className="mt-1">Can we improve execution quality without creating a support or treasury mess?</p>
              </div>
              <div>
                <p className="font-semibold text-white">For ops and infra</p>
                <p className="mt-1">Is access controlled, rate-limited, and realistic for server-to-server production use?</p>
              </div>
              <div>
                <p className="font-semibold text-white">For finance and leadership</p>
                <p className="mt-1">Is the business model durable, and can the value split be explained after the fact?</p>
              </div>
            </div>
            <div className="mt-8 rounded-2xl border border-white/10 bg-white/5 p-5 text-sm leading-6 text-zinc-200">
              The most credible version of Oxidity is not “magic MEV money.” It is a controlled execution product with explicit rules, measurable
              outcomes, and a commercial model that does not collapse the moment traffic arrives.
            </div>
            <div className="mt-8 flex flex-wrap gap-3">
              <Link
                to="/partners?requested=production"
                className="inline-flex items-center gap-2 rounded-xl bg-white px-4 py-2.5 text-sm font-semibold text-zinc-900 hover:bg-zinc-100"
              >
                Start onboarding
                <ArrowRight className="h-4 w-4" />
              </Link>
              <Link
                to="/pricing"
                className="inline-flex items-center gap-2 rounded-xl border border-zinc-700 px-4 py-2.5 text-sm font-semibold text-zinc-100 hover:bg-zinc-800"
              >
                Review packaging
                <ArrowRight className="h-4 w-4" />
              </Link>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
