import { motion } from 'motion/react';
import { BarChart3, Coins, ShieldCheck, Zap } from 'lucide-react';

const cards = [
  {
    icon: ShieldCheck,
    title: 'Protected execution',
    body: 'Private routing and policy-based controls are surfaced here when the wallet has live transaction history.',
    tone: 'blue',
  },
  {
    icon: Zap,
    title: 'Gas outcomes',
    body: 'Gas savings and sponsorship decisions will appear after real execution data is available.',
    tone: 'emerald',
  },
  {
    icon: Coins,
    title: 'Rebates',
    body: 'Rebate reporting should be explicit and auditable, not simulated in the UI.',
    tone: 'amber',
  },
];

function toneSurface(tone: string): string {
  switch (tone) {
    case 'emerald':
      return 'bg-emerald-50 text-emerald-600';
    case 'amber':
      return 'bg-amber-50 text-amber-600';
    default:
      return 'bg-blue-50 text-blue-600';
  }
}

export function InsightsTab() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
      transition={{ duration: 0.25 }}
      className="absolute inset-0 overflow-y-auto pb-28"
    >
      <div className="sticky top-0 z-10 border-b border-white/70 bg-white/88 px-6 pb-4 pt-6 backdrop-blur">
        <h2 className="text-2xl font-extrabold tracking-tight text-slate-950">Insights</h2>
        <p className="mt-2 text-sm leading-7 text-slate-600">
          This section stays quiet until there is real execution history to explain.
        </p>
      </div>

      <div className="px-6 py-6">
        <div className="rounded-[2rem] border border-white/80 bg-white/92 p-6 shadow-[0_24px_70px_rgba(15,23,42,0.06)]">
          <div className="rounded-[1.7rem] border border-slate-200 bg-[linear-gradient(135deg,#eff6ff_0%,#ffffff_45%,#eefdf8_100%)] p-6">
            <div className="flex h-14 w-14 items-center justify-center rounded-[1.3rem] bg-white shadow-sm">
              <BarChart3 className="h-7 w-7 text-blue-700" />
            </div>
            <h3 className="mt-6 text-2xl font-bold tracking-tight text-slate-950">No performance history yet</h3>
            <p className="mt-3 max-w-md text-[15px] leading-7 text-slate-600">
              Once the wallet is backed by live receipts and execution reporting, this area will explain what was protected, what was sponsored, and what the user actually received.
            </p>
          </div>

          <div className="mt-5 grid gap-4">
            {cards.map((card) => (
              <div key={card.title} className="rounded-[1.5rem] border border-slate-200 bg-slate-50 p-5">
                <div className={`flex h-11 w-11 items-center justify-center rounded-[1rem] ${toneSurface(card.tone)}`}>
                  <card.icon className="h-5 w-5" />
                </div>
                <h4 className="mt-4 text-lg font-bold tracking-tight text-slate-950">{card.title}</h4>
                <p className="mt-2 text-sm leading-7 text-slate-600">{card.body}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </motion.div>
  );
}
