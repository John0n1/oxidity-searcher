import { useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { ArrowRight, BriefcaseBusiness, Coins, Shield, Zap } from 'lucide-react';
import { useAppStore } from '../store/appStore';
import { cn } from '../utils/cn';

const FALLBACK_CARDS = [
  {
    id: 'private',
    icon: Shield,
    title: 'Private execution where it helps',
    description: 'Eligible transactions can avoid the public mempool instead of broadcasting every intent by default.',
    tone: 'blue',
  },
  {
    id: 'sponsorship',
    icon: Coins,
    title: 'Selective sponsorship, clearly explained',
    description: 'Coverage and rebates are policy-based. The wallet should tell you what happened instead of guessing.',
    tone: 'amber',
  },
  {
    id: 'business',
    icon: BriefcaseBusiness,
    title: 'A clean path for teams',
    description: 'The same wallet front door can lead into partner onboarding, controls, and reporting when you need more than a retail app.',
    tone: 'emerald',
  },
];

function toneClasses(tone: string) {
  switch (tone) {
    case 'amber':
      return {
        icon: 'text-amber-600',
        surface: 'bg-amber-50 border-amber-200',
      };
    case 'emerald':
      return {
        icon: 'text-emerald-600',
        surface: 'bg-emerald-50 border-emerald-200',
      };
    default:
      return {
        icon: 'text-blue-600',
        surface: 'bg-blue-50 border-blue-200',
      };
  }
}

export function WalkthroughView() {
  const setView = useAppStore((state) => state.setView);
  const bootstrap = useAppStore((state) => state.bootstrap);
  const [step, setStep] = useState(0);

  const cards = bootstrap?.copy.walkthrough?.length
    ? bootstrap.copy.walkthrough.map((card, index) => ({
        ...card,
        icon: [Shield, Zap, Coins][index] ?? Shield,
        tone: ['blue', 'emerald', 'amber'][index] ?? 'blue',
      }))
    : FALLBACK_CARDS;

  const nextStep = () => {
    if (step < cards.length - 1) {
      setStep((current) => current + 1);
    } else {
      setView('main');
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.97 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, y: -18 }}
      transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
      className="absolute inset-0 overflow-y-auto bg-transparent px-6 pb-8 pt-8"
    >
      <div className="flex justify-end pb-4">
        <button
          onClick={() => setView('main')}
          className="rounded-full border border-white/80 bg-white/80 px-4 py-2 text-sm font-semibold text-slate-600 shadow-sm transition-colors hover:text-slate-950"
        >
          Skip
        </button>
      </div>

      <div className="rounded-[2rem] border border-white/80 bg-white/90 p-6 shadow-[0_30px_80px_rgba(15,23,42,0.08)]">
        <AnimatePresence mode="wait">
          <motion.div
            key={cards[step].id}
            initial={{ opacity: 0, x: 16 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -16 }}
            className="flex min-h-[620px] flex-col"
          >
            <div
              className={cn(
                'flex h-16 w-16 items-center justify-center rounded-[1.4rem] border',
                toneClasses(cards[step].tone).surface
              )}
            >
              {(() => {
                const Icon = cards[step].icon;
                return <Icon className={cn('h-8 w-8', toneClasses(cards[step].tone).icon)} />;
              })()}
            </div>
            <h2 className="mt-8 text-3xl font-extrabold tracking-tight text-slate-950">{cards[step].title}</h2>
            <p className="mt-4 text-[15px] leading-8 text-slate-600">{cards[step].description}</p>
            <div className="mt-8 rounded-[1.5rem] border border-slate-200 bg-slate-50 p-4 text-sm leading-7 text-slate-600">
              This shell is shared across the web app, extension popup, and Android wrapper so onboarding feels consistent across platforms.
            </div>
          </motion.div>
        </AnimatePresence>

        <div className="mt-8">
          <div className="mb-8 flex justify-center gap-2">
            {cards.map((card, index) => (
              <div
                key={card.id}
                className={cn(
                  'h-1.5 rounded-full transition-all duration-300',
                  index === step ? 'w-7 bg-blue-600' : 'w-2 bg-slate-200'
                )}
              />
            ))}
          </div>

          <button
            onClick={nextStep}
            className="flex w-full items-center justify-center gap-2 rounded-[1.3rem] bg-slate-950 px-5 py-4 font-semibold text-white transition-colors hover:bg-slate-900"
          >
            {step === cards.length - 1 ? 'Open wallet' : 'Continue'}
            <ArrowRight className="h-4 w-4" />
          </button>
        </div>
      </div>
    </motion.div>
  );
}
