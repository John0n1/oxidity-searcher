import { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { useAppStore } from '../store/appStore';
import { Shield, Zap, Coins, ArrowRight } from 'lucide-react';
import { cn } from '../utils/cn';

const CARDS = [
  {
    id: 'private',
    icon: Shield,
    title: 'Private Execution',
    description: 'Transactions can be routed privately instead of through the public mempool, keeping your intent hidden.',
    color: 'text-indigo-400',
    bg: 'bg-indigo-500/10',
    border: 'border-indigo-500/20'
  },
  {
    id: 'mev',
    icon: Zap,
    title: 'MEV Protection',
    description: 'Designed to reduce exposure to common hostile execution behavior like front-running and sandwich attacks.',
    color: 'text-emerald-400',
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/20'
  },
  {
    id: 'rebates',
    icon: Coins,
    title: 'Rebates & Coverage',
    description: 'Some transactions may qualify for better execution outcomes, including rebates or gas support.',
    color: 'text-amber-400',
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/20'
  }
];

export function WalkthroughView() {
  const setView = useAppStore((state) => state.setView);
  const [step, setStep] = useState(0);

  const nextStep = () => {
    if (step < CARDS.length - 1) {
      setStep(s => s + 1);
    } else {
      setView('main');
    }
  };

  const skip = () => setView('main');

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, y: -20 }}
      transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
      className="absolute inset-0 flex flex-col p-6"
    >
      <div className="flex justify-end pt-2">
        <button onClick={skip} className="text-zinc-500 font-medium text-sm hover:text-white transition-colors">
          Skip
        </button>
      </div>

      <div className="flex-1 flex flex-col justify-center relative">
        <AnimatePresence mode="wait">
          <motion.div
            key={step}
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -20 }}
            transition={{ duration: 0.3 }}
            className="flex flex-col items-center text-center"
          >
            <div className={cn("w-24 h-24 rounded-full flex items-center justify-center mb-8 border", CARDS[step].bg, CARDS[step].border)}>
              {(() => {
                const Icon = CARDS[step].icon;
                return <Icon className={cn("w-10 h-10", CARDS[step].color)} />;
              })()}
            </div>
            <h2 className="text-3xl font-semibold tracking-tight mb-4">{CARDS[step].title}</h2>
            <p className="text-zinc-400 leading-relaxed max-w-[280px]">
              {CARDS[step].description}
            </p>
          </motion.div>
        </AnimatePresence>
      </div>

      <div className="mt-auto pb-8">
        <div className="flex justify-center gap-2 mb-10">
          {CARDS.map((_, i) => (
            <div
              key={i}
              className={cn(
                "h-1.5 rounded-full transition-all duration-300",
                i === step ? "w-6 bg-white" : "w-1.5 bg-zinc-800"
              )}
            />
          ))}
        </div>

        <button
          onClick={nextStep}
          className="w-full bg-white text-black font-medium py-4 rounded-2xl hover:bg-zinc-200 transition-colors flex items-center justify-center gap-2"
        >
          {step === CARDS.length - 1 ? 'Get Started' : 'Continue'}
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </motion.div>
  );
}
