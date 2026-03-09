import { motion } from 'motion/react';
import { useAppStore } from '../store/appStore';
import { Shield, ArrowRight, PlayCircle } from 'lucide-react';
import { Logo } from '../components/Logo';

export function WelcomeView() {
  const setView = useAppStore((state) => state.setView);

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, x: -20 }}
      transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
      className="absolute inset-0 flex flex-col p-6"
    >
      <div className="flex-1 flex flex-col justify-center items-center text-center mt-12">
        <div className="relative mb-8">
          <div className="absolute inset-0 bg-indigo-500/20 blur-2xl rounded-full" />
          <div className="relative z-10 bg-zinc-900/80 p-5 rounded-3xl border border-white/10 backdrop-blur-xl">
            <Logo className="w-12 h-12 text-indigo-500" />
          </div>
        </div>

        <h1 className="text-4xl font-semibold tracking-tight text-white mb-4">
          The Smarter<br />Ethereum Wallet
        </h1>
        <p className="text-zinc-400 text-base max-w-[280px] leading-relaxed">
          Private execution, MEV protection, and smarter transaction outcomes.
        </p>

        <div className="mt-12 w-full space-y-3">
          <button
            onClick={() => setView('create-wallet')}
            className="w-full bg-white text-black font-medium py-4 rounded-2xl hover:bg-zinc-200 transition-colors flex items-center justify-center gap-2"
          >
            Create Wallet
            <ArrowRight className="w-4 h-4" />
          </button>
          
          <button
            onClick={() => setView('import-wallet')}
            className="w-full bg-zinc-900 text-white font-medium py-4 rounded-2xl border border-white/5 hover:bg-zinc-800 transition-colors"
          >
            Import Wallet
          </button>
        </div>

        <button className="mt-8 text-zinc-500 text-sm font-medium flex items-center gap-2 hover:text-zinc-300 transition-colors">
          <PlayCircle className="w-4 h-4" />
          Watch Demo
        </button>
      </div>
    </motion.div>
  );
}
