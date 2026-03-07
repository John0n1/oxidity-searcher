import { motion } from 'motion/react';

export function SplashView() {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0, scale: 1.02 }}
      transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
      className="absolute inset-0 overflow-hidden bg-[linear-gradient(180deg,#f8fbff_0%,#eef6ff_52%,#f9fbff_100%)]"
    >
      <div className="absolute -left-10 top-0 h-48 w-48 rounded-full bg-blue-300/25 blur-3xl" />
      <div className="absolute right-0 top-28 h-56 w-56 rounded-full bg-cyan-300/18 blur-3xl" />
      <div className="flex h-full flex-col items-center justify-center px-8 text-center">
        <motion.div
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ duration: 0.65, ease: 'easeOut' }}
          className="relative flex h-24 w-24 items-center justify-center rounded-[2rem] border border-white/80 bg-white/90 shadow-[0_30px_80px_rgba(37,99,235,0.18)]"
        >
          <div className="absolute inset-0 rounded-[2rem] bg-[radial-gradient(circle_at_top,_rgba(59,130,246,0.2),_transparent_60%)]" />
          <img src="/brand-mark.svg" alt="Oxidity Wallet" className="relative h-12 w-12" />
        </motion.div>
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2, duration: 0.55 }}
          className="mt-8"
        >
          <h1 className="text-3xl font-extrabold tracking-tight text-slate-950">Oxidity Wallet</h1>
          <p className="mt-2 text-sm font-medium uppercase tracking-[0.18em] text-slate-500">
            Preparing secure local session
          </p>
        </motion.div>
      </div>
    </motion.div>
  );
}
