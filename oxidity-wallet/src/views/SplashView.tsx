import { useEffect } from 'react';
import { motion } from 'motion/react';
import { useAppStore } from '../store/appStore';
import { Logo } from '../components/Logo';

export function SplashView() {
  const setView = useAppStore((state) => state.setView);

  useEffect(() => {
    const timer = setTimeout(() => {
      setView('welcome');
    }, 2500);
    return () => clearTimeout(timer);
  }, [setView]);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0, scale: 1.05 }}
      transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
      className="absolute inset-0 flex flex-col items-center justify-center"
    >
      <motion.div
        initial={{ opacity: 0, y: -20, filter: 'blur(10px)' }}
        animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
        transition={{ delay: 0.2, duration: 0.8, ease: "easeOut" }}
        className="mb-10 text-center"
      >
        <h1 className="text-4xl font-semibold tracking-tight text-white">Oxidity</h1>
        <p className="text-indigo-400/80 text-sm mt-2 tracking-[0.2em] uppercase font-medium">Private Execution</p>
      </motion.div>

      <div className="relative">
        <motion.div
          animate={{
            scale: [1, 1.2, 1],
            opacity: [0.3, 0.8, 0.3],
          }}
          transition={{
            duration: 2,
            repeat: Infinity,
            ease: "easeInOut"
          }}
          className="absolute inset-0 bg-indigo-500/30 blur-3xl rounded-full"
        />
        <motion.div
          initial={{ scale: 0.8, opacity: 0, rotate: -10 }}
          animate={{ scale: 1, opacity: 1, rotate: 0 }}
          transition={{ delay: 0.4, duration: 0.8, ease: "easeOut" }}
          className="relative z-10 bg-zinc-900/50 p-6 rounded-3xl border border-white/5 backdrop-blur-xl"
        >
          <Logo className="w-16 h-16 text-indigo-500" />
        </motion.div>
      </div>
    </motion.div>
  );
}
