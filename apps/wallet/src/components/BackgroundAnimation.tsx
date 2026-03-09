import { Capacitor } from '@capacitor/core';
import { motion } from 'motion/react';

export function BackgroundAnimation() {
  if (Capacitor.isNativePlatform()) {
    return (
      <div className="absolute inset-0 -z-10 overflow-hidden pointer-events-none">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(99,102,241,0.10),transparent_45%),radial-gradient(circle_at_bottom_right,rgba(16,185,129,0.08),transparent_40%)]" />
      </div>
    );
  }

  return (
    <div className="absolute inset-0 -z-10 overflow-hidden pointer-events-none">
      {/* Subtle animated blobs */}
      <motion.div
        animate={{
          x: [0, 100, 0],
          y: [0, 50, 0],
          scale: [1, 1.2, 1],
        }}
        transition={{
          duration: 20,
          repeat: Infinity,
          ease: "linear"
        }}
        className="absolute -top-[10%] -left-[10%] w-[50%] h-[50%] rounded-full bg-indigo-500/10 blur-[120px]"
      />
      <motion.div
        animate={{
          x: [0, -80, 0],
          y: [0, 100, 0],
          scale: [1, 1.1, 1],
        }}
        transition={{
          duration: 25,
          repeat: Infinity,
          ease: "linear"
        }}
        className="absolute top-[20%] -right-[5%] w-[40%] h-[40%] rounded-full bg-emerald-500/5 blur-[100px]"
      />
      <motion.div
        animate={{
          x: [0, 50, 0],
          y: [0, -100, 0],
          scale: [1, 1.3, 1],
        }}
        transition={{
          duration: 30,
          repeat: Infinity,
          ease: "linear"
        }}
        className="absolute -bottom-[10%] left-[20%] w-[60%] h-[60%] rounded-full bg-violet-500/10 blur-[150px]"
      />
      
      {/* Grain overlay for texture */}
      <div className="absolute inset-0 opacity-[0.03] mix-blend-overlay pointer-events-none bg-[radial-gradient(circle,rgba(255,255,255,0.5)_1px,transparent_1px)] [background-size:18px_18px]" />
    </div>
  );
}
