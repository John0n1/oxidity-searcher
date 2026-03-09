import { motion, AnimatePresence } from 'motion/react';
import { Fingerprint, X } from 'lucide-react';

interface BiometricPromptProps {
  isOpen: boolean;
  onSuccess: () => void;
  onCancel: () => void;
  title?: string;
  subtitle?: string;
}

export function BiometricPrompt({ 
  isOpen, 
  onSuccess, 
  onCancel,
  title = "Authenticate",
  subtitle = "Use Face ID or Touch ID to continue"
}: BiometricPromptProps) {
  return (
    <AnimatePresence>
      {isOpen && (
        <>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[100]"
            onClick={onCancel}
          />
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            className="fixed left-6 right-6 top-1/2 -translate-y-1/2 bg-zinc-900 border border-white/10 rounded-3xl p-6 z-[101] flex flex-col items-center text-center shadow-2xl"
          >
            <button 
              onClick={onCancel}
              className="absolute top-4 right-4 p-2 text-zinc-500 hover:text-white transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
            
            <div className="w-20 h-20 bg-indigo-500/10 rounded-full flex items-center justify-center mb-4">
              <Fingerprint className="w-10 h-10 text-indigo-400" />
            </div>
            
            <h3 className="text-xl font-semibold tracking-tight mb-2">{title}</h3>
            <p className="text-zinc-400 text-sm mb-8">{subtitle}</p>
            
            <button
              onClick={() => {
                // Simulate biometric success after a short delay
                setTimeout(onSuccess, 500);
              }}
              className="w-full bg-indigo-500 text-white font-medium py-3.5 rounded-2xl hover:bg-indigo-600 transition-colors"
            >
              Simulate Success
            </button>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
