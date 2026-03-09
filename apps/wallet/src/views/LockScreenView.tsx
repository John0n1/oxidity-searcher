import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { useAppStore } from '../store/appStore';
import { Fingerprint, ChevronLeft } from 'lucide-react';
import { cn } from '../utils/cn';
import { Logo } from '../components/Logo';
import { unlockWithBiometrics } from '../lib/nativeAuth';

export function LockScreenView() {
  const unlockWallet = useAppStore((state) => state.unlockWallet);
  const biometricsEnabled = useAppStore((state) => state.biometricsEnabled);
  const [passcode, setPasscode] = useState('');
  const [showBiometrics, setShowBiometrics] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [isBiometricLoading, setIsBiometricLoading] = useState(false);

  useEffect(() => {
    if (biometricsEnabled) {
      const timer = window.setTimeout(() => setShowBiometrics(true), 500);
      return () => window.clearTimeout(timer);
    }
  }, [biometricsEnabled]);

  useEffect(() => {
    if (!showBiometrics || !biometricsEnabled) {
      return;
    }
    void handleBiometricUnlock();
  }, [showBiometrics, biometricsEnabled]);

  const submitPasscode = async (candidate: string) => {
    setIsUnlocking(true);
    setErrorMessage(null);
    try {
      const unlocked = await unlockWallet(candidate);
      if (!unlocked) {
        setPasscode('');
        setErrorMessage('Incorrect passcode');
      } else {
        setPasscode('');
      }
    } catch (error) {
      setPasscode('');
      setErrorMessage(error instanceof Error ? error.message : 'Unlock failed');
    } finally {
      setIsUnlocking(false);
    }
  };

  const handleBiometricUnlock = async () => {
    setIsBiometricLoading(true);
    setErrorMessage(null);
    try {
      const storedPasscode = await unlockWithBiometrics();
      if (!storedPasscode) {
        throw new Error('Biometric unlock is not available on this device');
      }
      const unlocked = await unlockWallet(storedPasscode);
      if (!unlocked) {
        throw new Error('Saved biometric unlock is no longer valid');
      }
      setPasscode('');
      setShowBiometrics(false);
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Biometric authentication failed',
      );
    } finally {
      setIsBiometricLoading(false);
    }
  };

  const handlePasscode = (n: string) => {
    if (passcode.length < 6 && !isUnlocking) {
      setErrorMessage(null);
      const newPass = passcode + n;
      setPasscode(newPass);
      if (newPass.length === 6) {
        void submitPasscode(newPass);
      }
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className="absolute inset-0 bg-zinc-950 flex flex-col z-50"
    >
      <div className="flex-1 flex flex-col items-center justify-center px-6">
        <div className="w-16 h-16 bg-zinc-900 rounded-2xl flex items-center justify-center border border-white/5 mb-6">
          <Logo className="w-10 h-10 text-indigo-500" />
        </div>
        <h2 className="text-2xl font-semibold tracking-tight mb-2">Welcome Back</h2>
        <p className="text-zinc-400 mb-8">Enter your passcode to unlock</p>

        <div className="flex justify-center gap-3 mb-12">
          {[...Array(6)].map((_, i) => (
            <div
              key={i}
              className={cn(
                "w-4 h-4 rounded-full border-2 transition-colors",
                i < passcode.length ? "bg-white border-white" : "border-zinc-800"
              )}
            />
          ))}
        </div>
        {errorMessage && (
          <p className="text-sm text-red-400 mb-6 text-center">{errorMessage}</p>
        )}

        <div className="w-full max-w-xs grid grid-cols-3 gap-4 mb-8">
          {[1, 2, 3, 4, 5, 6, 7, 8, 9].map((n) => (
            <button
              key={n}
              onClick={() => handlePasscode(n.toString())}
              disabled={isUnlocking}
              className="h-16 rounded-2xl text-2xl font-medium flex items-center justify-center bg-zinc-900 hover:bg-zinc-800 active:bg-zinc-700 transition-colors"
            >
              {n}
            </button>
          ))}
          
          <button
            onClick={() => setShowBiometrics(true)}
            disabled={!biometricsEnabled || isBiometricLoading}
            className={cn(
              "h-16 rounded-2xl flex items-center justify-center transition-colors",
              biometricsEnabled ? "bg-zinc-900 hover:bg-zinc-800 active:bg-zinc-700" : "opacity-0 pointer-events-none"
            )}
          >
            <Fingerprint className="w-6 h-6" />
          </button>
          
          <button
            onClick={() => handlePasscode('0')}
            disabled={isUnlocking}
            className="h-16 rounded-2xl text-2xl font-medium flex items-center justify-center bg-zinc-900 hover:bg-zinc-800 active:bg-zinc-700 transition-colors"
          >
            0
          </button>
          
          <button
            onClick={() => setPasscode(p => p.slice(0, -1))}
            disabled={isUnlocking}
            className="h-16 rounded-2xl flex items-center justify-center bg-zinc-900 hover:bg-zinc-800 active:bg-zinc-700 transition-colors"
          >
            <ChevronLeft className="w-6 h-6" />
          </button>
        </div>
      </div>

      {/* Biometric Prompt Overlay */}
      <AnimatePresence>
        {showBiometrics && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[100]"
              onClick={() => setShowBiometrics(false)}
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="fixed left-6 right-6 top-1/2 -translate-y-1/2 bg-zinc-900 border border-white/10 rounded-3xl p-6 z-[101] flex flex-col items-center text-center shadow-2xl"
            >
              <div className="w-20 h-20 bg-indigo-500/10 rounded-full flex items-center justify-center mb-4">
                <Fingerprint className="w-10 h-10 text-indigo-400" />
              </div>
              
              <h3 className="text-xl font-semibold tracking-tight mb-2">Face ID</h3>
              <p className="text-zinc-400 text-sm mb-8">Authenticate to unlock wallet</p>
              
              <button
                onClick={() => void handleBiometricUnlock()}
                disabled={isBiometricLoading}
                className="w-full bg-indigo-500 text-white font-medium py-3.5 rounded-2xl hover:bg-indigo-600 transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {isBiometricLoading ? 'Authenticating...' : 'Use Biometrics'}
              </button>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
