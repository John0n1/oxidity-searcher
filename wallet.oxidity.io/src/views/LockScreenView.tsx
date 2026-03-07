import { useEffect, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { ChevronLeft, Fingerprint, LockKeyhole } from 'lucide-react';
import { useAppStore } from '../store/appStore';
import { cn } from '../utils/cn';

export function LockScreenView() {
  const unlockWallet = useAppStore((state) => state.unlockWallet);
  const unlockWithBiometrics = useAppStore((state) => state.unlockWithBiometrics);
  const biometricsEnabled = useAppStore((state) => state.biometricsEnabled);
  const unlockError = useAppStore((state) => state.unlockError);

  const [passcode, setPasscode] = useState('');
  const [showBiometrics, setShowBiometrics] = useState(false);

  useEffect(() => {
    if (!biometricsEnabled) {
      return undefined;
    }
    const timer = window.setTimeout(() => setShowBiometrics(true), 500);
    return () => window.clearTimeout(timer);
  }, [biometricsEnabled]);

  const handlePasscode = (value: string) => {
    if (passcode.length >= 6) {
      return;
    }

    const nextPasscode = `${passcode}${value}`;
    setPasscode(nextPasscode);
    if (nextPasscode.length === 6) {
      window.setTimeout(async () => {
        const ok = await unlockWallet(nextPasscode);
        if (!ok) {
          setPasscode('');
        }
      }, 120);
    }
  };

  const handleBiometricSuccess = async () => {
    setShowBiometrics(false);
    const ok = await unlockWithBiometrics();
    if (!ok) {
      setPasscode('');
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -12 }}
      className="absolute inset-0 overflow-hidden bg-[linear-gradient(180deg,#f9fbff_0%,#eef6ff_56%,#f9fbff_100%)]"
    >
      <div className="absolute -left-10 top-0 h-48 w-48 rounded-full bg-blue-300/25 blur-3xl" />
      <div className="absolute right-0 top-24 h-56 w-56 rounded-full bg-cyan-300/18 blur-3xl" />
      <div className="flex h-full flex-col items-center justify-center px-6">
        <div className="w-full max-w-sm rounded-[2rem] border border-white/80 bg-white/92 p-6 shadow-[0_32px_90px_rgba(15,23,42,0.1)]">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-[1.4rem] bg-blue-50 text-blue-600">
            <LockKeyhole className="h-8 w-8" />
          </div>
          <h2 className="mt-6 text-center text-3xl font-extrabold tracking-tight text-slate-950">Unlock wallet</h2>
          <p className="mt-3 text-center text-[15px] leading-7 text-slate-600">
            Enter the 6-digit device passcode to decrypt the local vault.
          </p>
          {unlockError ? (
            <div className="mt-5 rounded-[1.2rem] border border-rose-200 bg-rose-50 px-4 py-3 text-sm font-medium text-rose-600">
              {unlockError}
            </div>
          ) : null}

          <div className="mt-10 flex justify-center gap-3">
            {[...Array(6)].map((_, index) => (
              <div
                key={index}
                className={cn(
                  'h-4 w-4 rounded-full border-2 transition-colors',
                  index < passcode.length ? 'border-blue-600 bg-blue-600' : 'border-slate-200'
                )}
              />
            ))}
          </div>

          <div className="mt-10 grid grid-cols-3 gap-3">
            {[1, 2, 3, 4, 5, 6, 7, 8, 9].map((value) => (
              <button
                key={value}
                onClick={() => handlePasscode(String(value))}
                className="flex h-14 items-center justify-center rounded-[1.25rem] border border-slate-200 bg-slate-50 text-xl font-semibold text-slate-950 transition-colors hover:border-slate-300 hover:bg-white"
              >
                {value}
              </button>
            ))}

            <button
              onClick={() => setShowBiometrics(true)}
              disabled={!biometricsEnabled}
              className={cn(
                'flex h-14 items-center justify-center rounded-[1.25rem] border transition-colors',
                biometricsEnabled
                  ? 'border-slate-200 bg-slate-50 text-slate-700 hover:border-slate-300 hover:bg-white'
                  : 'pointer-events-none border-transparent bg-transparent opacity-0'
              )}
            >
              <Fingerprint className="h-5 w-5" />
            </button>
            <button
              onClick={() => handlePasscode('0')}
              className="flex h-14 items-center justify-center rounded-[1.25rem] border border-slate-200 bg-slate-50 text-xl font-semibold text-slate-950 transition-colors hover:border-slate-300 hover:bg-white"
            >
              0
            </button>
            <button
              onClick={() => setPasscode((current) => current.slice(0, -1))}
              className="flex h-14 items-center justify-center rounded-[1.25rem] border border-slate-200 bg-slate-50 text-slate-700 transition-colors hover:border-slate-300 hover:bg-white"
            >
              <ChevronLeft className="h-5 w-5" />
            </button>
          </div>
        </div>
      </div>

      <AnimatePresence>
        {showBiometrics ? (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 bg-slate-950/20 backdrop-blur-sm"
              onClick={() => setShowBiometrics(false)}
            />
            <motion.div
              initial={{ opacity: 0, y: 16, scale: 0.97 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 16, scale: 0.97 }}
              className="fixed left-6 right-6 top-1/2 z-20 mx-auto max-w-sm -translate-y-1/2 rounded-[2rem] border border-white/80 bg-white p-6 text-center shadow-[0_32px_90px_rgba(15,23,42,0.14)]"
            >
              <div className="mx-auto flex h-20 w-20 items-center justify-center rounded-full bg-blue-50 text-blue-600">
                <Fingerprint className="h-10 w-10" />
              </div>
              <h3 className="mt-5 text-2xl font-bold tracking-tight text-slate-950">Biometric unlock</h3>
              <p className="mt-3 text-sm leading-7 text-slate-600">
                On web this reuses the current secure session. Native biometric plugins come in through the Android wrapper.
              </p>
              <button
                onClick={() => {
                  void handleBiometricSuccess();
                }}
                className="mt-6 w-full rounded-[1.2rem] bg-slate-950 px-4 py-3.5 font-semibold text-white transition-colors hover:bg-slate-900"
              >
                Continue
              </button>
            </motion.div>
          </>
        ) : null}
      </AnimatePresence>
    </motion.div>
  );
}
