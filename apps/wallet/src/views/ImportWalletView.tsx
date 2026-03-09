import { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { useAppStore } from '../store/appStore';
import { KeyRound, CheckCircle2, ChevronLeft, ArrowRight, Lock, FileKey2, Fingerprint } from 'lucide-react';
import { cn } from '../utils/cn';
import { Mnemonic } from 'ethers';

export function ImportWalletView() {
  const setView = useAppStore((state) => state.setView);
  const setBiometricsEnabled = useAppStore((state) => state.setBiometricsEnabled);
  const importWallet = useAppStore((state) => state.importWallet);
  const [step, setStep] = useState(1);
  const [phrase, setPhrase] = useState('');
  const [passcode, setPasscode] = useState('');
  const [importType, setImportType] = useState<'mnemonic' | 'privateKey'>('mnemonic');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const nextStep = () => setStep((s) => s + 1);
  const prevStep = () => {
    if (step === 1) setView('welcome');
    else setStep((s) => s - 1);
  };

  const handlePasscode = (n: string) => {
    if (passcode.length < 6) {
      const newPass = passcode + n;
      setPasscode(newPass);
      if (newPass.length === 6) {
        setTimeout(nextStep, 300);
      }
    }
  };

  const enableBiometrics = () => {
    setBiometricsEnabled(true);
    nextStep();
  };

  const skipBiometrics = () => {
    setBiometricsEnabled(false);
    nextStep();
  };

  const canContinue =
    importType === 'mnemonic'
      ? Mnemonic.isValidMnemonic(phrase.trim())
      : /^0x?[0-9a-fA-F]{64}$/.test(phrase.trim());

  const finishImport = async () => {
    setIsSubmitting(true);
    setErrorMessage(null);
    try {
      await importWallet({
        secret: phrase.trim(),
        importType,
        passcode,
      });
      setView('walkthrough');
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Failed to import wallet');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -20 }}
      transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
      className="absolute inset-0 flex flex-col"
    >
      {/* Header */}
      <div className="flex items-center justify-between p-6 pb-2">
        {step < 5 ? (
          <button onClick={prevStep} className="p-2 -ml-2 text-zinc-400 hover:text-white transition-colors">
            <ChevronLeft className="w-6 h-6" />
          </button>
        ) : <div className="w-10" />}
        <div className="flex gap-1.5">
          {[1, 2, 3, 4].map((i) => (
            <div
              key={i}
              className={cn(
                "h-1.5 rounded-full transition-all duration-300",
                i === step ? "w-6 bg-indigo-500" : i < step ? "w-1.5 bg-indigo-500/50" : "w-1.5 bg-zinc-800"
              )}
            />
          ))}
        </div>
        <div className="w-10" />
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto px-6 pb-6 flex flex-col">
        <AnimatePresence mode="wait">
          {step === 1 && (
            <motion.div
              key="step1"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="flex-1 flex flex-col"
            >
              <div className="mt-8 mb-6 w-16 h-16 bg-zinc-900 rounded-2xl flex items-center justify-center border border-white/5">
                <FileKey2 className="w-8 h-8 text-indigo-400" />
              </div>
              <h2 className="text-3xl font-semibold tracking-tight mb-3">Import Wallet</h2>
              <p className="text-zinc-400 leading-relaxed mb-8">
                Restore your existing wallet using a recovery phrase or private key.
              </p>
              
              <div className="space-y-3">
                <button
                  onClick={() => {
                    setImportType('mnemonic');
                    nextStep();
                  }}
                  className="w-full bg-zinc-900 border border-white/5 text-left p-5 rounded-2xl hover:bg-zinc-800 transition-colors flex items-center justify-between"
                >
                  <div>
                    <div className="font-medium text-white mb-1">Recovery Phrase</div>
                    <div className="text-sm text-zinc-500">12 or 24 words</div>
                  </div>
                  <ChevronLeft className="w-5 h-5 text-zinc-600 rotate-180" />
                </button>
                <button
                  onClick={() => {
                    setImportType('privateKey');
                    nextStep();
                  }}
                  className="w-full bg-zinc-900 border border-white/5 text-left p-5 rounded-2xl hover:bg-zinc-800 transition-colors flex items-center justify-between"
                >
                  <div>
                    <div className="font-medium text-white mb-1">Private Key</div>
                    <div className="text-sm text-zinc-500">64-character hex string</div>
                  </div>
                  <ChevronLeft className="w-5 h-5 text-zinc-600 rotate-180" />
                </button>
              </div>
            </motion.div>
          )}

          {step === 2 && (
            <motion.div
              key="step2"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="flex-1 flex flex-col"
            >
              <div className="mt-8 mb-6 w-16 h-16 bg-zinc-900 rounded-2xl flex items-center justify-center border border-white/5">
                <KeyRound className="w-8 h-8 text-indigo-400" />
              </div>
              <h2 className="text-3xl font-semibold tracking-tight mb-3">
                {importType === 'mnemonic' ? 'Enter Phrase' : 'Enter Private Key'}
              </h2>
              <p className="text-zinc-400 leading-relaxed mb-8">
                {importType === 'mnemonic'
                  ? 'Type or paste your recovery phrase below.'
                  : 'Paste your private key below.'}
              </p>
              
              <textarea
                value={phrase}
                onChange={(e) => setPhrase(e.target.value)}
                placeholder={
                  importType === 'mnemonic'
                    ? 'abandon ability able about above absent absorb abstract absurd abuse access accident'
                    : '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
                }
                className="w-full h-40 bg-zinc-900 border border-white/10 rounded-2xl p-4 text-white placeholder:text-zinc-600 focus:outline-none focus:border-indigo-500/50 resize-none font-medium leading-relaxed"
              />

              <div className="mt-auto">
                <button
                  disabled={!canContinue}
                  onClick={nextStep}
                  className="w-full bg-white text-black font-medium py-4 rounded-2xl hover:bg-zinc-200 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                >
                  Continue
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </motion.div>
          )}

          {step === 3 && (
            <motion.div
              key="step3"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="flex-1 flex flex-col"
            >
              <div className="mt-8 mb-6 w-16 h-16 bg-zinc-900 rounded-2xl flex items-center justify-center border border-white/5">
                <Lock className="w-8 h-8 text-indigo-400" />
              </div>
              <h2 className="text-3xl font-semibold tracking-tight mb-3">Set Passcode</h2>
              <p className="text-zinc-400 leading-relaxed mb-12">
                Secure your wallet with a 6-digit passcode.
              </p>
              
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

              <div className="mt-auto grid grid-cols-3 gap-4 mb-8">
                {[1, 2, 3, 4, 5, 6, 7, 8, 9, '', 0, 'del'].map((n, i) => (
                  <button
                    key={i}
                    onClick={() => {
                      if (n === 'del') setPasscode(p => p.slice(0, -1));
                      else if (n !== '') handlePasscode(n.toString());
                    }}
                    disabled={n === ''}
                    className={cn(
                      "h-16 rounded-2xl text-2xl font-medium flex items-center justify-center transition-colors",
                      n !== '' ? "bg-zinc-900 hover:bg-zinc-800 active:bg-zinc-700" : ""
                    )}
                  >
                    {n === 'del' ? <ChevronLeft className="w-6 h-6" /> : n}
                  </button>
                ))}
              </div>
            </motion.div>
          )}

          {step === 4 && (
            <motion.div
              key="step4"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="flex-1 flex flex-col"
            >
              <div className="mt-8 mb-6 w-16 h-16 bg-zinc-900 rounded-2xl flex items-center justify-center border border-white/5">
                <Fingerprint className="w-8 h-8 text-indigo-400" />
              </div>
              <h2 className="text-3xl font-semibold tracking-tight mb-3">Enable Biometrics</h2>
              <p className="text-zinc-400 leading-relaxed mb-8">
                Use Face ID or Touch ID for faster access and transaction approvals.
              </p>
              
              <div className="mt-auto space-y-3">
                <button
                  onClick={enableBiometrics}
                  className="w-full bg-white text-black font-medium py-4 rounded-2xl hover:bg-zinc-200 transition-colors flex items-center justify-center gap-2"
                >
                  Enable Biometrics
                </button>
                <button
                  onClick={skipBiometrics}
                  className="w-full bg-zinc-900 text-white font-medium py-4 rounded-2xl border border-white/5 hover:bg-zinc-800 transition-colors"
                >
                  Skip for now
                </button>
              </div>
            </motion.div>
          )}

          {step === 5 && (
            <motion.div
              key="step5"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="flex-1 flex flex-col items-center justify-center text-center"
            >
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ type: "spring", bounce: 0.5, delay: 0.2 }}
                className="w-24 h-24 bg-emerald-500/20 rounded-full flex items-center justify-center mb-6"
              >
                <CheckCircle2 className="w-12 h-12 text-emerald-400" />
              </motion.div>
              <h2 className="text-3xl font-semibold tracking-tight mb-3">Wallet Imported</h2>
              <p className="text-zinc-400 leading-relaxed mb-12 max-w-[260px]">
                Your wallet is ready. Experience private execution and MEV protection.
              </p>
              
              <div className="w-full mt-auto">
                <button
                  onClick={() => void finishImport()}
                  disabled={isSubmitting}
                  className="w-full bg-white text-black font-medium py-4 rounded-2xl hover:bg-zinc-200 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                >
                  {isSubmitting ? 'Importing Wallet...' : 'Go to Wallet'}
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
        {errorMessage && (
          <p className="mt-4 text-sm text-red-400 text-center">{errorMessage}</p>
        )}
      </div>
    </motion.div>
  );
}
