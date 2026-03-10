import { useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { useAppStore } from '../store/appStore';
import { Shield, KeyRound, CheckCircle2, ChevronLeft, ArrowRight, Lock, EyeOff, Fingerprint } from 'lucide-react';
import { cn } from '../utils/cn';
import { HDNodeWallet } from 'ethers';

type VerificationChoice = {
  id: string;
  word: string;
  seedIndex: number;
};

function shuffle<T>(items: T[]): T[] {
  const next = [...items];
  for (let index = next.length - 1; index > 0; index -= 1) {
    const swapIndex = Math.floor(Math.random() * (index + 1));
    [next[index], next[swapIndex]] = [next[swapIndex], next[index]];
  }
  return next;
}

function randomSeedIndexes(total: number, count: number): number[] {
  return shuffle(Array.from({ length: total }, (_, index) => index))
    .slice(0, Math.min(total, count))
    .sort((left, right) => left - right);
}

export function CreateWalletView() {
  const setView = useAppStore((state) => state.setView);
  const setBiometricsEnabled = useAppStore((state) => state.setBiometricsEnabled);
  const importWallet = useAppStore((state) => state.importWallet);
  const [step, setStep] = useState(1);
  const [passcode, setPasscode] = useState('');
  const [selectedVerificationIds, setSelectedVerificationIds] = useState<string[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const seedPhrase = useMemo(() => {
    const wallet = HDNodeWallet.createRandom();
    return wallet.mnemonic?.phrase || '';
  }, []);
  const seedWords = useMemo(() => seedPhrase.split(' ').filter(Boolean), [seedPhrase]);
  const verificationIndexes = useMemo(() => randomSeedIndexes(seedWords.length, 3), [seedWords]);
  const expectedVerificationIds = useMemo(
    () => verificationIndexes.map((index) => `seed-${index}`),
    [verificationIndexes],
  );
  const verificationPool = useMemo<VerificationChoice[]>(() => {
    const targetChoices = verificationIndexes.map((seedIndex) => ({
      id: `seed-${seedIndex}`,
      word: seedWords[seedIndex] || '',
      seedIndex,
    }));
    const distractorChoices = shuffle(
      seedWords
        .map((word, seedIndex) => ({ id: `seed-${seedIndex}`, word, seedIndex }))
        .filter((choice) => !expectedVerificationIds.includes(choice.id)),
    ).slice(0, Math.min(6, Math.max(seedWords.length - targetChoices.length, 0)));

    return shuffle([...targetChoices, ...distractorChoices]);
  }, [expectedVerificationIds, seedWords, verificationIndexes]);

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

  const handleWordSelect = (choice: VerificationChoice) => {
    setErrorMessage(null);
    if (selectedVerificationIds.includes(choice.id)) {
      setSelectedVerificationIds(
        selectedVerificationIds.filter((existingChoiceId) => existingChoiceId !== choice.id),
      );
      return;
    }
    if (selectedVerificationIds.length >= expectedVerificationIds.length) {
      return;
    }

    const nextSelection = [...selectedVerificationIds, choice.id];
    setSelectedVerificationIds(nextSelection);
    if (nextSelection.length === expectedVerificationIds.length) {
      if (nextSelection.join(' ') === expectedVerificationIds.join(' ')) {
        setTimeout(nextStep, 400);
      } else {
        window.setTimeout(() => {
          setSelectedVerificationIds([]);
          setErrorMessage('The selected words do not match the requested recovery phrase words.');
        }, 350);
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

  const finishCreation = async () => {
    if (!seedPhrase) {
      setErrorMessage('Failed to generate a recovery phrase');
      return;
    }

    setIsSubmitting(true);
    setErrorMessage(null);
    try {
      await importWallet({
        secret: seedPhrase,
        importType: 'mnemonic',
        passcode,
      });
      setView('walkthrough');
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Failed to create wallet');
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
        {step < 6 ? (
          <button onClick={prevStep} className="p-2 -ml-2 text-zinc-400 hover:text-white transition-colors">
            <ChevronLeft className="w-6 h-6" />
          </button>
        ) : <div className="w-10" />}
        <div className="flex gap-1.5">
          {[1, 2, 3, 4, 5].map((i) => (
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
                <Shield className="w-8 h-8 text-indigo-400" />
              </div>
              <h2 className="text-3xl font-semibold tracking-tight mb-3">Self-Custody</h2>
              <p className="text-zinc-400 leading-relaxed mb-8">
                You are the only one who controls your funds. Oxidity cannot access or recover your wallet.
              </p>
              
              <div className="mt-auto">
                <button
                  onClick={nextStep}
                  className="w-full bg-white text-black font-medium py-4 rounded-2xl hover:bg-zinc-200 transition-colors flex items-center justify-center gap-2"
                >
                  I Understand
                  <ArrowRight className="w-4 h-4" />
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

          {step === 3 && (
            <motion.div
              key="step3"
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

          {step === 4 && (
            <motion.div
              key="step4"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="flex-1 flex flex-col"
            >
              <div className="mt-8 mb-6 w-16 h-16 bg-zinc-900 rounded-2xl flex items-center justify-center border border-white/5">
                <EyeOff className="w-8 h-8 text-indigo-400" />
              </div>
              <h2 className="text-3xl font-semibold tracking-tight mb-3">Recovery Phrase</h2>
              <p className="text-zinc-400 leading-relaxed mb-8">
                Write down these 12 words in order. Never share them with anyone.
              </p>
              
              <div className="grid grid-cols-2 gap-3 mb-8">
                {seedWords.map((word, i) => (
                  <div key={i} className="bg-zinc-900 border border-white/5 rounded-xl p-3 flex items-center gap-3">
                    <span className="text-zinc-500 text-sm w-4">{i + 1}</span>
                    <span className="font-medium text-white">{word}</span>
                  </div>
                ))}
              </div>

              <div className="mt-auto">
                <button
                  onClick={nextStep}
                  className="w-full bg-white text-black font-medium py-4 rounded-2xl hover:bg-zinc-200 transition-colors flex items-center justify-center gap-2"
                >
                  I've Saved It
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </motion.div>
          )}

          {step === 5 && (
            <motion.div
              key="step5"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="flex-1 flex flex-col"
            >
              <div className="mt-8 mb-6 w-16 h-16 bg-zinc-900 rounded-2xl flex items-center justify-center border border-white/5">
                <KeyRound className="w-8 h-8 text-indigo-400" />
              </div>
              <h2 className="text-3xl font-semibold tracking-tight mb-3">Verify Phrase</h2>
              <p className="text-zinc-400 leading-relaxed mb-8">
                Select words{' '}
                {verificationIndexes.map((index) => `#${index + 1}`).join(', ')} in that order.
                This screen continues automatically when they are correct.
              </p>
              
              <div className="flex flex-wrap gap-2 mb-8">
                {verificationPool.map((choice) => (
                  <button
                    key={choice.id}
                    onClick={() => handleWordSelect(choice)}
                    className={cn(
                      "px-4 py-3 rounded-xl border transition-colors font-medium",
                      selectedVerificationIds.includes(choice.id)
                        ? "bg-indigo-500/20 border-indigo-500 text-indigo-300"
                        : "bg-zinc-900 border-white/5 text-zinc-300 hover:bg-zinc-800"
                    )}
                  >
                    {choice.word}
                  </button>
                ))}
              </div>

              <div className="mt-auto rounded-2xl border border-white/5 bg-zinc-900/70 p-4">
                <div className="text-xs uppercase tracking-[0.18em] text-zinc-500">Selected</div>
                <div className="mt-3 flex min-h-11 flex-wrap gap-2">
                  {selectedVerificationIds.length > 0 ? (
                    selectedVerificationIds.map((choiceId) => {
                      const choice = verificationPool.find((entry) => entry.id === choiceId);
                      return choice ? (
                        <div
                          key={choiceId}
                          className="rounded-full border border-indigo-500/30 bg-indigo-500/10 px-3 py-2 text-sm font-medium text-indigo-200"
                        >
                          #{choice.seedIndex + 1} {choice.word}
                        </div>
                      ) : null;
                    })
                  ) : (
                    <div className="text-sm text-zinc-500">Tap the requested words to verify your backup.</div>
                  )}
                </div>
              </div>
            </motion.div>
          )}

          {step === 6 && (
            <motion.div
              key="step6"
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
              <h2 className="text-3xl font-semibold tracking-tight mb-3">Wallet Created</h2>
              <p className="text-zinc-400 leading-relaxed mb-12 max-w-[260px]">
                Your wallet is ready. Experience private execution and MEV protection.
              </p>
              
              <div className="w-full mt-auto">
                <button
                  onClick={() => void finishCreation()}
                  disabled={isSubmitting}
                  className="w-full bg-white text-black font-medium py-4 rounded-2xl hover:bg-zinc-200 transition-colors flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isSubmitting ? 'Creating Wallet...' : 'Enter Wallet'}
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
