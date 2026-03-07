import { useEffect, useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { ArrowRight, CheckCircle2, ChevronLeft, EyeOff, Fingerprint, Lock, Shield } from 'lucide-react';
import { useAppStore } from '../store/appStore';
import { cn } from '../utils/cn';

function NumericPad({
  onDigit,
  onDelete,
}: {
  onDigit: (value: string) => void;
  onDelete: () => void;
}) {
  return (
    <div className="mt-auto grid grid-cols-3 gap-3">
      {[1, 2, 3, 4, 5, 6, 7, 8, 9, '', 0, 'del'].map((value, index) => (
        <button
          key={`${value}-${index}`}
          onClick={() => {
            if (value === 'del') {
              onDelete();
            } else if (value !== '') {
              onDigit(String(value));
            }
          }}
          disabled={value === ''}
          className={cn(
            'flex h-14 items-center justify-center rounded-[1.25rem] text-xl font-semibold transition-colors',
            value === ''
              ? 'pointer-events-none opacity-0'
              : 'border border-slate-200 bg-white text-slate-950 hover:border-slate-300 hover:bg-slate-50'
          )}
        >
          {value === 'del' ? <ChevronLeft className="h-5 w-5" /> : value}
        </button>
      ))}
    </div>
  );
}

export function CreateWalletView() {
  const setView = useAppStore((state) => state.setView);
  const draftWallet = useAppStore((state) => state.draftWallet);
  const startCreateFlow = useAppStore((state) => state.startCreateFlow);
  const completeDraftCreation = useAppStore((state) => state.completeDraftCreation);

  const [step, setStep] = useState(1);
  const [passcode, setPasscode] = useState('');
  const [biometricsEnabled, setBiometricsEnabled] = useState(false);
  const [confirmingWords, setConfirmingWords] = useState<string[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const seedPhrase = draftWallet?.words ?? [];
  const verificationIndexes = useMemo(() => [1, 4, 9].filter((index) => seedPhrase[index]), [seedPhrase]);
  const verificationWords = useMemo(
    () => verificationIndexes.map((index) => seedPhrase[index]),
    [seedPhrase, verificationIndexes]
  );
  const selectableWords = useMemo(() => {
    const extras = seedPhrase.filter((word) => !verificationWords.includes(word)).slice(0, 3);
    return [...verificationWords, ...extras].sort((left, right) => left.localeCompare(right));
  }, [seedPhrase, verificationWords]);

  useEffect(() => {
    if (!draftWallet) {
      startCreateFlow();
    }
  }, [draftWallet, startCreateFlow]);

  const nextStep = () => setStep((current) => current + 1);

  const prevStep = () => {
    if (step === 1) {
      setView('welcome');
    } else {
      setStep((current) => current - 1);
    }
  };

  const handlePasscode = (value: string) => {
    if (passcode.length >= 6) {
      return;
    }

    const nextPasscode = `${passcode}${value}`;
    setPasscode(nextPasscode);
    if (nextPasscode.length === 6) {
      window.setTimeout(nextStep, 140);
    }
  };

  const toggleWord = (word: string) => {
    if (confirmingWords.includes(word)) {
      setConfirmingWords(confirmingWords.filter((current) => current !== word));
      return;
    }

    if (confirmingWords.length >= verificationWords.length) {
      return;
    }

    setConfirmingWords([...confirmingWords, word]);
  };

  const canFinish = passcode.length === 6 && confirmingWords.join(' ') === verificationWords.join(' ');

  const finishCreation = async () => {
    if (!canFinish) {
      return;
    }
    setIsSubmitting(true);
    await completeDraftCreation(passcode, biometricsEnabled);
    setIsSubmitting(false);
  };

  return (
    <motion.div
      initial={{ opacity: 0, x: 18 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -18 }}
      transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
      className="absolute inset-0 overflow-y-auto bg-transparent px-6 pb-8 pt-8"
    >
      <div className="flex items-center justify-between pb-4">
        <button
          onClick={prevStep}
          className="flex h-10 w-10 items-center justify-center rounded-full border border-white/80 bg-white/80 text-slate-600 shadow-sm transition-colors hover:text-slate-950"
        >
          <ChevronLeft className="h-5 w-5" />
        </button>
        <div className="flex gap-1.5">
          {[1, 2, 3, 4, 5].map((index) => (
            <div
              key={index}
              className={cn(
                'h-1.5 rounded-full transition-all duration-300',
                index === step ? 'w-7 bg-blue-600' : index < step ? 'w-2 bg-blue-300' : 'w-2 bg-slate-200'
              )}
            />
          ))}
        </div>
        <div className="w-10" />
      </div>

      <div className="rounded-[2rem] border border-white/80 bg-white/90 p-6 shadow-[0_30px_80px_rgba(15,23,42,0.08)]">
        <AnimatePresence mode="wait">
          {step === 1 && (
            <motion.div
              key="intro"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="flex min-h-[620px] flex-col"
            >
              <div className="flex h-16 w-16 items-center justify-center rounded-[1.4rem] bg-blue-50 text-blue-600">
                <Shield className="h-8 w-8" />
              </div>
              <h2 className="mt-8 text-3xl font-extrabold tracking-tight text-slate-950">You keep the keys</h2>
              <p className="mt-4 text-[15px] leading-7 text-slate-600">
                Oxidity Wallet encrypts your wallet locally on this device. We do not hold your recovery phrase, private key, or unlock secret.
              </p>
              <div className="mt-8 rounded-[1.5rem] border border-slate-200 bg-slate-50 p-4 text-sm leading-7 text-slate-600">
                Write down your recovery phrase somewhere safe before you fund the wallet. If you lose both the device and the phrase, the wallet cannot be recovered.
              </div>
              <button
                onClick={nextStep}
                className="mt-auto flex items-center justify-center gap-2 rounded-[1.3rem] bg-slate-950 px-5 py-4 font-semibold text-white transition-colors hover:bg-slate-900"
              >
                I understand
                <ArrowRight className="h-4 w-4" />
              </button>
            </motion.div>
          )}

          {step === 2 && (
            <motion.div
              key="passcode"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="flex min-h-[620px] flex-col"
            >
              <div className="flex h-16 w-16 items-center justify-center rounded-[1.4rem] bg-blue-50 text-blue-600">
                <Lock className="h-8 w-8" />
              </div>
              <h2 className="mt-8 text-3xl font-extrabold tracking-tight text-slate-950">Set a device passcode</h2>
              <p className="mt-4 text-[15px] leading-7 text-slate-600">
                Use a 6-digit code to encrypt the wallet locally. This secures the vault in the browser, extension, or Android wrapper.
              </p>
              <div className="mt-14 flex justify-center gap-3">
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
              <NumericPad
                onDigit={handlePasscode}
                onDelete={() => setPasscode((current) => current.slice(0, -1))}
              />
            </motion.div>
          )}

          {step === 3 && (
            <motion.div
              key="biometrics"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="flex min-h-[620px] flex-col"
            >
              <div className="flex h-16 w-16 items-center justify-center rounded-[1.4rem] bg-emerald-50 text-emerald-600">
                <Fingerprint className="h-8 w-8" />
              </div>
              <h2 className="mt-8 text-3xl font-extrabold tracking-tight text-slate-950">Use biometrics when available</h2>
              <p className="mt-4 text-[15px] leading-7 text-slate-600">
                Browser support is limited, but the same setting carries into the extension and Android wrapper when secure local biometric unlock is available.
              </p>
              <div className="mt-auto grid gap-3">
                <button
                  onClick={() => {
                    setBiometricsEnabled(true);
                    nextStep();
                  }}
                  className="rounded-[1.3rem] bg-slate-950 px-5 py-4 font-semibold text-white transition-colors hover:bg-slate-900"
                >
                  Enable when supported
                </button>
                <button
                  onClick={() => {
                    setBiometricsEnabled(false);
                    nextStep();
                  }}
                  className="rounded-[1.3rem] border border-slate-200 bg-slate-50 px-5 py-4 font-semibold text-slate-700 transition-colors hover:border-slate-300 hover:bg-white"
                >
                  Skip for now
                </button>
              </div>
            </motion.div>
          )}

          {step === 4 && (
            <motion.div
              key="phrase"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="flex min-h-[620px] flex-col"
            >
              <div className="flex h-16 w-16 items-center justify-center rounded-[1.4rem] bg-amber-50 text-amber-600">
                <EyeOff className="h-8 w-8" />
              </div>
              <h2 className="mt-8 text-3xl font-extrabold tracking-tight text-slate-950">Save your recovery phrase</h2>
              <p className="mt-4 text-[15px] leading-7 text-slate-600">
                Store these words offline. Anyone with the phrase can control this wallet.
              </p>
              <div className="mt-8 grid grid-cols-2 gap-3 rounded-[1.7rem] border border-slate-200 bg-slate-50 p-4">
                {seedPhrase.map((word, index) => (
                  <div
                    key={`${word}-${index}`}
                    className="rounded-[1.1rem] border border-white bg-white px-3 py-3 text-sm font-semibold text-slate-700 shadow-sm"
                  >
                    <span className="mr-2 font-mono text-xs text-slate-400">{index + 1}.</span>
                    {word}
                  </div>
                ))}
              </div>
              <button
                onClick={nextStep}
                className="mt-auto flex items-center justify-center gap-2 rounded-[1.3rem] bg-slate-950 px-5 py-4 font-semibold text-white transition-colors hover:bg-slate-900"
              >
                I saved it
                <ArrowRight className="h-4 w-4" />
              </button>
            </motion.div>
          )}

          {step === 5 && (
            <motion.div
              key="verify"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="flex min-h-[620px] flex-col"
            >
              <div className="flex h-16 w-16 items-center justify-center rounded-[1.4rem] bg-emerald-50 text-emerald-600">
                <CheckCircle2 className="h-8 w-8" />
              </div>
              <h2 className="mt-8 text-3xl font-extrabold tracking-tight text-slate-950">Confirm a few words</h2>
              <p className="mt-4 text-[15px] leading-7 text-slate-600">
                Tap word {verificationIndexes[0] + 1}, {verificationIndexes[1] + 1}, and {verificationIndexes[2] + 1} in that order.
              </p>

              <div className="mt-8 rounded-[1.5rem] border border-slate-200 bg-slate-50 p-4">
                <div className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Selected</div>
                <div className="mt-3 flex min-h-14 flex-wrap gap-2">
                  {confirmingWords.length === 0 ? (
                    <div className="rounded-full border border-dashed border-slate-300 px-3 py-2 text-sm text-slate-400">
                      Choose the requested words
                    </div>
                  ) : (
                    confirmingWords.map((word) => (
                      <div key={word} className="rounded-full bg-blue-600 px-3 py-2 text-sm font-semibold text-white">
                        {word}
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div className="mt-5 flex flex-wrap gap-2">
                {selectableWords.map((word) => (
                  <button
                    key={word}
                    onClick={() => toggleWord(word)}
                    className={cn(
                      'rounded-full border px-3 py-2 text-sm font-semibold transition-colors',
                      confirmingWords.includes(word)
                        ? 'border-blue-600 bg-blue-600 text-white'
                        : 'border-slate-200 bg-white text-slate-700 hover:border-slate-300 hover:bg-slate-50'
                    )}
                  >
                    {word}
                  </button>
                ))}
              </div>

              <button
                disabled={!canFinish || isSubmitting}
                onClick={() => {
                  void finishCreation();
                }}
                className="mt-auto flex items-center justify-center gap-2 rounded-[1.3rem] bg-slate-950 px-5 py-4 font-semibold text-white transition-colors hover:bg-slate-900 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {isSubmitting ? 'Creating wallet…' : 'Open wallet'}
                <ArrowRight className="h-4 w-4" />
              </button>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}
