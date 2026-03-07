import { useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { ArrowRight, ChevronLeft, FileKey2, Fingerprint, KeyRound, Lock } from 'lucide-react';
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

export function ImportWalletView() {
  const setView = useAppStore((state) => state.setView);
  const importMethod = useAppStore((state) => state.importMethod);
  const setImportMethod = useAppStore((state) => state.setImportMethod);
  const completeImport = useAppStore((state) => state.completeImport);

  const [step, setStep] = useState(1);
  const [secret, setSecret] = useState('');
  const [passcode, setPasscode] = useState('');
  const [biometricsEnabled, setBiometricsEnabled] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

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

  const finishImport = async () => {
    setErrorMessage('');
    setIsSubmitting(true);
    const result = await completeImport(secret, importMethod, passcode, biometricsEnabled);
    setIsSubmitting(false);
    if (!result.ok) {
      setErrorMessage(result.error ?? 'Unable to import wallet');
    }
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
          {[1, 2, 3, 4].map((index) => (
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
              key="method"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="flex min-h-[620px] flex-col"
            >
              <div className="flex h-16 w-16 items-center justify-center rounded-[1.4rem] bg-blue-50 text-blue-600">
                <FileKey2 className="h-8 w-8" />
              </div>
              <h2 className="mt-8 text-3xl font-extrabold tracking-tight text-slate-950">Import a wallet you already own</h2>
              <p className="mt-4 text-[15px] leading-7 text-slate-600">
                Restore from a recovery phrase or a raw private key. Secrets stay on-device and are encrypted before persistence.
              </p>
              <div className="mt-8 grid gap-3">
                <button
                  onClick={() => {
                    setImportMethod('mnemonic');
                    nextStep();
                  }}
                  className="rounded-[1.5rem] border border-slate-200 bg-slate-50 p-5 text-left transition-colors hover:border-slate-300 hover:bg-white"
                >
                  <div className="font-semibold text-slate-950">Recovery phrase</div>
                  <div className="mt-1 text-sm text-slate-600">12 or 24 words from an existing wallet.</div>
                </button>
                <button
                  onClick={() => {
                    setImportMethod('private-key');
                    nextStep();
                  }}
                  className="rounded-[1.5rem] border border-slate-200 bg-slate-50 p-5 text-left transition-colors hover:border-slate-300 hover:bg-white"
                >
                  <div className="font-semibold text-slate-950">Private key</div>
                  <div className="mt-1 text-sm text-slate-600">Use this only when you know exactly what you are importing.</div>
                </button>
              </div>
            </motion.div>
          )}

          {step === 2 && (
            <motion.div
              key="secret"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="flex min-h-[620px] flex-col"
            >
              <div className="flex h-16 w-16 items-center justify-center rounded-[1.4rem] bg-blue-50 text-blue-600">
                <KeyRound className="h-8 w-8" />
              </div>
              <h2 className="mt-8 text-3xl font-extrabold tracking-tight text-slate-950">
                {importMethod === 'mnemonic' ? 'Paste your recovery phrase' : 'Paste your private key'}
              </h2>
              <p className="mt-4 text-[15px] leading-7 text-slate-600">
                {importMethod === 'mnemonic'
                  ? 'The phrase will be normalized and encrypted locally on this device.'
                  : 'The raw private key is only used to derive the address before the vault is encrypted.'}
              </p>

              <textarea
                value={secret}
                onChange={(event) => setSecret(event.target.value)}
                placeholder={
                  importMethod === 'mnemonic'
                    ? 'abandon ability able about above absent absorb abstract absurd abuse access accident'
                    : '0x0123456789abcdef...'
                }
                className="mt-8 h-44 w-full resize-none rounded-[1.5rem] border border-slate-200 bg-slate-50 p-4 text-[15px] font-medium leading-7 text-slate-950 placeholder:text-slate-400 focus:border-blue-300 focus:outline-none"
              />

              <button
                disabled={secret.trim().length < 10}
                onClick={nextStep}
                className="mt-auto flex items-center justify-center gap-2 rounded-[1.3rem] bg-slate-950 px-5 py-4 font-semibold text-white transition-colors hover:bg-slate-900 disabled:cursor-not-allowed disabled:opacity-50"
              >
                Continue
                <ArrowRight className="h-4 w-4" />
              </button>
            </motion.div>
          )}

          {step === 3 && (
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
              <h2 className="mt-8 text-3xl font-extrabold tracking-tight text-slate-950">Choose a device passcode</h2>
              <p className="mt-4 text-[15px] leading-7 text-slate-600">
                The imported wallet is encrypted locally with this 6-digit passcode.
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

          {step === 4 && (
            <motion.div
              key="finish"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="flex min-h-[620px] flex-col"
            >
              <div className="flex h-16 w-16 items-center justify-center rounded-[1.4rem] bg-emerald-50 text-emerald-600">
                <Fingerprint className="h-8 w-8" />
              </div>
              <h2 className="mt-8 text-3xl font-extrabold tracking-tight text-slate-950">Almost there</h2>
              <p className="mt-4 text-[15px] leading-7 text-slate-600">
                Enable biometrics when the platform supports it, then finish the import.
              </p>
              {errorMessage ? (
                <div className="mt-6 rounded-[1.3rem] border border-rose-200 bg-rose-50 px-4 py-3 text-sm font-medium text-rose-600">
                  {errorMessage}
                </div>
              ) : null}
              <div className="mt-8 grid gap-3">
                <button
                  onClick={() => setBiometricsEnabled((current) => !current)}
                  className={cn(
                    'rounded-[1.5rem] border px-5 py-4 text-left transition-colors',
                    biometricsEnabled
                      ? 'border-blue-200 bg-blue-50 text-blue-700'
                      : 'border-slate-200 bg-slate-50 text-slate-700 hover:border-slate-300 hover:bg-white'
                  )}
                >
                  <div className="font-semibold">Biometric unlock</div>
                  <div className="mt-1 text-sm">
                    {biometricsEnabled
                      ? 'Enabled when the current platform supports secure local unlock helpers.'
                      : 'Leave this off if you want passcode-only unlock for now.'}
                  </div>
                </button>
              </div>
              <button
                disabled={isSubmitting}
                onClick={() => {
                  void finishImport();
                }}
                className="mt-auto flex items-center justify-center gap-2 rounded-[1.3rem] bg-slate-950 px-5 py-4 font-semibold text-white transition-colors hover:bg-slate-900 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {isSubmitting ? 'Importing wallet…' : 'Finish import'}
                <ArrowRight className="h-4 w-4" />
              </button>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}
