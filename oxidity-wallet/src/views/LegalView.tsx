import { motion } from 'motion/react';
import { ArrowLeft, ShieldCheck, FileText, Scale } from 'lucide-react';
import { useAppStore } from '../store/appStore';

export function LegalView() {
  const setView = useAppStore((state) => state.setView);

  const SECTIONS = [
    {
      title: 'Terms of Service',
      icon: Scale,
      content: `By using Oxidity Wallet, you agree to our terms of service. Oxidity is a non-custodial wallet provider. We do not store your private keys or have access to your funds. You are solely responsible for the security of your recovery phrase.

1. Use of Service: You must be of legal age to use this service.
2. Security: You are responsible for maintaining the confidentiality of your credentials.
3. Fees: Network fees (gas) are paid to the blockchain network, not Oxidity.
4. Liability: Oxidity is not liable for any losses resulting from lost keys or unauthorized access.`
    },
    {
      title: 'Privacy Policy',
      icon: ShieldCheck,
      content: `Your privacy is our priority. Oxidity does not collect personal data, tracking information, or IP addresses linked to your wallet.

- No Data Collection: We do not collect your name, email, or phone number.
- Local Storage: Your private keys are encrypted and stored only on your device.
- Third-Party Services: We may use third-party RPC providers to interact with the blockchain. These providers have their own privacy policies.`
    },
    {
      title: 'Cookie Policy',
      icon: FileText,
      content: `Oxidity does not use cookies for tracking or advertising. We may use local storage to save your app preferences and encrypted wallet data locally on your device.`
    }
  ];

  return (
    <motion.div
      initial={{ x: '100%' }}
      animate={{ x: 0 }}
      exit={{ x: '100%' }}
      transition={{ type: 'spring', damping: 25, stiffness: 200 }}
      className="absolute inset-0 bg-zinc-950 z-50 flex flex-col"
    >
      {/* Header */}
      <div className="p-6 flex items-center gap-4 border-b border-white/5 bg-zinc-950/80 backdrop-blur-xl sticky top-0 z-10">
        <button
          onClick={() => setView('main')}
          className="w-10 h-10 rounded-full bg-zinc-900 flex items-center justify-center hover:bg-zinc-800 transition-colors"
        >
          <ArrowLeft className="w-5 h-5" />
        </button>
        <h2 className="text-xl font-semibold">Legal & Privacy</h2>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-6 space-y-8 pb-12">
        <div className="text-center space-y-2 mb-8">
          <div className="w-16 h-16 bg-indigo-500/10 rounded-2xl flex items-center justify-center mx-auto mb-4">
            <ShieldCheck className="w-8 h-8 text-indigo-400" />
          </div>
          <h3 className="text-lg font-medium">Standard Legal Notice</h3>
          <p className="text-sm text-zinc-500">Last updated: March 2026</p>
        </div>

        {SECTIONS.map((section, i) => (
          <div key={i} className="space-y-4">
            <div className="flex items-center gap-2 text-indigo-400">
              <section.icon className="w-5 h-5" />
              <h4 className="font-semibold uppercase tracking-wider text-xs">{section.title}</h4>
            </div>
            <div className="bg-zinc-900/50 border border-white/5 rounded-2xl p-5">
              <p className="text-sm text-zinc-400 leading-relaxed whitespace-pre-wrap">
                {section.content}
              </p>
            </div>
          </div>
        ))}

        <div className="pt-8 text-center">
          <p className="text-xs text-zinc-600">
            © 2026 Oxidity Wallet. All rights reserved.
          </p>
        </div>
      </div>
    </motion.div>
  );
}
