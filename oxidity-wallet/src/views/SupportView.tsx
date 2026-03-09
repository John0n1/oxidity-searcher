import { motion } from 'motion/react';
import { ArrowLeft, HelpCircle, Mail, MessageSquare, ExternalLink, ChevronDown } from 'lucide-react';
import { useAppStore } from '../store/appStore';
import { useState } from 'react';
import { cn } from '../utils/cn';

export function SupportView() {
  const setView = useAppStore((state) => state.setView);
  const [openFaq, setOpenFaq] = useState<number | null>(null);

  const FAQS = [
    {
      question: "What is Oxidity Wallet?",
      answer: "Oxidity is a non-custodial, multi-chain crypto wallet that gives you full control over your digital assets. We prioritize security, privacy, and ease of use."
    },
    {
      question: "How do I back up my wallet?",
      answer: "Go to Settings > Security > Recovery Phrase. Write down your 12 or 24-word recovery phrase and store it in a safe, offline location. Never share it with anyone."
    },
    {
      question: "What if I lose my recovery phrase?",
      answer: "Since Oxidity is a non-custodial wallet, we do not have access to your keys. If you lose your recovery phrase, your funds cannot be recovered. Always keep a backup."
    },
    {
      question: "Are there any fees?",
      answer: "Oxidity does not charge fees for basic wallet functions. You only pay network fees (gas) to the blockchain miners/validators when sending transactions."
    },
    {
      question: "How do I contact support?",
      answer: "You can reach us directly via email at support@oxidity.io. Our team typically responds within 24-48 hours."
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
        <h2 className="text-xl font-semibold">Help & Support</h2>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-6 space-y-8 pb-12">
        {/* Contact Options */}
        <div className="grid grid-cols-2 gap-4">
          <a
            href="mailto:support@oxidity.io"
            className="bg-zinc-900 border border-white/5 rounded-3xl p-5 flex flex-col items-center gap-3 hover:bg-zinc-800 transition-colors group"
          >
            <div className="w-12 h-12 bg-indigo-500/10 rounded-2xl flex items-center justify-center group-hover:bg-indigo-500/20 transition-colors">
              <Mail className="w-6 h-6 text-indigo-400" />
            </div>
            <div className="text-center">
              <span className="block font-semibold text-sm">Email Us</span>
              <span className="text-[10px] text-zinc-500">support@oxidity.io</span>
            </div>
          </a>
          <button
            className="bg-zinc-900 border border-white/5 rounded-3xl p-5 flex flex-col items-center gap-3 hover:bg-zinc-800 transition-colors group"
          >
            <div className="w-12 h-12 bg-emerald-500/10 rounded-2xl flex items-center justify-center group-hover:bg-emerald-500/20 transition-colors">
              <MessageSquare className="w-6 h-6 text-emerald-400" />
            </div>
            <div className="text-center">
              <span className="block font-semibold text-sm">Live Chat</span>
              <span className="text-[10px] text-zinc-500">Coming Soon</span>
            </div>
          </button>
        </div>

        {/* FAQs */}
        <div className="space-y-4">
          <div className="flex items-center gap-2 text-zinc-400 px-2">
            <HelpCircle className="w-4 h-4" />
            <h3 className="text-sm font-medium uppercase tracking-wider">Frequently Asked Questions</h3>
          </div>
          
          <div className="bg-zinc-900 border border-white/5 rounded-3xl overflow-hidden">
            {FAQS.map((faq, i) => (
              <div key={i} className={cn(i !== FAQS.length - 1 && "border-b border-white/5")}>
                <button
                  onClick={() => setOpenFaq(openFaq === i ? null : i)}
                  className="w-full flex items-center justify-between p-5 text-left hover:bg-zinc-800 transition-colors"
                >
                  <span className="font-medium text-sm pr-4">{faq.question}</span>
                  <ChevronDown className={cn("w-4 h-4 text-zinc-500 transition-transform duration-300", openFaq === i && "rotate-180")} />
                </button>
                <motion.div
                  initial={false}
                  animate={{ height: openFaq === i ? 'auto' : 0, opacity: openFaq === i ? 1 : 0 }}
                  className="overflow-hidden bg-zinc-950/50"
                >
                  <div className="p-5 text-sm text-zinc-400 leading-relaxed border-t border-white/5">
                    {faq.answer}
                  </div>
                </motion.div>
              </div>
            ))}
          </div>
        </div>

        {/* Community Links */}
        <div className="space-y-4">
          <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-wider px-2">Community</h3>
          <div className="space-y-3">
            {['Twitter', 'Discord', 'Telegram', 'Blog'].map((platform) => (
              <button
                key={platform}
                className="w-full flex items-center justify-between p-4 bg-zinc-900 border border-white/5 rounded-2xl hover:bg-zinc-800 transition-colors"
              >
                <span className="text-sm font-medium">{platform}</span>
                <ExternalLink className="w-4 h-4 text-zinc-600" />
              </button>
            ))}
          </div>
        </div>
      </div>
    </motion.div>
  );
}
