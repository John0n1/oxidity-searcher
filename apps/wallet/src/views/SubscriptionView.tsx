import { motion } from 'motion/react';
import { useAppStore } from '../store/appStore';
import { ArrowLeft, Check, Sparkles, Zap, Shield, Globe } from 'lucide-react';

export function SubscriptionView() {
  const setView = useAppStore((state) => state.setView);
  const setSubscribed = useAppStore((state) => state.setSubscribed);

  const handleSubscribe = () => {
    // In a real app, this would trigger Stripe
    setSubscribed(true);
    setView('ai');
  };

  const features = [
    { icon: <Zap className="w-5 h-5 text-amber-400" />, text: "Unlimited AI Market Analysis" },
    { icon: <Sparkles className="w-5 h-5 text-indigo-400" />, text: "Real-time Alpha Detection" },
    { icon: <Shield className="w-5 h-5 text-emerald-400" />, text: "Priority Support & Security" },
    { icon: <Globe className="w-5 h-5 text-blue-400" />, text: "Global Market Coverage" },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: 20 }}
      className="absolute inset-0 bg-zinc-950 flex flex-col z-[70]"
    >
      {/* Header */}
      <div className="p-6 flex items-center gap-4">
        <button
          onClick={() => setView('ai')}
          className="p-2 hover:bg-zinc-900 rounded-full transition-colors"
        >
          <ArrowLeft className="w-6 h-6" />
        </button>
        <h2 className="text-xl font-bold">Oxidity Pro</h2>
      </div>

      <div className="flex-1 overflow-y-auto px-6 pb-10">
        {/* Hero */}
        <div className="text-center mt-4 mb-10">
          <div className="w-20 h-20 bg-indigo-600 rounded-3xl flex items-center justify-center mx-auto mb-6 shadow-[0_0_40px_rgba(79,70,229,0.4)]">
            <Sparkles className="w-10 h-10 text-white" />
          </div>
          <h1 className="text-3xl font-bold tracking-tight mb-2">Unlock Unlimited Alpha</h1>
          <p className="text-zinc-400 text-sm max-w-[280px] mx-auto">
            Get unrestricted access to Oxidity AI and stay ahead of the market.
          </p>
        </div>

        {/* Pricing Card */}
        <div className="bg-zinc-900 border border-indigo-500/30 rounded-[32px] p-8 mb-8 relative overflow-hidden group">
          <div className="absolute top-0 right-0 p-4">
            <div className="bg-indigo-500 text-[10px] font-bold uppercase tracking-widest px-2 py-1 rounded-full">
              Best Value
            </div>
          </div>
          
          <div className="mb-6">
            <span className="text-4xl font-bold">$5</span>
            <span className="text-zinc-500 ml-2">/ month</span>
          </div>

          <div className="space-y-4 mb-8">
            {features.map((feature, i) => (
              <div key={i} className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-zinc-800 flex items-center justify-center">
                  {feature.icon}
                </div>
                <span className="text-sm text-zinc-300">{feature.text}</span>
              </div>
            ))}
          </div>

          <button
            onClick={handleSubscribe}
            className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-4 rounded-2xl transition-all active:scale-95 shadow-lg shadow-indigo-500/20"
          >
            Subscribe Now
          </button>
          
          <p className="text-[10px] text-zinc-500 text-center mt-4">
            Cancel anytime. Secure payment via Stripe.
          </p>
        </div>

        {/* Free Tier Info */}
        <div className="bg-zinc-900/50 border border-white/5 rounded-2xl p-6">
          <h3 className="text-sm font-bold mb-2">Why am I seeing this?</h3>
          <p className="text-xs text-zinc-500 leading-relaxed">
            Free users are limited to 1 AI message every 24 hours. Subscribe to Oxidity Pro for unlimited straight-shooting market analysis.
          </p>
        </div>
      </div>
    </motion.div>
  );
}
