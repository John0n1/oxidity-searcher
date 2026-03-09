import { useState } from 'react';
import { Capacitor } from '@capacitor/core';
import { motion } from 'motion/react';
import { ArrowLeft, Copy, CheckCircle2 } from 'lucide-react';
import { useAppStore } from '../store/appStore';
import { QRCodeSVG } from 'qrcode.react';
import { Logo } from '../components/Logo';
import { copyText } from '../lib/clipboard';

export function ReceiveQRView() {
  const setView = useAppStore((state) => state.setView);
  const selectedReceiveToken = useAppStore((state) => state.selectedReceiveToken);
  const isNativePlatform = Capacitor.isNativePlatform();
  const ScreenWrapper: any = isNativePlatform ? 'div' : motion.div;
  const [copied, setCopied] = useState(false);

  if (!selectedReceiveToken) {
    return (
      <div className="flex flex-col h-[600px] bg-zinc-950 items-center justify-center text-white">
        <p>Token not found</p>
        <button onClick={() => setView('receive')} className="mt-4 text-indigo-400">Go back</button>
      </div>
    );
  }

  const receiveAddress = selectedReceiveToken.receiveAddress || selectedReceiveToken.address;

  const handleCopy = () => {
    void copyText(receiveAddress).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <ScreenWrapper
      {...(!isNativePlatform
        ? {
            initial: { opacity: 0, x: 20 },
            animate: { opacity: 1, x: 0 },
            exit: { opacity: 0, x: -20 },
          }
        : {})}
      className="absolute inset-0 overflow-x-hidden bg-zinc-950 flex flex-col"
    >
      <div className="p-6 pb-4 border-b border-white/5 flex items-center justify-between">
        <button 
          onClick={() => setView('receive')}
          className="w-10 h-10 bg-zinc-900 border border-white/5 rounded-full flex items-center justify-center hover:bg-zinc-800 transition-colors"
        >
          <ArrowLeft className="w-5 h-5 text-white" />
        </button>
        <h2 className="text-xl font-semibold text-white">Receive {selectedReceiveToken.symbol}</h2>
        <div className="w-10" />
      </div>

      <div className="flex-1 overflow-y-auto p-6 flex flex-col items-center justify-center">
        <div className="bg-white p-6 rounded-3xl mb-8 relative">
          <QRCodeSVG 
            value={receiveAddress} 
            size={240} 
            level="H"
            includeMargin={false}
          />
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <div className="w-16 h-16 bg-white rounded-full flex items-center justify-center shadow-lg">
              <Logo className="w-10 h-10 text-indigo-600" />
            </div>
          </div>
        </div>

        <p className="text-zinc-400 text-sm mb-2 text-center">
          Send only {selectedReceiveToken.symbol} to this address.
        </p>

        <div className="w-full bg-zinc-900 border border-white/5 rounded-2xl p-4 flex items-center justify-between mb-6">
          <div className="truncate font-mono text-zinc-300 pr-4">
            {receiveAddress}
          </div>
          <button 
            onClick={handleCopy}
            className="w-10 h-10 bg-zinc-800 rounded-xl flex items-center justify-center shrink-0 hover:bg-zinc-700 transition-colors"
          >
            {copied ? <CheckCircle2 className="w-5 h-5 text-emerald-400" /> : <Copy className="w-5 h-5 text-zinc-400" />}
          </button>
        </div>

        <button 
          onClick={handleCopy}
          className="w-full py-4 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-2xl transition-colors"
        >
          {copied ? 'Copied!' : 'Copy Address'}
        </button>
      </div>
    </ScreenWrapper>
  );
}
