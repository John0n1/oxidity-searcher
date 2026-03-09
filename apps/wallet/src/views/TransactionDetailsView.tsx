import { Capacitor } from '@capacitor/core';
import { motion } from 'motion/react';
import {
  ArrowLeft,
  ArrowDownLeft,
  ArrowUpRight,
  CheckCircle2,
  ExternalLink,
  RefreshCw,
} from 'lucide-react';

import { useAppStore } from '../store/appStore';
import { cn } from '../utils/cn';
import { openExternalUrl } from '../lib/external';

function statusClasses(status?: string) {
  switch ((status || '').toLowerCase()) {
    case 'pending':
      return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    case 'failed':
      return 'bg-red-500/10 text-red-400 border-red-500/20';
    default:
      return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
  }
}

function compactAddress(address?: string) {
  if (!address) {
    return 'Unavailable';
  }
  return `${address.slice(0, 10)}...${address.slice(-8)}`;
}

export function TransactionDetailsView() {
  const setView = useAppStore((state) => state.setView);
  const selectedTransaction = useAppStore((state) => state.selectedTransaction);
  const isNativePlatform = Capacitor.isNativePlatform();
  const ScreenWrapper: any = isNativePlatform ? 'div' : motion.div;

  if (!selectedTransaction) {
    return (
      <div className="absolute inset-0 flex flex-col items-center justify-center bg-zinc-950 px-6 text-center">
        <p className="text-zinc-400">Transaction not found</p>
        <button onClick={() => setView('main')} className="mt-4 text-indigo-400">
          Go back
        </button>
      </div>
    );
  }

  const { type, title, amount, date, status, hash, from, to, fee, network, explorerUrl, fiatAmount } =
    selectedTransaction;

  const isReceive = type === 'receive';
  const isSend = type === 'send';
  const isSwap = type === 'swap';

  const icon = isReceive
    ? <ArrowDownLeft className="w-8 h-8 text-emerald-400" />
    : isSend
      ? <ArrowUpRight className="w-8 h-8 text-amber-400" />
      : isSwap
        ? <RefreshCw className="w-8 h-8 text-indigo-400" />
        : <CheckCircle2 className="w-8 h-8 text-zinc-400" />;

  return (
    <ScreenWrapper
      {...(!isNativePlatform
        ? {
            initial: { opacity: 0, x: 20 },
            animate: { opacity: 1, x: 0 },
            exit: { opacity: 0, x: -20 },
          }
        : {})}
      className="absolute inset-0 flex flex-col overflow-hidden bg-zinc-950"
    >
      <div className="sticky top-0 z-10 flex items-center justify-between border-b border-white/5 bg-zinc-950/80 p-6 backdrop-blur-xl">
        <button
          onClick={() => setView('main')}
          className="flex h-10 w-10 items-center justify-center rounded-full bg-zinc-900 transition-colors hover:bg-zinc-800"
        >
          <ArrowLeft className="w-5 h-5 text-white" />
        </button>
        <h1 className="text-lg font-semibold text-white">Transaction Details</h1>
        <div className="w-10" />
      </div>

      <div className="flex-1 overflow-y-auto px-6 py-5 pb-24">
        <div className="space-y-4">
          <div className="rounded-3xl border border-white/5 bg-zinc-900 p-6 text-center">
            <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-zinc-950">
              {icon}
            </div>
            <h2 className="mb-1 text-3xl font-bold text-white">{amount}</h2>
            <p className="text-sm text-zinc-400">{fiatAmount || '$0.00'}</p>
            <p className="mt-3 font-medium text-white">{title}</p>
            <div className={cn('mt-4 inline-flex rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-wider', statusClasses(status))}>
              {status || 'Completed'}
            </div>
          </div>

          <div className="rounded-3xl border border-white/5 bg-zinc-900 overflow-hidden">
            {[
              ['Date', date],
              ['Network', network || 'Unknown'],
              ['Network Fee', fee || '$0.00'],
              ['From', compactAddress(from)],
              ['To', compactAddress(to)],
            ].map(([label, value], index, rows) => (
              <div
                key={label}
                className={cn(
                  'flex items-start justify-between gap-4 p-4',
                  index !== rows.length - 1 && 'border-b border-white/5',
                )}
              >
                <span className="text-sm text-zinc-500">{label}</span>
                <span className="max-w-[55%] break-all text-right text-sm font-medium text-white">{value}</span>
              </div>
            ))}
          </div>

          <div className="rounded-3xl border border-white/5 bg-zinc-900 p-4">
            <div className="mb-2 text-sm text-zinc-500">Transaction Hash</div>
            <p className="mb-4 break-all rounded-2xl border border-white/5 bg-zinc-950 px-4 py-3 font-mono text-xs text-zinc-300">
              {hash || 'Unavailable'}
            </p>
            <a
              href={explorerUrl || '#'}
              target="_blank"
              rel="noopener noreferrer"
              onClick={(event) => {
                if (!explorerUrl) {
                  event.preventDefault();
                  return;
                }
                event.preventDefault();
                void openExternalUrl(explorerUrl);
              }}
              className={cn(
                'flex w-full items-center justify-center gap-2 rounded-2xl py-3 text-sm font-medium transition-colors',
                explorerUrl
                  ? 'bg-indigo-500/10 text-indigo-300 hover:bg-indigo-500/20'
                  : 'bg-zinc-950 text-zinc-500',
              )}
            >
              View on Explorer
              <ExternalLink className="w-4 h-4" />
            </a>
          </div>
        </div>
      </div>
    </ScreenWrapper>
  );
}
