import { useEffect, useMemo, useState } from 'react';
import { Capacitor } from '@capacitor/core';
import { motion } from 'motion/react';
import { ArrowLeft, ArrowDownToLine, CreditCard, TrendingUp } from 'lucide-react';

import { TokenLogo } from '../components/TokenLogo';
import { getTokenDetails, type ApiTokenChartSeries, type ApiTokenDetailsResponse } from '../lib/api';
import { useAppStore } from '../store/appStore';
import { preloadTokenLogos } from '../lib/tokenLogos';

type ChartKey = '24h' | 'week' | 'month';

function formatUsd(value: number, compact = false): string {
  if (!Number.isFinite(value)) {
    return '$0.00';
  }

  if (compact && value >= 1000) {
    return `$${value.toLocaleString('en-US', {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    })}`;
  }

  if (value >= 1) {
    return `$${value.toLocaleString('en-US', {
      minimumFractionDigits: 2,
      maximumFractionDigits: 4,
    })}`;
  }

  return `$${value.toLocaleString('en-US', {
    minimumFractionDigits: 4,
    maximumFractionDigits: 8,
  })}`;
}

function compactAddress(value?: string): string {
  if (!value) {
    return 'Unavailable';
  }
  return `${value.slice(0, 8)}...${value.slice(-6)}`;
}

function chartPath(
  points: ApiTokenChartSeries['points'],
  width: number,
  height: number,
  valueKey: 'priceUsd' | 'valueUsd',
) {
  if (points.length === 0) {
    return '';
  }

  const values = points.map((point) => point[valueKey]);
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || Math.max(max, 1);

  return points
    .map((point, index) => {
      const x = (index / Math.max(points.length - 1, 1)) * width;
      const y = height - ((point[valueKey] - min) / span) * height;
      return `${index === 0 ? 'M' : 'L'} ${x.toFixed(2)} ${y.toFixed(2)}`;
    })
    .join(' ');
}

export function TokenDetailsView() {
  const isNativePlatform = Capacitor.isNativePlatform();
  const ScreenWrapper: any = isNativePlatform ? 'div' : motion.div;
  const setView = useAppStore((state) => state.setView);
  const setSelectedReceiveToken = useAppStore((state) => state.setSelectedReceiveToken);
  const setSelectedBuyToken = useAppStore((state) => state.setSelectedBuyToken);
  const selectedAssetToken = useAppStore((state) => state.selectedAssetToken);
  const accounts = useAppStore((state) => state.accounts);
  const activeAccountId = useAppStore((state) => state.activeAccountId);
  const activeChainKey = useAppStore((state) => state.activeChainKey);
  const activeAccount = accounts.find((account) => account.id === activeAccountId);

  const [details, setDetails] = useState<ApiTokenDetailsResponse | null>(null);
  const [chartKey, setChartKey] = useState<ChartKey>('24h');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    if (selectedAssetToken) {
      void preloadTokenLogos([selectedAssetToken]);
    }
  }, [selectedAssetToken]);

  useEffect(() => {
    let cancelled = false;

    if (!selectedAssetToken || !activeAccount) {
      setDetails(null);
      return () => {
        cancelled = true;
      };
    }

    setIsLoading(true);
    setErrorMessage(null);
    void getTokenDetails({
      chainKey: activeChainKey,
      walletAddress: activeAccount.address,
      address: selectedAssetToken.isNative ? undefined : selectedAssetToken.address,
      symbol: selectedAssetToken.symbol,
    })
      .then((response) => {
        if (!cancelled) {
          setDetails(response);
        }
      })
      .catch((error) => {
        if (!cancelled) {
          setDetails(null);
          setErrorMessage(error instanceof Error ? error.message : 'Failed to load token details');
        }
      })
      .finally(() => {
        if (!cancelled) {
          setIsLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [activeAccount, activeChainKey, selectedAssetToken]);

  const token = details?.token || selectedAssetToken;
  const hasHoldings = Number(token.rawBalance || 0) > 0;
  const activeChart = useMemo(() => {
    if (!details) {
      return null;
    }
    return chartKey === '24h'
      ? details.chart24h
      : chartKey === 'week'
        ? details.chartWeek
        : details.chartMonth;
  }, [chartKey, details]);

  if (!selectedAssetToken || !activeAccount || !token) {
    return (
      <div className="absolute inset-0 flex flex-col items-center justify-center bg-zinc-950 px-6 text-center">
        <p className="text-zinc-400">Token not found</p>
        <button onClick={() => setView('main')} className="mt-4 text-indigo-400">
          Go back
        </button>
      </div>
    );
  }

  const line = activeChart
    ? chartPath(activeChart.points, 320, 120, hasHoldings ? 'valueUsd' : 'priceUsd')
    : '';

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
          <ArrowLeft className="h-5 w-5 text-white" />
        </button>
        <h1 className="text-lg font-semibold text-white">{token.symbol}</h1>
        <div className="w-10" />
      </div>

      <div className="flex-1 overflow-y-auto px-6 py-5 pb-24">
        <div className="space-y-4">
          <div className="rounded-3xl border border-white/5 bg-zinc-900 p-5">
            <div className="flex items-start justify-between gap-4">
              <div className="flex min-w-0 items-center gap-4">
                <TokenLogo
                  symbol={token.symbol}
                  logo={token.logo}
                  address={selectedAssetToken.isNative ? undefined : token.address}
                  className="h-14 w-14"
                />
                <div className="min-w-0">
                  <div className="truncate text-2xl font-semibold text-white">{token.symbol}</div>
                  <div className="truncate text-sm text-zinc-400">{token.name}</div>
                </div>
              </div>
            </div>

            <div className="mt-6 grid grid-cols-2 gap-3">
              <div className="rounded-2xl bg-zinc-950 p-4">
                <div className="mb-1 text-[11px] uppercase tracking-[0.18em] text-zinc-500">Balance</div>
                <div className="text-lg font-semibold text-white">
                  {token.balance} {token.symbol}
                </div>
                <div className="mt-1 text-xs text-zinc-400">{formatUsd(Number(token.fiatValue || 0), true)}</div>
              </div>
              <div className="rounded-2xl bg-zinc-950 p-4">
                <div className="mb-1 text-[11px] uppercase tracking-[0.18em] text-zinc-500">Market Price</div>
                <div className="text-lg font-semibold text-white">
                  {(details?.marketPriceUsd || token.priceUsd || 0) > 0
                    ? formatUsd(details?.marketPriceUsd || token.priceUsd || 0)
                    : 'Market price unavailable'}
                </div>
                <div className="mt-1 text-xs text-zinc-400">Current market value per token</div>
              </div>
            </div>

            <div className="mt-5 grid grid-cols-2 gap-3">
              <button
                onClick={() => {
                  setSelectedBuyToken(token);
                  setView('buy');
                }}
                className="flex items-center justify-center gap-2 rounded-2xl bg-white py-3 font-semibold text-black transition-transform hover:scale-[1.01] active:scale-[0.99]"
              >
                <CreditCard className="h-4 w-4" />
                Buy
              </button>
              <button
                onClick={() => {
                  setSelectedReceiveToken({
                    ...token,
                    receiveAddress: activeAccount.address,
                  });
                  setView('receive-qr');
                }}
                className="flex items-center justify-center gap-2 rounded-2xl border border-white/10 bg-zinc-950 py-3 font-semibold text-white transition-colors hover:bg-zinc-800"
              >
                <ArrowDownToLine className="h-4 w-4" />
                Receive
              </button>
            </div>
          </div>

          <div className="rounded-3xl border border-white/5 bg-zinc-900 p-5">
            <div className="mb-4 flex items-center justify-between gap-3">
              <div>
                <div className="flex items-center gap-2 text-white">
                  <TrendingUp className="h-4 w-4 text-indigo-400" />
                  <span className="font-medium">Value Trend</span>
                </div>
                <div className="mt-1 text-xs text-zinc-500">
                  {hasHoldings ? 'Current holdings value' : 'Market price'} across {activeChart?.label || '24H'}
                </div>
              </div>

              <div className="flex items-center gap-2 rounded-full border border-white/5 bg-zinc-950 p-1">
                {[
                  ['24h', '24H'],
                  ['week', '1W'],
                  ['month', '1M'],
                ].map(([key, label]) => (
                  <button
                    key={key}
                    onClick={() => setChartKey(key as ChartKey)}
                    className={`rounded-full px-3 py-1 text-xs font-medium transition-colors ${
                      chartKey === key
                        ? 'bg-indigo-500 text-white'
                        : 'text-zinc-400 hover:text-white'
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            {isLoading ? (
              <div className="flex h-40 items-center justify-center text-sm text-zinc-500">
                Loading chart...
              </div>
            ) : errorMessage ? (
              <div className="flex h-40 items-center justify-center text-center text-sm text-red-400">
                {errorMessage}
              </div>
            ) : activeChart && activeChart.points.length > 1 ? (
              <>
                <div className="mb-4 flex items-end justify-between gap-4">
                  <div>
                    <div className="text-2xl font-semibold text-white">
                      {formatUsd(
                        hasHoldings
                          ? activeChart.points[activeChart.points.length - 1]?.valueUsd || 0
                          : activeChart.points[activeChart.points.length - 1]?.priceUsd || 0,
                        true,
                      )}
                    </div>
                    <div className="mt-1 text-xs text-zinc-500">
                      {hasHoldings
                        ? `${formatUsd(activeChart.points[activeChart.points.length - 1]?.priceUsd || 0)} per ${token.symbol}`
                        : `Spot ${formatUsd(activeChart.points[activeChart.points.length - 1]?.priceUsd || 0)}`}
                    </div>
                  </div>
                  <div className={`text-sm font-medium ${
                    activeChart.changePct >= 0 ? 'text-emerald-400' : 'text-red-400'
                  }`}>
                    {activeChart.changePct >= 0 ? '+' : ''}
                    {activeChart.changePct.toFixed(2)}%
                  </div>
                </div>

                <div className="overflow-hidden rounded-3xl border border-white/5 bg-zinc-950 p-3">
                  <svg viewBox="0 0 320 140" className="h-36 w-full">
                    <defs>
                      <linearGradient id="token-chart-line" x1="0%" y1="0%" x2="100%" y2="0%">
                        <stop offset="0%" stopColor="#818cf8" />
                        <stop offset="100%" stopColor="#22c55e" />
                      </linearGradient>
                    </defs>
                    <path
                      d={line}
                      fill="none"
                      stroke="url(#token-chart-line)"
                      strokeWidth="3"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                </div>
              </>
            ) : (
              <div className="flex h-40 items-center justify-center text-center text-sm text-zinc-500">
                Market chart is not available for this asset yet.
              </div>
            )}
          </div>

          <div className="rounded-3xl border border-white/5 bg-zinc-900 overflow-hidden">
            {[
              ['Receive Address', compactAddress(activeAccount.address)],
              ['Token Address', selectedAssetToken.isNative ? 'Native asset' : compactAddress(token.address)],
            ].map(([label, value], index, rows) => (
              <div
                key={label}
                className={`flex items-start justify-between gap-4 p-4 ${
                  index !== rows.length - 1 ? 'border-b border-white/5' : ''
                }`}
              >
                <span className="text-sm text-zinc-500">{label}</span>
                <span className="max-w-[55%] text-right text-sm font-medium text-white">{value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </ScreenWrapper>
  );
}
