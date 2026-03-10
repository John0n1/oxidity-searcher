import { Capacitor } from '@capacitor/core';

export interface ApiToken {
  id: string;
  chainKey: string;
  symbol: string;
  name: string;
  address: string;
  decimals?: number;
  balance: string;
  rawBalance: number;
  fiatBalance: string;
  fiatValue: number;
  priceUsd: number;
  priceSource: string;
  receiveAddress?: string;
  logo?: string;
  isNative?: boolean;
  isCustom?: boolean;
}

export interface ApiTokenChartPoint {
  timestamp: number;
  priceUsd: number;
  valueUsd: number;
}

export interface ApiTokenChartSeries {
  label: string;
  source: string;
  changePct: number;
  points: ApiTokenChartPoint[];
}

export interface ApiTokenDetailsResponse {
  token: ApiToken;
  marketPriceUsd: number;
  marketPriceSource: string;
  chart24h: ApiTokenChartSeries;
  chartWeek: ApiTokenChartSeries;
  chartMonth: ApiTokenChartSeries;
}

export interface ApiNft {
  id: string;
  chainKey: string;
  contractAddress: string;
  tokenId: string;
  collection: string;
  name: string;
  image: string;
  price: string;
  priceFiat: string;
  externalUrl: string;
  explorerUrl: string;
}

export interface ApiActivityItem {
  id: string;
  type: string;
  title: string;
  amount: string;
  fiatAmount: string;
  date: string;
  timestamp: number;
  asset: string;
  address?: string;
  isProtected?: boolean;
  rebate?: string;
  hash?: string;
  from?: string;
  to?: string;
  fee?: string;
  network?: string;
  status?: string;
  explorerUrl?: string;
}

export interface PortfolioResponse {
  network: {
    key: string;
    name: string;
    chainId: number;
    nativeSymbol: string;
    explorerTxBaseUrl: string;
  };
  account: {
    address: string;
    nativeBalance: number;
    fiatBalance: number;
  };
  nativeAsset: ApiToken;
  tokens: ApiToken[];
  nfts: ApiNft[];
  insights: {
    protectedTxCount: number;
    rebatesUsd: number;
    gasSavedUsd: number;
    totalSavedUsd: number;
    privateRoutingPct: number;
  };
}

export interface QuotePreviewResponse {
  chainKey: string;
  sellToken: string;
  buyToken: string;
  routerName?: string | null;
  routePath: string[];
  sellAmount: number;
  receiveAmount: number;
  minimumReceived: number;
  rate: number;
  sellUsdValue: number;
  receiveUsdValue: number;
  minimumReceivedUsd: number;
  priceImpactPct: number;
  estimatedGasUsd: number;
  estimatedGasNative: number;
  speedOptions: Record<string, { label: string; eta: string; gasUsd: number }>;
  executionMode: string;
}

export interface SendPrepareResponse {
  protocol: string;
  chainKey: string;
  chainId: number;
  network: string;
  nonce: number;
  gasLimit: string;
  maxFeePerGas: string;
  maxPriorityFeePerGas: string;
  estimatedFeeNative: number;
  estimatedFeeUsd: number;
  explorerTxBaseUrl: string;
  executionMode: string;
  recentBlockhash?: string | null;
  lastValidBlockHeight?: number | null;
  lamportsPerSignature?: number | null;
}

export interface SendBroadcastResponse {
  hash: string;
  status: string;
  explorerUrl: string;
  executionMode: string;
}

export interface SwapPrepareResponse {
  chainKey: string;
  chainId: number;
  network: string;
  routerName: string;
  routePath: string[];
  router: string;
  to: string;
  data: string;
  value: string;
  nonce: number;
  gasLimit: string;
  maxFeePerGas: string;
  maxPriorityFeePerGas: string;
  expectedOut: string;
  minOut: string;
  sellSymbol: string;
  sellAmountFormatted: string;
  expectedOutFormatted: string;
  minimumReceivedFormatted: string;
  buySymbol: string;
  expectedOutUsd: number;
  minimumReceivedUsd: number;
  priceImpactPct: number;
  estimatedFeeNative: number;
  estimatedFeeUsd: number;
  explorerTxBaseUrl: string;
  executionMode: string;
}

export interface OnRampProviderQuote {
  id: string;
  name: string;
  rate: number;
  fee: number;
  deliveryTime: string;
  trustScore: number;
  receiveAmount: number;
  checkoutUrl: string;
}

export interface OnRampQuoteResponse {
  chainKey: string;
  amountUsd: number;
  buyToken: string;
  marketPriceUsd: number;
  providers: OnRampProviderQuote[];
}

export interface NftSendPrepareResponse {
  chainKey: string;
  chainId: number;
  network: string;
  contractAddress: string;
  tokenId: string;
  to: string;
  data: string;
  nonce: number;
  gasLimit: string;
  maxFeePerGas: string;
  maxPriorityFeePerGas: string;
  estimatedFeeNative: number;
  estimatedFeeUsd: number;
  explorerTxBaseUrl: string;
  executionMode: string;
}

export interface AiChatResponse {
  content: string;
  sources: Array<{ uri: string; title: string }>;
}

export interface NetworkHealth {
  key: string;
  name: string;
  protocol: string;
  status: string;
  chainId?: number | null;
  blockNumber?: number | null;
  detail?: string | null;
}

export interface BootstrapResponse {
  appName: string;
  version: string;
  walletAppUrl: string;
  downloads: {
    chromeExtension: string;
    androidApk: string;
  };
  supportedNetworks: NetworkHealth[];
  defaults: {
    chainKey: string;
    features: string[];
  };
}

export interface WalletAuthProof {
  walletAddress: string;
  chainKey: string;
  purpose: string;
  timestamp: number;
  signature: string;
}

const fallbackApiBaseUrl = (() => {
  if (typeof window === 'undefined') {
    return 'http://127.0.0.1:9555';
  }
  if (Capacitor.isNativePlatform()) {
    return 'https://wallet.oxidity.io';
  }
  if (window.location.protocol === 'chrome-extension:') {
    return 'https://wallet.oxidity.io';
  }
  if (
    window.location.hostname === 'localhost' ||
    window.location.hostname === '127.0.0.1'
  ) {
    return 'http://127.0.0.1:9555';
  }
  return window.location.origin;
})();

const apiBaseUrl =
  import.meta.env.VITE_WALLET_API_BASE_URL?.replace(/\/$/, '') || fallbackApiBaseUrl;

function withWalletAuthHeaders(
  headers: HeadersInit | undefined,
  auth: WalletAuthProof | undefined,
): HeadersInit | undefined {
  if (!auth) {
    return headers;
  }

  return {
    ...(headers || {}),
    'x-oxidity-wallet-auth-wallet': auth.walletAddress,
    'x-oxidity-wallet-auth-chain': auth.chainKey,
    'x-oxidity-wallet-auth-purpose': auth.purpose,
    'x-oxidity-wallet-auth-timestamp': String(auth.timestamp),
    'x-oxidity-wallet-auth-signature': auth.signature,
  };
}

async function request<T>(path: string, init?: RequestInit, auth?: WalletAuthProof): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    headers: {
      'content-type': 'application/json',
      ...withWalletAuthHeaders(init?.headers, auth),
    },
    ...init,
  });

  if (!response.ok) {
    let message = `Request failed with status ${response.status}`;
    try {
      const body = (await response.json()) as { error?: string };
      if (body.error) {
        message = body.error;
      }
    } catch {
      // Ignore JSON parsing failure and keep the generic message.
    }
    throw new Error(message);
  }

  return (await response.json()) as T;
}

export function getApiBaseUrl(): string {
  return apiBaseUrl;
}

export function getBootstrap(): Promise<BootstrapResponse> {
  return request<BootstrapResponse>('/api/bootstrap');
}

export function getNetworks(): Promise<NetworkHealth[]> {
  return request<NetworkHealth[]>('/api/networks');
}

export function getCatalog(): Promise<
  Array<{
    chainKey: string;
    name: string;
    nativeSymbol: string;
    tokens: Array<{ symbol: string; name: string; address: string; logo?: string }>;
  }>
> {
  return request('/api/catalog');
}

export function getPortfolio(input: {
  address: string;
  chainKey: string;
  customTokens: Array<{ address: string; symbol?: string; name?: string; logo?: string }>;
  auth?: WalletAuthProof;
}): Promise<PortfolioResponse> {
  return request<PortfolioResponse>('/api/portfolio', {
    method: 'POST',
    body: JSON.stringify({
      address: input.address,
      chainKey: input.chainKey,
      customTokens: input.customTokens,
    }),
  }, input.auth);
}

export function resolveToken(input: {
  address: string;
  chainKey: string;
  walletAddress?: string;
}): Promise<ApiToken> {
  return request<ApiToken>('/api/token/resolve', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export function getTokenDetails(input: {
  chainKey: string;
  walletAddress: string;
  address?: string;
  symbol?: string;
}): Promise<ApiTokenDetailsResponse> {
  return request<ApiTokenDetailsResponse>('/api/token/details', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export function getQuotePreview(input: {
  chainKey: string;
  sellToken?: string;
  buyToken?: string;
  sellAmount: string;
}): Promise<QuotePreviewResponse> {
  return request<QuotePreviewResponse>('/api/quote-preview', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export function prepareNativeSend(input: {
  chainKey: string;
  from: string;
  to: string;
  amount: string;
}): Promise<SendPrepareResponse> {
  return request<SendPrepareResponse>('/api/send/prepare', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export function prepareSwap(input: {
  chainKey: string;
  walletAddress: string;
  sellToken?: string;
  buyToken?: string;
  sellAmount: string;
  slippageBps?: number;
}): Promise<SwapPrepareResponse> {
  return request<SwapPrepareResponse>('/api/swap/prepare', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export function prepareNftSend(input: {
  chainKey: string;
  from: string;
  to: string;
  contractAddress: string;
  tokenId: string;
}): Promise<NftSendPrepareResponse> {
  return request<NftSendPrepareResponse>('/api/nft/send/prepare', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export function broadcastSignedSend(input: {
  chainKey: string;
  rawTransaction: string;
  walletAddress: string;
  auth?: WalletAuthProof;
  encoding?: string;
  txType: string;
  title: string;
  amount: string;
  fiatAmount: string;
  asset: string;
  to: string;
  fee: string;
}): Promise<SendBroadcastResponse> {
  return request<SendBroadcastResponse>('/api/send/broadcast', {
    method: 'POST',
    body: JSON.stringify({
      chainKey: input.chainKey,
      rawTransaction: input.rawTransaction,
      walletAddress: input.walletAddress,
      encoding: input.encoding,
      txType: input.txType,
      title: input.title,
      amount: input.amount,
      fiatAmount: input.fiatAmount,
      asset: input.asset,
      to: input.to,
      fee: input.fee,
    }),
  }, input.auth);
}

export function getActivity(
  address: string,
  chainKey?: string,
  auth?: WalletAuthProof,
): Promise<ApiActivityItem[]> {
  return request<ApiActivityItem[]>('/api/activity', {
    method: 'POST',
    body: JSON.stringify({ address, chainKey }),
  }, auth);
}

export function getOnRampQuote(input: {
  chainKey: string;
  walletAddress: string;
  amountUsd: string;
  buyToken?: string;
}): Promise<OnRampQuoteResponse> {
  return request<OnRampQuoteResponse>('/api/onramp/quote', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export function chatWithAi(message: string): Promise<AiChatResponse> {
  return request<AiChatResponse>('/api/ai/chat', {
    method: 'POST',
    body: JSON.stringify({ message }),
  });
}
