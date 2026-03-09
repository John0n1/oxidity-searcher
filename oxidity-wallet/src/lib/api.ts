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
  receiveAddress?: string;
  logo?: string;
  isNative?: boolean;
  isCustom?: boolean;
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
  sellAmount: number;
  receiveAmount: number;
  rate: number;
  sellUsdValue: number;
  receiveUsdValue: number;
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
  expectedOutFormatted: string;
  buySymbol: string;
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

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    headers: {
      'content-type': 'application/json',
      ...(init?.headers || {}),
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
}): Promise<PortfolioResponse> {
  return request<PortfolioResponse>('/api/portfolio', {
    method: 'POST',
    body: JSON.stringify(input),
  });
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
    body: JSON.stringify(input),
  });
}

export function getActivity(address: string, chainKey?: string): Promise<ApiActivityItem[]> {
  return request<ApiActivityItem[]>('/api/activity', {
    method: 'POST',
    body: JSON.stringify({ address, chainKey }),
  });
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
