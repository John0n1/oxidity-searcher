import { walletEnv } from './env';
import type {
  WalletBootstrap,
  WalletPortfolio,
  WalletQuotePreview,
  WalletQuotePreviewRequest,
} from '@/types/wallet';

const API_BASE = walletEnv.apiBase.replace(/\/$/, '');

const FALLBACK_BOOTSTRAP: WalletBootstrap = {
  productName: 'Oxidity Wallet',
  tagline:
    'Self-custody Ethereum access with live multi-chain reads, private-ready routing, and a cleaner path into production infrastructure.',
  supportEmail: walletEnv.supportEmail,
  defaultChainId: 1,
  chains: [
    {
      id: 1,
      slug: 'ethereum',
      name: 'Ethereum',
      rpcLabel: 'Local node',
      nativeCurrency: 'ETH',
      sourceLabel: 'local-node',
      explorerAddressUrl: 'https://etherscan.io/address/',
    },
    {
      id: 42161,
      slug: 'arbitrum',
      name: 'Arbitrum One',
      rpcLabel: 'PublicNode',
      nativeCurrency: 'ETH',
      sourceLabel: 'publicnode',
      explorerAddressUrl: 'https://arbiscan.io/address/',
    },
    {
      id: 8453,
      slug: 'base',
      name: 'Base',
      rpcLabel: 'PublicNode',
      nativeCurrency: 'ETH',
      sourceLabel: 'publicnode',
      explorerAddressUrl: 'https://basescan.org/address/',
    },
    {
      id: 10,
      slug: 'optimism',
      name: 'Optimism',
      rpcLabel: 'PublicNode',
      nativeCurrency: 'ETH',
      sourceLabel: 'publicnode',
      explorerAddressUrl: 'https://optimistic.etherscan.io/address/',
    },
    {
      id: 137,
      slug: 'polygon',
      name: 'Polygon',
      rpcLabel: 'PublicNode',
      nativeCurrency: 'POL',
      sourceLabel: 'publicnode',
      explorerAddressUrl: 'https://polygonscan.com/address/',
    },
    {
      id: 56,
      slug: 'bsc',
      name: 'BNB Smart Chain',
      rpcLabel: 'PublicNode',
      nativeCurrency: 'BNB',
      sourceLabel: 'publicnode',
      explorerAddressUrl: 'https://bscscan.com/address/',
    },
    {
      id: 43114,
      slug: 'avalanche',
      name: 'Avalanche C-Chain',
      rpcLabel: 'PublicNode',
      nativeCurrency: 'AVAX',
      sourceLabel: 'publicnode',
      explorerAddressUrl: 'https://snowtrace.io/address/',
    },
  ],
  features: {
    privateExecution: true,
    mevProtection: true,
    sponsorship: true,
    extension: true,
    android: true,
  },
  downloads: {
    extensionUrl: walletEnv.downloadExtensionUrl,
    androidUrl: walletEnv.downloadAndroidUrl,
  },
  business: {
    contactUrl: walletEnv.businessUrl,
    docsUrl: walletEnv.docsUrl,
    statusUrl: walletEnv.statusUrl,
  },
  copy: {
    welcomeTitle: 'Self-custody with live chain access',
    welcomeBody:
      'Create or import a wallet, keep your keys local, and read live balances across Ethereum and supported EVM networks without falling back to a generic wallet stack.',
    walkthrough: [
      {
        id: 'portfolio',
        title: 'Live multi-chain portfolio',
        description:
          'Ethereum mainnet comes from the local node. The supported L2 and sidechain reads come from dedicated PublicNode endpoints.',
      },
      {
        id: 'private',
        title: 'Private execution where it helps',
        description:
          'Routing stays private-ready for flows that benefit from avoiding the public mempool.',
      },
      {
        id: 'business',
        title: 'Same product, stronger path for teams',
        description:
          'The public wallet is also the front door into partner access, reporting, and production onboarding.',
      },
    ],
  },
};

const FALLBACK_QUOTES: Record<string, number> = {
  ETH_USDC: 3450,
  ETH_USDT: 3448,
  ETH_DAI: 3442,
  USDC_ETH: 1 / 3450,
  USDT_ETH: 1 / 3448,
  DAI_ETH: 1 / 3442,
};

export async function fetchWalletBootstrap(): Promise<WalletBootstrap> {
  try {
    const response = await fetch(`${API_BASE}/bootstrap`, {
      headers: {
        Accept: 'application/json',
      },
    });

    if (!response.ok) {
      return FALLBACK_BOOTSTRAP;
    }

    return (await response.json()) as WalletBootstrap;
  } catch {
    return FALLBACK_BOOTSTRAP;
  }
}

export async function fetchWalletPortfolio(address: string): Promise<WalletPortfolio> {
  const response = await fetch(`${API_BASE}/portfolio`, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ address }),
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'portfolio unavailable');
  }

  return (await response.json()) as WalletPortfolio;
}

export async function quoteSwapPreview(
  input: WalletQuotePreviewRequest
): Promise<WalletQuotePreview> {
  try {
    const response = await fetch(`${API_BASE}/quote-preview`, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(input),
    });

    if (!response.ok) {
      throw new Error('quote unavailable');
    }

    return (await response.json()) as WalletQuotePreview;
  } catch {
    const rate = FALLBACK_QUOTES[`${input.sellToken}_${input.buyToken}`] ?? 0;
    const sellAmount = Number.parseFloat(input.sellAmount || '0');
    return {
      chainId: input.chainId,
      sellToken: input.sellToken,
      buyToken: input.buyToken,
      sellAmount: input.sellAmount,
      estimatedBuyAmount: rate > 0 ? (sellAmount * rate).toFixed(4) : '0',
      estimatedPriceImpactBps: 18,
      gasEstimateWei: '2100000000000000',
      executionMode: 'private',
      sponsorshipEligible: false,
      rebateEligible: false,
      notes: [
        'Preview is using the local fallback model because the wallet API is unavailable.',
        'Amounts shown here are indicative only until backend routing is online.',
      ],
    };
  }
}
