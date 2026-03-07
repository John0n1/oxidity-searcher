export type View =
  | 'splash'
  | 'welcome'
  | 'create-wallet'
  | 'import-wallet'
  | 'walkthrough'
  | 'main';

export type MainTab = 'home' | 'activity' | 'swap' | 'insights' | 'settings';

export type ImportMethod = 'mnemonic' | 'private-key';

export interface Account {
  id: string;
  name: string;
  address: string;
  balance: number;
  fiatBalance: number;
  derivationIndex: number | null;
  derivationPath: string | null;
}

export interface WalletBootstrap {
  productName: string;
  tagline: string;
  supportEmail: string;
  defaultChainId: number;
  chains: Array<{
    id: number;
    slug: string;
    name: string;
    rpcLabel: string;
    nativeCurrency: string;
    sourceLabel: string;
    explorerAddressUrl: string;
  }>;
  features: {
    privateExecution: boolean;
    mevProtection: boolean;
    sponsorship: boolean;
    extension: boolean;
    android: boolean;
  };
  downloads: {
    extensionUrl: string;
    androidUrl: string;
  };
  business: {
    contactUrl: string;
    docsUrl: string;
    statusUrl: string;
  };
  copy: {
    welcomeTitle: string;
    welcomeBody: string;
    walkthrough: Array<{
      id: string;
      title: string;
      description: string;
    }>;
  };
}

export interface WalletVaultData {
  version: 1;
  source: 'mnemonic' | 'private-key';
  secret: string;
  accounts: Account[];
  activeAccountId: string;
  createdAt: string;
  updatedAt: string;
}

export interface PersistedVaultEnvelope {
  version: 1;
  salt: string;
  iv: string;
  ciphertext: string;
  biometricsEnabled: boolean;
  lastUnlockedAt?: string;
}

export interface WalletDraft {
  source: 'mnemonic' | 'private-key';
  secret: string;
  words: string[];
  primaryAccount: Account;
}

export interface WalletQuotePreviewRequest {
  chainId: number;
  sellToken: string;
  buyToken: string;
  sellAmount: string;
}

export interface WalletPortfolioChain {
  chainId: number;
  slug: string;
  name: string;
  nativeCurrency: string;
  sourceLabel: string;
  status: 'ok' | 'degraded';
  latestBlock: number | null;
  gasPriceWei: string | null;
  balanceWei: string | null;
  balanceDisplay: string | null;
  explorerAddressUrl: string;
  error: string | null;
}

export interface WalletPortfolio {
  address: string;
  refreshedAt: string;
  summary: {
    trackedChains: number;
    healthyChains: number;
    fundedChains: number;
    defaultChainBalance: string | null;
    defaultChainSymbol: string | null;
  };
  chains: WalletPortfolioChain[];
  notes: string[];
}

export interface WalletQuotePreview {
  chainId: number;
  sellToken: string;
  buyToken: string;
  sellAmount: string;
  estimatedBuyAmount: string;
  estimatedPriceImpactBps: number;
  gasEstimateWei: string;
  executionMode: 'private' | 'standard';
  sponsorshipEligible: boolean;
  rebateEligible: boolean;
  notes: string[];
}
