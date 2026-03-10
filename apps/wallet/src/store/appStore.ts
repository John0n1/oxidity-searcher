import { create } from 'zustand';
import { Wallet, getAddress } from 'ethers';
import { ed25519 } from '@noble/curves/ed25519';

import {
  deriveSolanaPrivateKeyFromMnemonic,
  resolveAccountAddress,
  supportsChainAddress,
} from '../lib/chainAddresses';
import { getDefaultWalletAvatarId, type WalletAvatarId } from '../lib/walletDefaults';
import type { ApiActivityItem, ApiNft, ApiToken, NetworkHealth } from '../lib/api';
import { getActivity, getNetworks, getPortfolio, resolveToken } from '../lib/api';
import {
  addAccountFromVault,
  clearVault,
  createWallet as createWalletVault,
  emptyVault,
  exportRecoveryPhrase,
  exportPrivateKey,
  getAccountPrivateKeyFromVault,
  hydrateVaultChainAddresses,
  importWallet as importWalletVault,
  loadVault,
  reencryptVaultSecrets,
  saveVault,
  type PersistedTrackedToken,
  type PersistedVault,
  type PersistedWalletAccount,
  type SecretType,
  verifyPasscode,
} from '../lib/walletVault';
import {
  removeSavedBiometricPasscode,
  savePasscodeForBiometrics,
} from '../lib/nativeAuth';

type View =
  | 'splash'
  | 'welcome'
  | 'create-wallet'
  | 'import-wallet'
  | 'walkthrough'
  | 'token-management'
  | 'token-details'
  | 'send'
  | 'buy'
  | 'legal'
  | 'support'
  | 'advanced'
  | 'licenses'
  | 'ai'
  | 'subscription'
  | 'transaction-details'
  | 'receive'
  | 'receive-qr'
  | 'address-book'
  | 'main';

type MainTab = 'home' | 'activity' | 'swap' | 'nfts' | 'insights' | 'settings';
type SyncStatus = 'idle' | 'loading' | 'error';
export type WalletAuthPurpose = 'activity' | 'portfolio_insights' | 'send_broadcast';

export interface WalletAuthProof {
  walletAddress: string;
  chainKey: string;
  purpose: WalletAuthPurpose;
  timestamp: number;
  signature: string;
}

export interface AddressBookEntry {
  id: string;
  name: string;
  address: string;
  chainKey: string;
}

export interface Account {
  id: string;
  name: string;
  avatarId: WalletAvatarId;
  address: string;
  balance: number;
  fiatBalance: number;
  chainKey: string;
  secretType?: SecretType;
  derivationIndex?: number;
}

export interface NFT {
  id: string;
  chainKey: string;
  contractAddress: string;
  tokenId: string;
  name: string;
  collection: string;
  image: string;
  price: string;
  priceFiat: string;
  externalUrl: string;
  explorerUrl: string;
}

export interface Token {
  id: string;
  symbol: string;
  name: string;
  address: string;
  balance: string;
  fiatBalance: string;
  logo?: string;
  priceUsd?: number;
  priceSource?: string;
  chainKey?: string;
  receiveAddress?: string;
  isNative?: boolean;
  isCustom?: boolean;
  rawBalance?: number;
  fiatValue?: number;
  decimals?: number;
}

export interface WalletInsights {
  protectedTxCount: number;
  rebatesUsd: number;
  gasSavedUsd: number;
  totalSavedUsd: number;
  privateRoutingPct: number;
}

export interface WalletActivityItem extends ApiActivityItem {}

interface AppState {
  vault: PersistedVault;
  currentView: View;
  currentTab: MainTab;
  walletCreated: boolean;
  isReady: boolean;
  syncStatus: SyncStatus;
  errorMessage: string | null;
  activeChainKey: string;
  availableNetworks: NetworkHealth[];
  sessionPasscode: string | null;

  accounts: Account[];
  activeAccountId: string;
  addressBook: AddressBookEntry[];
  nfts: NFT[];
  customTokens: Token[];
  nativeAsset: Token | null;
  activity: WalletActivityItem[];
  insights: WalletInsights;

  biometricsEnabled: boolean;
  isLocked: boolean;
  isSubscribed: boolean;
  firstMessageTimestamp: number | null;

  selectedTransaction: WalletActivityItem | null;
  selectedAssetToken: Token | null;
  selectedBuyToken: Token | null;
  selectedReceiveToken: Token | null;

  initialize: () => Promise<void>;
  refreshNetworks: () => Promise<void>;
  refreshWalletData: () => Promise<void>;
  createWallet: (passcode: string) => Promise<{ mnemonic: string }>;
  importWallet: (input: {
    secret: string;
    importType: SecretType;
    passcode: string;
  }) => Promise<void>;
  unlockWallet: (passcode: string) => Promise<boolean>;
  exportActivePrivateKey: () => Promise<string>;
  exportActiveRecoveryPhrase: () => Promise<string>;
  exportActivePrivateKeyWithPasscode: (passcode: string) => Promise<string>;
  exportActiveRecoveryPhraseWithPasscode: (passcode: string) => Promise<string>;
  changePasscode: (currentPasscode: string, nextPasscode: string) => Promise<void>;

  setView: (view: View) => void;
  setTab: (tab: MainTab) => void;
  setActiveChainKey: (chainKey: string) => Promise<void>;
  setWalletCreated: (created: boolean) => void;

  addAccount: (input?: { name?: string }) => Promise<void>;
  setActiveAccount: (id: string) => void;
  setAccountAvatar: (id: string, avatarId: WalletAvatarId) => void;
  renameAccount: (id: string, name: string) => void;
  removeActiveAccount: () => void;

  addAddressBookEntry: (entry: Omit<AddressBookEntry, 'id' | 'chainKey'>) => void;
  removeAddressBookEntry: (id: string) => void;

  setSelectedTransaction: (tx: WalletActivityItem | null) => void;
  setSelectedAssetToken: (token: Token | null) => void;
  setSelectedBuyToken: (token: Token | null) => void;
  setSelectedReceiveToken: (token: Token | null) => void;

  addCustomToken: (token: Token) => void;
  resolveAndAddCustomToken: (address: string) => Promise<Token>;

  setBiometricsEnabled: (enabled: boolean) => void;
  setIsLocked: (locked: boolean) => void;
  setSubscribed: (subscribed: boolean) => void;
  setFirstMessageTimestamp: (timestamp: number | null) => void;
  buildWalletAuth: (
    purpose: WalletAuthPurpose,
    options?: { walletAddress?: string; chainKey?: string },
  ) => Promise<WalletAuthProof | null>;
}

const EMPTY_INSIGHTS: WalletInsights = {
  protectedTxCount: 0,
  rebatesUsd: 0,
  gasSavedUsd: 0,
  totalSavedUsd: 0,
  privateRoutingPct: 0,
};

const initialVault = emptyVault();

function walletAuthMessage(input: {
  purpose: WalletAuthPurpose;
  chainKey: string;
  walletAddress: string;
  timestamp: number;
}): string {
  return [
    'Oxidity Wallet Authentication',
    `purpose:${input.purpose}`,
    `chain:${input.chainKey}`,
    `wallet:${input.walletAddress}`,
    `ts:${input.timestamp}`,
  ].join('\n');
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  bytes.forEach((value) => {
    binary += String.fromCharCode(value);
  });
  return btoa(binary);
}

function accountFromPersisted(account: PersistedWalletAccount, chainKey: string): Account {
  return {
    id: account.id,
    name: account.name,
    avatarId: account.avatarId || getDefaultWalletAvatarId(),
    address: resolveAccountAddress(account, chainKey),
    balance: 0,
    fiatBalance: 0,
    chainKey,
    secretType: account.secretType,
    derivationIndex: account.derivationIndex,
  };
}

function mapPersistedTokens(vaultTokens: PersistedTrackedToken[]): Token[] {
  return vaultTokens.map((token) => ({
    id: token.id,
    symbol: token.symbol,
    name: token.name,
    address: token.address,
    balance: '0',
    fiatBalance: '0.00',
    logo: token.logo,
    chainKey: token.chainKey,
    receiveAddress: token.address,
    isCustom: true,
  }));
}

function mapApiToken(token: ApiToken): Token {
  return {
    id: token.id,
    symbol: token.symbol,
    name: token.name,
    address: token.address,
    balance: token.balance,
    fiatBalance: token.fiatBalance,
    logo: token.logo,
    priceUsd: token.priceUsd,
    priceSource: token.priceSource,
    chainKey: token.chainKey,
    receiveAddress: token.receiveAddress || token.address,
    isNative: token.isNative,
    isCustom: token.isCustom,
    rawBalance: token.rawBalance,
    fiatValue: token.fiatValue,
    decimals: token.decimals,
  };
}

function mapApiNft(nft: ApiNft): NFT {
  return {
    id: nft.id,
    chainKey: nft.chainKey,
    contractAddress: nft.contractAddress,
    tokenId: nft.tokenId,
    name: nft.name,
    collection: nft.collection,
    image: nft.image,
    price: nft.price,
    priceFiat: nft.priceFiat,
    externalUrl: nft.externalUrl,
    explorerUrl: nft.explorerUrl,
  };
}

function persistVaultUpdate(
  set: (partial: Partial<AppState> | ((state: AppState) => Partial<AppState>)) => void,
  get: () => AppState,
  updater: (vault: PersistedVault) => PersistedVault,
) {
  const state = get();
  const vault = updater(state.vault);
  void saveVault(vault);
  set({
    vault,
    walletCreated: vault.walletCreated,
    activeChainKey: vault.activeChainKey,
    accounts: vault.accounts.map((account) => {
      const current = state.accounts.find((existing) => existing.id === account.id);
      return {
        ...accountFromPersisted(account, vault.activeChainKey),
        balance: current?.balance || 0,
        fiatBalance: current?.fiatBalance || 0,
      };
    }),
    activeAccountId: vault.activeAccountId || vault.accounts[0]?.id || '',
    addressBook: vault.addressBook,
    biometricsEnabled: vault.biometricsEnabled,
    isSubscribed: vault.isSubscribed,
    firstMessageTimestamp: vault.firstMessageTimestamp,
    customTokens: mapPersistedTokens(vault.customTokens).map((token) => {
      const current = state.customTokens.find((existing) => existing.id === token.id);
      return current ? { ...token, ...current } : token;
    }),
  });
}

export const useAppStore = create<AppState>((set, get) => ({
  vault: initialVault,
  currentView: 'splash',
  currentTab: 'home',
  walletCreated: initialVault.walletCreated,
  isReady: false,
  syncStatus: 'idle',
  errorMessage: null,
  activeChainKey: initialVault.activeChainKey,
  availableNetworks: [],
  sessionPasscode: null,

  accounts: initialVault.accounts.map((account) =>
    accountFromPersisted(account, initialVault.activeChainKey),
  ),
  activeAccountId: initialVault.activeAccountId || initialVault.accounts[0]?.id || '',
  addressBook: initialVault.addressBook,
  nfts: [],
  customTokens: mapPersistedTokens(initialVault.customTokens),
  nativeAsset: null,
  activity: [],
  insights: EMPTY_INSIGHTS,

  biometricsEnabled: initialVault.biometricsEnabled,
  isLocked: initialVault.walletCreated,
  isSubscribed: initialVault.isSubscribed,
  firstMessageTimestamp: initialVault.firstMessageTimestamp,

  selectedTransaction: null,
  selectedAssetToken: null,
  selectedBuyToken: null,
  selectedReceiveToken: null,

  async initialize() {
    const { vault, errorMessage } = await loadVault();
    set({
      vault,
      isReady: true,
      walletCreated: vault.walletCreated,
      activeChainKey: vault.activeChainKey,
      accounts: vault.accounts.map((account) => accountFromPersisted(account, vault.activeChainKey)),
      activeAccountId: vault.activeAccountId || vault.accounts[0]?.id || '',
      addressBook: vault.addressBook,
      biometricsEnabled: vault.biometricsEnabled,
      isSubscribed: vault.isSubscribed,
      firstMessageTimestamp: vault.firstMessageTimestamp,
      customTokens: mapPersistedTokens(vault.customTokens),
      isLocked: vault.walletCreated,
      currentView: vault.walletCreated ? 'main' : 'splash',
      errorMessage,
      selectedAssetToken: null,
      selectedBuyToken: null,
      selectedReceiveToken: null,
      selectedTransaction: null,
    });
    void get().refreshNetworks();
    if (vault.walletCreated && vault.accounts.length > 0) {
      void get().refreshWalletData();
    }
  },

  async refreshNetworks() {
    try {
      const state = get();
      const activeAccount = state.vault.accounts.find(
        (account) => account.id === state.activeAccountId,
      );
      const networks = await getNetworks();
      set({
        availableNetworks: networks.filter((network) => {
          const supportedProtocol = network.protocol === 'evm' || network.protocol === 'solana';
          if (!supportedProtocol) {
            return false;
          }
          return activeAccount ? supportsChainAddress(activeAccount, network.key) : network.protocol === 'evm';
        }),
      });
    } catch {
      // Keep the current list if network discovery fails.
    }
  },

  async refreshWalletData() {
    const state = get();
    const activeAccount = state.accounts.find((account) => account.id === state.activeAccountId);
    if (!activeAccount) {
      return;
    }

    set({ syncStatus: 'loading', errorMessage: null });

    try {
      const trackedTokens = state.vault.customTokens.filter(
        (token) => token.chainKey === state.activeChainKey,
      );
      const [portfolioAuth, activityAuth] = await Promise.all([
        get().buildWalletAuth('portfolio_insights'),
        get().buildWalletAuth('activity'),
      ]);

      const [portfolio, activity] = await Promise.all([
        getPortfolio({
          address: activeAccount.address,
          chainKey: state.activeChainKey,
          customTokens: trackedTokens,
          auth: portfolioAuth || undefined,
        }),
        getActivity(activeAccount.address, state.activeChainKey, activityAuth || undefined),
      ]);

      const nativeAsset = mapApiToken(portfolio.nativeAsset);
      const tokenByAddress = new Map(
        portfolio.tokens.map((token) => [token.address.toLowerCase(), mapApiToken(token)]),
      );

      const customTokens = trackedTokens.map((token) => {
        const resolved = tokenByAddress.get(token.address.toLowerCase());
        return (
          resolved || {
            id: token.id,
            symbol: token.symbol,
            name: token.name,
            address: token.address,
            balance: '0',
            fiatBalance: '0.00',
            logo: token.logo,
            chainKey: token.chainKey,
            receiveAddress: activeAccount.address,
            isCustom: true,
          }
        );
      });

      set((current) => ({
        syncStatus: 'idle',
        nativeAsset,
        customTokens,
        nfts: portfolio.nfts.map(mapApiNft),
        activity,
        insights: portfolio.insights || EMPTY_INSIGHTS,
        accounts: current.accounts.map((account) =>
          account.id === activeAccount.id
            ? {
                ...account,
                balance: portfolio.account.nativeBalance,
                fiatBalance: portfolio.account.fiatBalance,
              }
            : account,
        ),
      }));
    } catch (error) {
      set({
        syncStatus: 'error',
        errorMessage: error instanceof Error ? error.message : 'Failed to refresh wallet data',
      });
    }
  },

  async createWallet(passcode) {
    const result = await createWalletVault(passcode);
    const current = get();
    const vault: PersistedVault = {
      ...result.vault,
      biometricsEnabled: current.biometricsEnabled,
      isSubscribed: current.isSubscribed,
      firstMessageTimestamp: current.firstMessageTimestamp,
    };

    await saveVault(vault);
    set({
      vault,
      walletCreated: true,
      sessionPasscode: passcode,
      accounts: vault.accounts.map((account) => accountFromPersisted(account, vault.activeChainKey)),
      activeAccountId: result.account.id,
      currentTab: 'home',
      isLocked: false,
      customTokens: mapPersistedTokens(vault.customTokens),
      addressBook: [],
      activity: [],
      nativeAsset: null,
      nfts: [],
      errorMessage: null,
    });

    if (vault.biometricsEnabled) {
      void savePasscodeForBiometrics(passcode);
    }
    void get().refreshNetworks();
    await get().refreshWalletData();
    return { mnemonic: result.mnemonic };
  },

  async importWallet({ secret, importType, passcode }) {
    const result = await importWalletVault({
      secret,
      importType,
      passcode,
      name: 'Main Wallet',
    });
    const current = get();
    const vault: PersistedVault = {
      ...result.vault,
      biometricsEnabled: current.biometricsEnabled,
      isSubscribed: current.isSubscribed,
      firstMessageTimestamp: current.firstMessageTimestamp,
    };

    await saveVault(vault);
    set({
      vault,
      walletCreated: true,
      sessionPasscode: passcode,
      accounts: vault.accounts.map((account) => accountFromPersisted(account, vault.activeChainKey)),
      activeAccountId: result.account.id,
      currentTab: 'home',
      isLocked: false,
      customTokens: mapPersistedTokens(vault.customTokens),
      addressBook: [],
      activity: [],
      nativeAsset: null,
      nfts: [],
      errorMessage: null,
    });

    if (vault.biometricsEnabled) {
      void savePasscodeForBiometrics(passcode);
    }
    void get().refreshNetworks();
    await get().refreshWalletData();
  },

  async unlockWallet(passcode) {
    const valid = await verifyPasscode(get().vault.accounts, passcode);
    if (!valid) {
      return false;
    }

    const hydratedVault = await hydrateVaultChainAddresses(get().vault, passcode);
    await saveVault(hydratedVault);
    set({
      vault: hydratedVault,
      sessionPasscode: passcode,
      isLocked: false,
      currentView: 'main',
      errorMessage: null,
      accounts: hydratedVault.accounts.map((account) =>
        accountFromPersisted(account, hydratedVault.activeChainKey),
      ),
    });
    if (get().biometricsEnabled) {
      void savePasscodeForBiometrics(passcode);
    }
    void get().refreshNetworks();
    await get().refreshWalletData();
    return true;
  },

  async exportActivePrivateKey() {
    const state = get();
    if (!state.sessionPasscode) {
      throw new Error('Unlock the wallet first');
    }
    if (!state.activeAccountId) {
      throw new Error('No active account');
    }
    const account = state.vault.accounts.find(
      (candidate) => candidate.id === state.activeAccountId,
    );
    if (!account) {
      throw new Error('Active account not found');
    }
    return exportPrivateKey(account, state.sessionPasscode);
  },

  async exportActiveRecoveryPhrase() {
    const state = get();
    if (!state.sessionPasscode) {
      throw new Error('Unlock the wallet first');
    }
    if (!state.activeAccountId) {
      throw new Error('No active account');
    }
    const account = state.vault.accounts.find(
      (candidate) => candidate.id === state.activeAccountId,
    );
    if (!account) {
      throw new Error('Active account not found');
    }
    return exportRecoveryPhrase(account, state.sessionPasscode);
  },

  async exportActivePrivateKeyWithPasscode(passcode) {
    if (!/^\d{6}$/.test(passcode)) {
      throw new Error('Passcode must be 6 digits');
    }

    const state = get();
    if (!state.activeAccountId) {
      throw new Error('No active account');
    }
    const account = state.vault.accounts.find(
      (candidate) => candidate.id === state.activeAccountId,
    );
    if (!account) {
      throw new Error('Active account not found');
    }

    try {
      return await exportPrivateKey(account, passcode);
    } catch (error) {
      if (
        error instanceof Error
        && error.message === 'Recovery phrase export is only available for mnemonic wallets'
      ) {
        throw error;
      }
      throw new Error('Passcode is incorrect');
    }
  },

  async exportActiveRecoveryPhraseWithPasscode(passcode) {
    if (!/^\d{6}$/.test(passcode)) {
      throw new Error('Passcode must be 6 digits');
    }

    const state = get();
    if (!state.activeAccountId) {
      throw new Error('No active account');
    }
    const account = state.vault.accounts.find(
      (candidate) => candidate.id === state.activeAccountId,
    );
    if (!account) {
      throw new Error('Active account not found');
    }

    try {
      return await exportRecoveryPhrase(account, passcode);
    } catch (error) {
      if (
        error instanceof Error
        && error.message === 'Recovery phrase export is only available for mnemonic wallets'
      ) {
        throw error;
      }
      throw new Error('Passcode is incorrect');
    }
  },

  async changePasscode(currentPasscode, nextPasscode) {
    const state = get();
    if (!/^\d{6}$/.test(currentPasscode)) {
      throw new Error('Current passcode must be 6 digits');
    }
    if (!/^\d{6}$/.test(nextPasscode)) {
      throw new Error('New passcode must be 6 digits');
    }
    if (!(await verifyPasscode(state.vault.accounts, currentPasscode))) {
      throw new Error('Current passcode is incorrect');
    }

    const vault = await reencryptVaultSecrets(state.vault, currentPasscode, nextPasscode);
    await saveVault(vault);
    set({
      vault,
      sessionPasscode: nextPasscode,
      errorMessage: null,
    });

    if (state.biometricsEnabled) {
      void savePasscodeForBiometrics(nextPasscode);
    }
  },

  setView: (view) => set({ currentView: view }),
  setTab: (tab) => set({ currentTab: tab }),
  setActiveChainKey: async (chainKey) => {
    const state = get();
    if (!chainKey || chainKey === state.activeChainKey) {
      return;
    }

    persistVaultUpdate(set, get, (vault) => ({
      ...vault,
      activeChainKey: chainKey,
    }));
    set({
      accounts: state.vault.accounts.map((account) => accountFromPersisted(account, chainKey)),
      nativeAsset: null,
      customTokens: state.customTokens.filter((token) => token.chainKey === chainKey),
      nfts: [],
      activity: [],
      selectedTransaction: null,
      selectedAssetToken: null,
      selectedBuyToken: null,
      selectedReceiveToken: null,
    });
    await get().refreshWalletData();
  },
  setWalletCreated: (created) => {
    persistVaultUpdate(set, get, (vault) => ({
      ...vault,
      walletCreated: created,
    }));
  },

  async addAccount(input) {
    const state = get();
    if (!state.sessionPasscode) {
      throw new Error('Unlock the wallet before adding another account');
    }

    const name = input?.name || `Wallet ${state.accounts.length + 1}`;
    const result = await addAccountFromVault(state.vault, state.sessionPasscode, name);
    await saveVault(result.vault);
    set({
      vault: result.vault,
      accounts: result.vault.accounts.map((account) =>
        accountFromPersisted(account, result.vault.activeChainKey),
      ),
      activeAccountId: result.account.id,
      walletCreated: true,
      currentTab: 'home',
    });
    await get().refreshWalletData();
  },

  setActiveAccount: (id) => {
    persistVaultUpdate(set, get, (vault) => ({
      ...vault,
      activeAccountId: id,
    }));
    void get().refreshWalletData();
  },

  setAccountAvatar: (id, avatarId) => {
    persistVaultUpdate(set, get, (vault) => ({
      ...vault,
      accounts: vault.accounts.map((account) =>
        account.id === id ? { ...account, avatarId } : account,
      ),
    }));
  },

  renameAccount: (id, name) => {
    persistVaultUpdate(set, get, (vault) => ({
      ...vault,
      accounts: vault.accounts.map((account) =>
        account.id === id ? { ...account, name } : account,
      ),
    }));
  },

  removeActiveAccount: () => {
    const state = get();
    const remainingAccounts = state.vault.accounts.filter(
      (account) => account.id !== state.activeAccountId,
    );

    if (remainingAccounts.length === 0) {
      void clearVault();
      void removeSavedBiometricPasscode();
      const empty = emptyVault();
      set({
        vault: empty,
        walletCreated: false,
        accounts: [],
        activeAccountId: '',
        addressBook: [],
        customTokens: mapPersistedTokens(empty.customTokens),
        nativeAsset: null,
        activity: [],
        insights: EMPTY_INSIGHTS,
        sessionPasscode: null,
        biometricsEnabled: false,
        isLocked: false,
        currentView: 'welcome',
        selectedAssetToken: null,
        selectedBuyToken: null,
        selectedReceiveToken: null,
        selectedTransaction: null,
      });
      return;
    }

    const nextVault: PersistedVault = {
      ...state.vault,
      accounts: remainingAccounts,
      activeAccountId: remainingAccounts[0].id,
    };
    void saveVault(nextVault);
    set({
      vault: nextVault,
      accounts: nextVault.accounts.map((account) =>
        accountFromPersisted(account, nextVault.activeChainKey),
      ),
      activeAccountId: nextVault.activeAccountId || '',
      currentView: 'main',
      selectedAssetToken: null,
      selectedBuyToken: null,
      selectedReceiveToken: null,
      selectedTransaction: null,
    });
    void get().refreshWalletData();
  },

  addAddressBookEntry: (entry) => {
    const chainKey = get().activeChainKey;
    const rawAddress = entry.address.trim();
    if (!rawAddress) {
      throw new Error('Address is required');
    }
    const normalizedAddress = chainKey === 'solana'
      ? rawAddress
      : getAddress(rawAddress);
    if (
      chainKey === 'solana'
      && !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(normalizedAddress)
    ) {
      throw new Error('Invalid Solana address');
    }
    persistVaultUpdate(set, get, (vault) => ({
      ...vault,
      addressBook: vault.addressBook.some(
        (candidate) =>
          candidate.chainKey === chainKey
          && candidate.address.toLowerCase() === normalizedAddress.toLowerCase(),
      )
        ? vault.addressBook
        : [
            ...vault.addressBook,
            {
              ...entry,
              id: crypto.randomUUID(),
              address: normalizedAddress,
              chainKey,
            },
          ],
    }));
  },

  removeAddressBookEntry: (id) => {
    persistVaultUpdate(set, get, (vault) => ({
      ...vault,
      addressBook: vault.addressBook.filter((entry) => entry.id !== id),
    }));
  },

  setSelectedTransaction: (tx) => set({ selectedTransaction: tx }),
  setSelectedAssetToken: (token) => set({ selectedAssetToken: token }),
  setSelectedBuyToken: (token) => set({ selectedBuyToken: token }),
  setSelectedReceiveToken: (token) => set({ selectedReceiveToken: token }),

  addCustomToken: (token) => {
    persistVaultUpdate(set, get, (vault) => {
      const nextToken: PersistedTrackedToken = {
        id: token.id,
        chainKey: token.chainKey || vault.activeChainKey,
        symbol: token.symbol,
        name: token.name,
        address: token.address,
        logo: token.logo,
      };
      const existing = vault.customTokens.find(
        (candidate) =>
          candidate.chainKey === nextToken.chainKey &&
          candidate.address.toLowerCase() === nextToken.address.toLowerCase(),
      );
      return {
        ...vault,
        customTokens: existing
          ? vault.customTokens
          : [...vault.customTokens, nextToken],
      };
    });
    void get().refreshWalletData();
  },

  async resolveAndAddCustomToken(address) {
    const state = get();
    const activeAccount = state.accounts.find((account) => account.id === state.activeAccountId);
    const token = await resolveToken({
      address,
      chainKey: state.activeChainKey,
      walletAddress: activeAccount?.address,
    });
    const mapped = mapApiToken({
      ...token,
      id: token.id || `${state.activeChainKey}:${address.toLowerCase()}`,
      chainKey: token.chainKey || state.activeChainKey,
    });
    get().addCustomToken({ ...mapped, isCustom: true });
    return mapped;
  },

  setBiometricsEnabled: (enabled) => {
    persistVaultUpdate(set, get, (vault) => ({
      ...vault,
      biometricsEnabled: enabled,
    }));

    const passcode = get().sessionPasscode;
    if (enabled && passcode) {
      void savePasscodeForBiometrics(passcode);
    }
    if (!enabled) {
      void removeSavedBiometricPasscode();
    }
  },

  setIsLocked: (locked) => {
    set({
      isLocked: locked,
      sessionPasscode: locked ? null : get().sessionPasscode,
    });
  },

  setSubscribed: (subscribed) => {
    persistVaultUpdate(set, get, (vault) => ({
      ...vault,
      isSubscribed: subscribed,
    }));
  },

  setFirstMessageTimestamp: (timestamp) => {
    persistVaultUpdate(set, get, (vault) => ({
      ...vault,
      firstMessageTimestamp: timestamp,
    }));
  },

  async buildWalletAuth(purpose, options) {
    const state = get();
    if (!state.sessionPasscode || !state.activeAccountId) {
      return null;
    }

    const chainKey = options?.chainKey || state.activeChainKey;
    const account = state.vault.accounts.find((candidate) => candidate.id === state.activeAccountId);
    if (!account) {
      return null;
    }

    const walletAddress = options?.walletAddress || resolveAccountAddress(account, chainKey);
    if (!walletAddress) {
      return null;
    }

    const timestamp = Date.now();
    const message = walletAuthMessage({
      purpose,
      chainKey,
      walletAddress,
      timestamp,
    });

    if (chainKey === 'solana') {
      if (account.secretType !== 'mnemonic') {
        return null;
      }

      const phrase = await exportRecoveryPhrase(account, state.sessionPasscode);
      const secretKey = deriveSolanaPrivateKeyFromMnemonic(phrase, account.derivationIndex || 0);
      const signature = ed25519.sign(new TextEncoder().encode(message), secretKey);
      return {
        walletAddress,
        chainKey,
        purpose,
        timestamp,
        signature: bytesToBase64(signature),
      };
    }

    const privateKey = await getAccountPrivateKeyFromVault(
      state.vault,
      account.id,
      state.sessionPasscode,
    );
    const signature = await new Wallet(privateKey).signMessage(message);
    return {
      walletAddress,
      chainKey,
      purpose,
      timestamp,
      signature,
    };
  },
}));
