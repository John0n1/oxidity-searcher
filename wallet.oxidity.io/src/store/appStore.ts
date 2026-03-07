import { create } from 'zustand';
import { fetchWalletBootstrap, fetchWalletPortfolio } from '@/lib/api';
import { loadJson, saveJson } from '@/lib/storage';
import {
  addDerivedMnemonicAccount,
  createMnemonicDraft,
  importWalletDraft,
  persistVault,
  reencryptVault,
  renameVaultAccount,
  setVaultActiveAccount,
  unlockVault,
} from '@/lib/vault';
import type {
  Account,
  ImportMethod,
  MainTab,
  PersistedVaultEnvelope,
  View,
  WalletBootstrap,
  WalletDraft,
  WalletPortfolio,
  WalletVaultData,
} from '@/types/wallet';

const VAULT_STORAGE_KEY = 'oxidity.wallet.vault';

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function applyUnlockedVault(vault: WalletVaultData) {
  return {
    accounts: vault.accounts,
    activeAccountId: vault.activeAccountId,
  };
}

interface AppState {
  hydrated: boolean;
  hydrating: boolean;
  bootstrap: WalletBootstrap | null;
  bootstrapError: string | null;
  currentView: View;
  currentTab: MainTab;
  walletCreated: boolean;
  importMethod: ImportMethod;
  accounts: Account[];
  activeAccountId: string;
  balance: number;
  fiatBalance: number;
  portfolio: WalletPortfolio | null;
  portfolioError: string | null;
  portfolioRefreshing: boolean;
  biometricsEnabled: boolean;
  isLocked: boolean;
  unlockError: string | null;
  draftWallet: WalletDraft | null;
  vaultEnvelope: PersistedVaultEnvelope | null;
  vaultData: WalletVaultData | null;
  sessionPasscode: string | null;
  hydrate: () => Promise<void>;
  setView: (view: View) => void;
  setTab: (tab: MainTab) => void;
  setWalletCreated: (created: boolean) => void;
  startCreateFlow: () => void;
  setImportMethod: (method: ImportMethod) => void;
  addAccount: (name?: string) => Promise<void>;
  setActiveAccount: (id: string) => Promise<void>;
  renameAccount: (id: string, name: string) => Promise<void>;
  setBiometricsEnabled: (enabled: boolean) => Promise<void>;
  setIsLocked: (locked: boolean) => void;
  refreshPortfolio: (address?: string) => Promise<void>;
  completeDraftCreation: (passcode: string, biometricsEnabled: boolean) => Promise<void>;
  completeImport: (
    secret: string,
    method: ImportMethod,
    passcode: string,
    biometricsEnabled: boolean
  ) => Promise<{ ok: boolean; error?: string }>;
  unlockWallet: (passcode: string) => Promise<boolean>;
  unlockWithBiometrics: () => Promise<boolean>;
}

export const useAppStore = create<AppState>((set, get) => ({
  hydrated: false,
  hydrating: false,
  bootstrap: null,
  bootstrapError: null,
  currentView: 'splash',
  currentTab: 'home',
  walletCreated: false,
  importMethod: 'mnemonic',
  accounts: [],
  activeAccountId: '',
  balance: 0,
  fiatBalance: 0,
  portfolio: null,
  portfolioError: null,
  portfolioRefreshing: false,
  biometricsEnabled: false,
  isLocked: false,
  unlockError: null,
  draftWallet: null,
  vaultEnvelope: null,
  vaultData: null,
  sessionPasscode: null,

  hydrate: async () => {
    if (get().hydrated || get().hydrating) {
      return;
    }

    set({ hydrating: true, currentView: 'splash' });

    const [bootstrap, envelope] = await Promise.all([
      fetchWalletBootstrap().catch(() => null),
      loadJson<PersistedVaultEnvelope>(VAULT_STORAGE_KEY),
      wait(900),
    ]).then(([loadedBootstrap, loadedEnvelope]) => [loadedBootstrap, loadedEnvelope] as const);

    if (envelope) {
      set({
        hydrated: true,
        hydrating: false,
        bootstrap,
        bootstrapError: bootstrap ? null : 'Wallet bootstrap unavailable',
        walletCreated: true,
        biometricsEnabled: envelope.biometricsEnabled,
        isLocked: true,
        currentView: 'main',
        vaultEnvelope: envelope,
        accounts: [],
        activeAccountId: '',
        portfolio: null,
        portfolioError: null,
        portfolioRefreshing: false,
        balance: 0,
        fiatBalance: 0,
      });
      return;
    }

    set({
      hydrated: true,
      hydrating: false,
      bootstrap,
      bootstrapError: bootstrap ? null : 'Wallet bootstrap unavailable',
      walletCreated: false,
      biometricsEnabled: false,
      isLocked: false,
      currentView: 'welcome',
      accounts: [],
      activeAccountId: '',
      portfolio: null,
      portfolioError: null,
      portfolioRefreshing: false,
      balance: 0,
      fiatBalance: 0,
    });
  },

  setView: (view) => set({ currentView: view }),
  setTab: (tab) => set({ currentTab: tab }),
  setWalletCreated: (created) => set({ walletCreated: created }),

  startCreateFlow: () => {
    set({
      draftWallet: createMnemonicDraft(),
      importMethod: 'mnemonic',
      currentView: 'create-wallet',
      unlockError: null,
    });
  },

  setImportMethod: (method) => set({ importMethod: method }),

  addAccount: async (name) => {
    const { vaultData, sessionPasscode, biometricsEnabled } = get();
    if (!vaultData || !sessionPasscode) {
      return;
    }

    const updatedVault =
      vaultData.source === 'mnemonic'
        ? addDerivedMnemonicAccount(vaultData, name?.trim() || `Wallet ${vaultData.accounts.length + 1}`)
        : vaultData;

    const envelope = await reencryptVault(updatedVault, sessionPasscode, biometricsEnabled);
    await saveJson(VAULT_STORAGE_KEY, envelope);

    set({
      vaultEnvelope: envelope,
      vaultData: updatedVault,
      ...applyUnlockedVault(updatedVault),
    });

    void get().refreshPortfolio();
  },

  setActiveAccount: async (id) => {
    const { vaultData, sessionPasscode, biometricsEnabled } = get();
    if (!vaultData || !sessionPasscode) {
      set({ activeAccountId: id });
      return;
    }

    const updatedVault = setVaultActiveAccount(vaultData, id);
    const envelope = await reencryptVault(updatedVault, sessionPasscode, biometricsEnabled);
    await saveJson(VAULT_STORAGE_KEY, envelope);

    set({
      vaultEnvelope: envelope,
      vaultData: updatedVault,
      activeAccountId: id,
    });

    void get().refreshPortfolio(updatedVault.accounts.find((account) => account.id === id)?.address);
  },

  renameAccount: async (id, name) => {
    const trimmed = name.trim();
    if (!trimmed) {
      return;
    }

    const { vaultData, sessionPasscode, biometricsEnabled } = get();
    if (!vaultData || !sessionPasscode) {
      set((state) => ({
        accounts: state.accounts.map((account) =>
          account.id === id ? { ...account, name: trimmed } : account
        ),
      }));
      return;
    }

    const updatedVault = renameVaultAccount(vaultData, id, trimmed);
    const envelope = await reencryptVault(updatedVault, sessionPasscode, biometricsEnabled);
    await saveJson(VAULT_STORAGE_KEY, envelope);

    set({
      vaultEnvelope: envelope,
      vaultData: updatedVault,
      accounts: updatedVault.accounts,
    });
  },

  setBiometricsEnabled: async (enabled) => {
    const envelope = get().vaultEnvelope;
    if (!envelope) {
      set({ biometricsEnabled: enabled });
      return;
    }

    const updatedEnvelope = {
      ...envelope,
      biometricsEnabled: enabled,
    };
    await saveJson(VAULT_STORAGE_KEY, updatedEnvelope);
    set({ biometricsEnabled: enabled, vaultEnvelope: updatedEnvelope });
  },

  setIsLocked: (locked) => {
    if (!locked) {
      set({ isLocked: false, unlockError: null });
      return;
    }

    set({
      isLocked: true,
      unlockError: null,
      vaultData: null,
      portfolio: null,
      portfolioError: null,
      portfolioRefreshing: false,
      balance: 0,
      fiatBalance: 0,
      currentView: 'main',
    });
  },

  refreshPortfolio: async (address) => {
    const activeAddress =
      address ??
      get().accounts.find((account) => account.id === get().activeAccountId)?.address ??
      get().vaultData?.accounts.find((account) => account.id === get().vaultData?.activeAccountId)?.address;

    if (!activeAddress) {
      set({
        portfolio: null,
        portfolioError: null,
        portfolioRefreshing: false,
        balance: 0,
        fiatBalance: 0,
      });
      return;
    }

    set({ portfolioRefreshing: true, portfolioError: null });

    try {
      const portfolio = await fetchWalletPortfolio(activeAddress);
      const defaultChainBalance = Number.parseFloat(portfolio.summary.defaultChainBalance ?? '0');

      set({
        portfolio,
        portfolioError: null,
        portfolioRefreshing: false,
        balance: Number.isFinite(defaultChainBalance) ? defaultChainBalance : 0,
        fiatBalance: 0,
      });
    } catch (error) {
      set({
        portfolio: null,
        portfolioRefreshing: false,
        portfolioError: error instanceof Error ? error.message : 'Unable to refresh live balances',
        balance: 0,
        fiatBalance: 0,
      });
    }
  },

  completeDraftCreation: async (passcode, biometricsEnabled) => {
    const draftWallet = get().draftWallet ?? createMnemonicDraft();
    const { envelope, vault } = await persistVault(draftWallet, passcode, biometricsEnabled);
    await saveJson(VAULT_STORAGE_KEY, envelope);

    set({
      walletCreated: true,
      biometricsEnabled,
      vaultEnvelope: envelope,
      vaultData: vault,
      draftWallet: null,
      sessionPasscode: passcode,
      isLocked: false,
      unlockError: null,
      currentView: 'walkthrough',
      ...applyUnlockedVault(vault),
    });

    void get().refreshPortfolio(vault.accounts.find((account) => account.id === vault.activeAccountId)?.address);
  },

  completeImport: async (secret, method, passcode, biometricsEnabled) => {
    try {
      const draft = importWalletDraft(method, secret);
      const { envelope, vault } = await persistVault(draft, passcode, biometricsEnabled);
      await saveJson(VAULT_STORAGE_KEY, envelope);

      set({
        walletCreated: true,
        biometricsEnabled,
        vaultEnvelope: envelope,
        vaultData: vault,
        draftWallet: null,
        importMethod: method,
        sessionPasscode: passcode,
        isLocked: false,
        unlockError: null,
        currentView: 'walkthrough',
        ...applyUnlockedVault(vault),
      });

      void get().refreshPortfolio(vault.accounts.find((account) => account.id === vault.activeAccountId)?.address);

      return { ok: true };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error.message : 'Unable to import wallet',
      };
    }
  },

  unlockWallet: async (passcode) => {
    const envelope = get().vaultEnvelope ?? (await loadJson<PersistedVaultEnvelope>(VAULT_STORAGE_KEY));
    if (!envelope) {
      return false;
    }

    try {
      const vault = await unlockVault(envelope, passcode);
      const updatedEnvelope = {
        ...envelope,
        lastUnlockedAt: new Date().toISOString(),
      };
      await saveJson(VAULT_STORAGE_KEY, updatedEnvelope);
      set({
        vaultEnvelope: updatedEnvelope,
        vaultData: vault,
        sessionPasscode: passcode,
        isLocked: false,
        unlockError: null,
        currentView: 'main',
        walletCreated: true,
        biometricsEnabled: envelope.biometricsEnabled,
        ...applyUnlockedVault(vault),
      });
      void get().refreshPortfolio(vault.accounts.find((account) => account.id === vault.activeAccountId)?.address);
      return true;
    } catch {
      set({ unlockError: 'Incorrect passcode' });
      return false;
    }
  },

  unlockWithBiometrics: async () => {
    const sessionPasscode = get().sessionPasscode;
    if (!sessionPasscode) {
      return false;
    }

    return get().unlockWallet(sessionPasscode);
  },
}));
