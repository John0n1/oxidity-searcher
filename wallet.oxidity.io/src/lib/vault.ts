import { HDNodeWallet, Wallet } from 'ethers';
import { decryptJson, encryptJson } from './crypto';
import type {
  Account,
  ImportMethod,
  PersistedVaultEnvelope,
  WalletDraft,
  WalletVaultData,
} from '@/types/wallet';

const VAULT_VERSION = 1;
const HD_PATH_PREFIX = "m/44'/60'/0'/0";

function nowIso(): string {
  return new Date().toISOString();
}

function pathForIndex(index: number): string {
  return `${HD_PATH_PREFIX}/${index}`;
}

function normalizeMnemonic(input: string): string {
  return input
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .join(' ');
}

function normalizePrivateKey(input: string): string {
  const trimmed = input.trim();
  return trimmed.startsWith('0x') ? trimmed : `0x${trimmed}`;
}

function buildAccount(params: {
  name: string;
  address: string;
  derivationIndex: number | null;
  derivationPath: string | null;
}): Account {
  return {
    id: crypto.randomUUID(),
    name: params.name,
    address: params.address,
    balance: 0,
    fiatBalance: 0,
    derivationIndex: params.derivationIndex,
    derivationPath: params.derivationPath,
  };
}

export function createMnemonicDraft(name = 'Main Wallet'): WalletDraft {
  const wallet = Wallet.createRandom();
  const phrase = wallet.mnemonic?.phrase;
  if (!phrase) {
    throw new Error('Failed to generate mnemonic');
  }

  const normalized = normalizeMnemonic(phrase);
  const primary = deriveMnemonicAccount(normalized, 0, name);

  return {
    source: 'mnemonic',
    secret: normalized,
    words: normalized.split(' '),
    primaryAccount: primary,
  };
}

export function importWalletDraft(
  method: ImportMethod,
  secret: string,
  name = 'Main Wallet'
): WalletDraft {
  if (method === 'mnemonic') {
    const normalized = normalizeMnemonic(secret);
    const primary = deriveMnemonicAccount(normalized, 0, name);
    return {
      source: 'mnemonic',
      secret: normalized,
      words: normalized.split(' '),
      primaryAccount: primary,
    };
  }

  const normalized = normalizePrivateKey(secret);
  const wallet = new Wallet(normalized);
  return {
    source: 'private-key',
    secret: normalized,
    words: [],
    primaryAccount: buildAccount({
      name,
      address: wallet.address,
      derivationIndex: null,
      derivationPath: null,
    }),
  };
}

export function deriveMnemonicAccount(
  mnemonic: string,
  index: number,
  name: string
): Account {
  const path = pathForIndex(index);
  const wallet = HDNodeWallet.fromPhrase(mnemonic, undefined, path);
  return buildAccount({
    name,
    address: wallet.address,
    derivationIndex: index,
    derivationPath: path,
  });
}

export async function persistVault(
  draft: WalletDraft,
  passcode: string,
  biometricsEnabled: boolean
): Promise<{ envelope: PersistedVaultEnvelope; vault: WalletVaultData }> {
  const createdAt = nowIso();
  const vault: WalletVaultData = {
    version: VAULT_VERSION,
    source: draft.source,
    secret: draft.secret,
    accounts: [draft.primaryAccount],
    activeAccountId: draft.primaryAccount.id,
    createdAt,
    updatedAt: createdAt,
  };

  const encrypted = await encryptJson(passcode, vault);
  return {
    vault,
    envelope: {
      version: VAULT_VERSION,
      salt: encrypted.salt,
      iv: encrypted.iv,
      ciphertext: encrypted.ciphertext,
      biometricsEnabled,
    },
  };
}

export async function unlockVault(
  envelope: PersistedVaultEnvelope,
  passcode: string
): Promise<WalletVaultData> {
  return decryptJson<WalletVaultData>(passcode, envelope);
}

export async function reencryptVault(
  vault: WalletVaultData,
  passcode: string,
  biometricsEnabled: boolean
): Promise<PersistedVaultEnvelope> {
  const encrypted = await encryptJson(passcode, {
    ...vault,
    updatedAt: nowIso(),
  });

  return {
    version: VAULT_VERSION,
    salt: encrypted.salt,
    iv: encrypted.iv,
    ciphertext: encrypted.ciphertext,
    biometricsEnabled,
    lastUnlockedAt: nowIso(),
  };
}

export function addDerivedMnemonicAccount(vault: WalletVaultData, name: string): WalletVaultData {
  if (vault.source !== 'mnemonic') {
    throw new Error('Additional derived accounts require a mnemonic-backed vault');
  }

  const nextIndex =
    vault.accounts.reduce((max, account) => Math.max(max, account.derivationIndex ?? -1), -1) + 1;
  const nextAccount = deriveMnemonicAccount(vault.secret, nextIndex, name);

  return {
    ...vault,
    accounts: [...vault.accounts, nextAccount],
    activeAccountId: nextAccount.id,
    updatedAt: nowIso(),
  };
}

export function renameVaultAccount(
  vault: WalletVaultData,
  accountId: string,
  name: string
): WalletVaultData {
  return {
    ...vault,
    accounts: vault.accounts.map((account) =>
      account.id === accountId ? { ...account, name } : account
    ),
    updatedAt: nowIso(),
  };
}

export function setVaultActiveAccount(
  vault: WalletVaultData,
  accountId: string
): WalletVaultData {
  return {
    ...vault,
    activeAccountId: accountId,
    updatedAt: nowIso(),
  };
}
