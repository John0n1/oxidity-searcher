import { HDNodeWallet, Mnemonic, Wallet, getAddress, getIndexedAccountPath } from 'ethers';
import {
  deriveChainAddresses,
  legacyAddressMap,
  resolveAccountAddress,
  type ChainAddressMap,
} from './chainAddresses';

export type SecretType = 'mnemonic' | 'privateKey';

export interface PersistedWalletAccount {
  id: string;
  name: string;
  address: string;
  addresses: ChainAddressMap;
  secretType: SecretType;
  derivationIndex: number;
  encryptedSecret: string;
  salt: string;
  iv: string;
  createdAt: number;
}

export interface PersistedAddressBookEntry {
  id: string;
  name: string;
  address: string;
  chainKey: string;
}

export interface PersistedTrackedToken {
  id: string;
  chainKey: string;
  symbol: string;
  name: string;
  address: string;
  logo?: string;
}

export interface PersistedVault {
  version: number;
  walletCreated: boolean;
  activeAccountId: string | null;
  activeChainKey: string;
  accounts: PersistedWalletAccount[];
  addressBook: PersistedAddressBookEntry[];
  biometricsEnabled: boolean;
  isSubscribed: boolean;
  firstMessageTimestamp: number | null;
  customTokens: PersistedTrackedToken[];
}

export interface CreatedWalletResult {
  vault: PersistedVault;
  account: PersistedWalletAccount;
  mnemonic: string;
  privateKey: string;
}

export interface ImportedWalletResult {
  vault: PersistedVault;
  account: PersistedWalletAccount;
  privateKey: string;
}

const VAULT_STORAGE_KEY = 'oxidity_wallet_vault_v2';
const DEFAULT_CHAIN_KEY = 'ethereum';
const PBKDF2_ITERATIONS = 250_000;

function randomId(): string {
  return crypto.randomUUID();
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  bytes.forEach((value) => {
    binary += String.fromCharCode(value);
  });
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function deriveKey(passcode: string, salt: Uint8Array): Promise<CryptoKey> {
  const normalizedSalt = Uint8Array.from(salt);
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passcode),
    'PBKDF2',
    false,
    ['deriveKey'],
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: normalizedSalt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function encryptSecret(
  secret: string,
  passcode: string,
): Promise<{ encryptedSecret: string; salt: string; iv: string }> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passcode, salt);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(secret),
  );

  return {
    encryptedSecret: toBase64(new Uint8Array(encrypted)),
    salt: toBase64(salt),
    iv: toBase64(iv),
  };
}

export async function decryptSecret(
  account: Pick<PersistedWalletAccount, 'encryptedSecret' | 'salt' | 'iv'>,
  passcode: string,
): Promise<string> {
  const salt = fromBase64(account.salt);
  const iv = Uint8Array.from(fromBase64(account.iv));
  const encrypted = Uint8Array.from(fromBase64(account.encryptedSecret));
  const key = await deriveKey(passcode, salt);
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    encrypted,
  );
  return new TextDecoder().decode(decrypted);
}

function emptyVault(): PersistedVault {
  return {
    version: 2,
    walletCreated: false,
    activeAccountId: null,
    activeChainKey: DEFAULT_CHAIN_KEY,
    accounts: [],
    addressBook: [],
    biometricsEnabled: false,
    isSubscribed: false,
    firstMessageTimestamp: null,
    customTokens: [],
  };
}

export function loadVault(): PersistedVault {
  const raw = localStorage.getItem(VAULT_STORAGE_KEY);
  if (!raw) {
    return emptyVault();
  }

  try {
    const parsed = JSON.parse(raw) as PersistedVault;
    return {
      ...emptyVault(),
      ...parsed,
      accounts: (parsed.accounts || []).map((account) => ({
        ...account,
        address: getAddress(account.address),
        addresses: account.addresses || legacyAddressMap(account.address),
      })),
      addressBook: (parsed.addressBook || []).map((entry) => ({
        ...entry,
        chainKey: entry.chainKey || DEFAULT_CHAIN_KEY,
      })),
      customTokens: parsed.customTokens || [],
    };
  } catch {
    return emptyVault();
  }
}

export function saveVault(vault: PersistedVault): void {
  localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify(vault));
}

function normalizePrivateKey(value: string): string {
  const trimmed = value.trim();
  const prefixed = trimmed.startsWith('0x') ? trimmed : `0x${trimmed}`;
  if (!/^0x[0-9a-fA-F]{64}$/.test(prefixed)) {
    throw new Error('Private key must be a 64-character hex string');
  }
  return prefixed;
}

function buildMnemonicWallet(phrase: string, index: number): HDNodeWallet {
  return HDNodeWallet.fromPhrase(phrase.trim(), undefined, getIndexedAccountPath(index));
}

function newPersistedAccount(input: {
  name: string;
  address: string;
  addresses: ChainAddressMap;
  secretType: SecretType;
  derivationIndex: number;
  encryptedSecret: string;
  salt: string;
  iv: string;
}): PersistedWalletAccount {
  return {
    id: randomId(),
    name: input.name,
    address: getAddress(input.address),
    addresses: input.addresses,
    secretType: input.secretType,
    derivationIndex: input.derivationIndex,
    encryptedSecret: input.encryptedSecret,
    salt: input.salt,
    iv: input.iv,
    createdAt: Date.now(),
  };
}

export async function createWallet(passcode: string, name = 'Main Wallet'): Promise<CreatedWalletResult> {
  const wallet = HDNodeWallet.createRandom();
  const phrase = wallet.mnemonic?.phrase;
  if (!phrase) {
    throw new Error('Failed to generate recovery phrase');
  }

  const encryption = await encryptSecret(phrase, passcode);
  const account = newPersistedAccount({
    name,
    address: wallet.address,
    addresses: deriveChainAddresses({
      secret: phrase,
      secretType: 'mnemonic',
      derivationIndex: 0,
    }),
    secretType: 'mnemonic',
    derivationIndex: 0,
    ...encryption,
  });

  const vault = emptyVault();
  vault.walletCreated = true;
  vault.activeAccountId = account.id;
  vault.accounts = [account];

  return {
    vault,
    account,
    mnemonic: phrase,
    privateKey: wallet.privateKey,
  };
}

export async function importWallet(input: {
  passcode: string;
  secret: string;
  importType: SecretType;
  name?: string;
}): Promise<ImportedWalletResult> {
  let accountAddress = '';
  let privateKey = '';
  let derivationIndex = 0;
  let normalizedSecret = input.secret.trim();

  if (input.importType === 'mnemonic') {
    if (!Mnemonic.isValidMnemonic(normalizedSecret)) {
      throw new Error('Recovery phrase is invalid');
    }
    const wallet = buildMnemonicWallet(normalizedSecret, 0);
    accountAddress = wallet.address;
    privateKey = wallet.privateKey;
  } else {
    normalizedSecret = normalizePrivateKey(normalizedSecret);
    const wallet = new Wallet(normalizedSecret);
    accountAddress = wallet.address;
    privateKey = wallet.privateKey;
    derivationIndex = 0;
  }

  const encryption = await encryptSecret(normalizedSecret, input.passcode);
  const account = newPersistedAccount({
    name: input.name || 'Main Wallet',
    address: accountAddress,
    addresses: deriveChainAddresses({
      secret: normalizedSecret,
      secretType: input.importType,
      derivationIndex,
    }),
    secretType: input.importType,
    derivationIndex,
    ...encryption,
  });

  const vault = emptyVault();
  vault.walletCreated = true;
  vault.activeAccountId = account.id;
  vault.accounts = [account];

  return {
    vault,
    account,
    privateKey,
  };
}

export async function exportPrivateKey(
  account: PersistedWalletAccount,
  passcode: string,
): Promise<string> {
  const secret = await decryptSecret(account, passcode);
  if (account.secretType === 'mnemonic') {
    return buildMnemonicWallet(secret, account.derivationIndex).privateKey;
  }
  return normalizePrivateKey(secret);
}

export async function exportRecoveryPhrase(
  account: PersistedWalletAccount,
  passcode: string,
): Promise<string> {
  if (account.secretType !== 'mnemonic') {
    throw new Error('Recovery phrase export is only available for mnemonic wallets');
  }
  return decryptSecret(account, passcode);
}

export async function verifyPasscode(
  accounts: PersistedWalletAccount[],
  passcode: string,
): Promise<boolean> {
  if (accounts.length === 0) {
    return false;
  }

  try {
    await decryptSecret(accounts[0], passcode);
    return true;
  } catch {
    return false;
  }
}

export async function addAccountFromVault(
  vault: PersistedVault,
  passcode: string,
  name: string,
): Promise<{ vault: PersistedVault; account: PersistedWalletAccount }> {
  const mnemonicAccounts = vault.accounts.filter((account) => account.secretType === 'mnemonic');
  const sourceAccount = mnemonicAccounts[0] || vault.accounts[0];
  if (!sourceAccount) {
    throw new Error('No wallet available to derive from');
  }

  let account: PersistedWalletAccount;
  if (sourceAccount.secretType === 'mnemonic') {
    const phrase = await decryptSecret(sourceAccount, passcode);
    const nextIndex =
      Math.max(
        -1,
        ...mnemonicAccounts.map((existingAccount) => existingAccount.derivationIndex),
      ) + 1;
    const wallet = buildMnemonicWallet(phrase, nextIndex);
    const encryption = await encryptSecret(phrase, passcode);
    account = newPersistedAccount({
      name,
      address: wallet.address,
      addresses: deriveChainAddresses({
        secret: phrase,
        secretType: 'mnemonic',
        derivationIndex: nextIndex,
      }),
      secretType: 'mnemonic',
      derivationIndex: nextIndex,
      ...encryption,
    });
  } else {
    const wallet = Wallet.createRandom();
    const encryption = await encryptSecret(wallet.privateKey, passcode);
    account = newPersistedAccount({
      name,
      address: wallet.address,
      addresses: deriveChainAddresses({
        secret: wallet.privateKey,
        secretType: 'privateKey',
        derivationIndex: 0,
      }),
      secretType: 'privateKey',
      derivationIndex: 0,
      ...encryption,
    });
  }

  const nextVault: PersistedVault = {
    ...vault,
    activeAccountId: account.id,
    accounts: [...vault.accounts, account],
  };
  return { vault: nextVault, account };
}

export async function getAccountPrivateKeyFromVault(
  vault: PersistedVault,
  accountId: string,
  passcode: string,
): Promise<string> {
  const account = vault.accounts.find((candidate) => candidate.id === accountId);
  if (!account) {
    throw new Error('Account not found');
  }
  return exportPrivateKey(account, passcode);
}

export async function reencryptVaultSecrets(
  vault: PersistedVault,
  currentPasscode: string,
  nextPasscode: string,
): Promise<PersistedVault> {
  if (!/^\d{6}$/.test(nextPasscode)) {
    throw new Error('New passcode must be 6 digits');
  }

  const accounts = await Promise.all(
    vault.accounts.map(async (account) => {
      const secret = await decryptSecret(account, currentPasscode);
      const encryption = await encryptSecret(secret, nextPasscode);
      return {
        ...account,
        ...encryption,
      };
    }),
  );

  return {
    ...vault,
    accounts,
  };
}

export function clearVault(): void {
  localStorage.removeItem(VAULT_STORAGE_KEY);
}

export async function hydrateVaultChainAddresses(
  vault: PersistedVault,
  passcode: string,
): Promise<PersistedVault> {
  let hasChanges = false;

  const accounts = await Promise.all(
    vault.accounts.map(async (account) => {
      const currentAddress = resolveAccountAddress(account, 'ethereum');
      const needsSolanaBackfill = account.secretType === 'mnemonic' && !account.addresses?.solana;
      if (account.addresses && !needsSolanaBackfill) {
        return account;
      }

      const secret = await decryptSecret(account, passcode);
      const addresses = deriveChainAddresses({
        secret,
        secretType: account.secretType,
        derivationIndex: account.derivationIndex,
      });
      hasChanges = true;
      return {
        ...account,
        address: currentAddress || account.address,
        addresses,
      };
    }),
  );

  if (!hasChanges) {
    return vault;
  }

  return {
    ...vault,
    accounts,
  };
}
