import {
  HDNodeWallet,
  Mnemonic,
  Wallet,
  encodeBase58,
  getAddress,
  getBytes,
  getIndexedAccountPath,
} from 'ethers';
import { ed25519 } from '@noble/curves/ed25519';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha512';

import type { SecretType } from './walletVault';

export const EVM_CHAIN_KEYS = [
  'ethereum',
  'bsc',
  'polygon',
  'base',
  'avalanche-c',
  'optimism',
  'arbitrum',
  'pulsechain',
  'linea',
  'unichain',
] as const;

export type ChainAddressMap = Record<string, string>;

const SOLANA_PATH_SUFFIX = "/0'";

function buildMnemonicWallet(phrase: string, index: number): HDNodeWallet {
  return HDNodeWallet.fromPhrase(phrase.trim(), undefined, getIndexedAccountPath(index));
}

function expandEvmAddresses(address: string): ChainAddressMap {
  const normalized = getAddress(address);
  return Object.fromEntries(EVM_CHAIN_KEYS.map((chainKey) => [chainKey, normalized]));
}

function deriveEd25519PrivateKey(seed: Uint8Array, path: string): Uint8Array {
  const segments = path
    .split('/')
    .slice(1)
    .map((segment) => {
      if (!segment.endsWith("'")) {
        throw new Error(`Unsupported non-hardened derivation segment in ${path}`);
      }
      const value = Number(segment.slice(0, -1));
      if (!Number.isInteger(value) || value < 0) {
        throw new Error(`Invalid derivation segment in ${path}`);
      }
      return value + 0x8000_0000;
    });

  let digest = hmac(sha512, new TextEncoder().encode('ed25519 seed'), seed);
  let privateKey = digest.slice(0, 32);
  let chainCode = digest.slice(32);

  for (const segment of segments) {
    const index = new Uint8Array(4);
    new DataView(index.buffer).setUint32(0, segment, false);
    const data = new Uint8Array(1 + privateKey.length + index.length);
    data[0] = 0;
    data.set(privateKey, 1);
    data.set(index, 1 + privateKey.length);
    digest = hmac(sha512, chainCode, data);
    privateKey = digest.slice(0, 32);
    chainCode = digest.slice(32);
  }

  return privateKey;
}

export function deriveSolanaPrivateKeyFromMnemonic(phrase: string, derivationIndex: number): Uint8Array {
  const mnemonic = Mnemonic.fromPhrase(phrase.trim());
  const seed = getBytes(mnemonic.computeSeed());
  return deriveEd25519PrivateKey(seed, `m/44'/501'/${derivationIndex}'${SOLANA_PATH_SUFFIX}`);
}

export function deriveSolanaAddressFromMnemonic(phrase: string, derivationIndex: number): string {
  const privateKey = deriveSolanaPrivateKeyFromMnemonic(phrase, derivationIndex);
  const publicKey = ed25519.getPublicKey(privateKey);
  return encodeBase58(publicKey);
}

export function deriveChainAddresses(input: {
  secret: string;
  secretType: SecretType;
  derivationIndex: number;
}): ChainAddressMap {
  const trimmedSecret = input.secret.trim();
  const addressMap: ChainAddressMap = {};

  const evmAddress =
    input.secretType === 'mnemonic'
      ? buildMnemonicWallet(trimmedSecret, input.derivationIndex).address
      : new Wallet(trimmedSecret).address;
  Object.assign(addressMap, expandEvmAddresses(evmAddress));

  if (input.secretType === 'mnemonic') {
    addressMap.solana = deriveSolanaAddressFromMnemonic(trimmedSecret, input.derivationIndex);
  }

  return addressMap;
}

export function legacyAddressMap(address: string): ChainAddressMap {
  return expandEvmAddresses(address);
}

export function resolveAccountAddress(
  account: { address: string; addresses?: ChainAddressMap },
  chainKey: string,
): string {
  return account.addresses?.[chainKey] || account.address;
}

export function supportsChainAddress(
  account: { address: string; addresses?: ChainAddressMap },
  chainKey: string,
): boolean {
  return Boolean(account.addresses?.[chainKey] || (EVM_CHAIN_KEYS as readonly string[]).includes(chainKey));
}
