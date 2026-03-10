import { Capacitor } from '@capacitor/core';
import {
  KeychainAccess,
  SecureStorage,
} from '@aparajita/capacitor-secure-storage';

const PREFIX = 'oxidity_wallet_';

let storageReady = false;

export function isNativeSecureStoragePlatform(): boolean {
  return Capacitor.isNativePlatform();
}

export async function ensureSecureStorageReady(): Promise<void> {
  if (!isNativeSecureStoragePlatform() || storageReady) {
    return;
  }

  await SecureStorage.setKeyPrefix(PREFIX);
  await SecureStorage.setDefaultKeychainAccess(KeychainAccess.whenUnlockedThisDeviceOnly);
  storageReady = true;
}

export async function secureStorageGetItem(key: string): Promise<string | null> {
  if (!isNativeSecureStoragePlatform()) {
    return null;
  }

  await ensureSecureStorageReady();
  return SecureStorage.getItem(key);
}

export async function secureStorageSetItem(key: string, value: string): Promise<void> {
  if (!isNativeSecureStoragePlatform()) {
    return;
  }

  await ensureSecureStorageReady();
  await SecureStorage.setItem(key, value);
}

export async function secureStorageRemoveItem(key: string): Promise<void> {
  if (!isNativeSecureStoragePlatform()) {
    return;
  }

  await ensureSecureStorageReady();
  await SecureStorage.removeItem(key);
}
