import { Capacitor } from '@capacitor/core';
import {
  AndroidBiometryStrength,
  BiometricAuth,
  type CheckBiometryResult,
} from '@aparajita/capacitor-biometric-auth';
import { SecureStorage } from '@aparajita/capacitor-secure-storage';

const PREFIX = 'oxidity_wallet_';
const PASSCODE_KEY = 'unlock_passcode';

let prefixReady = false;

async function ensurePrefix(): Promise<void> {
  if (prefixReady) {
    return;
  }
  await SecureStorage.setKeyPrefix(PREFIX);
  prefixReady = true;
}

export function isNativeBiometricPlatform(): boolean {
  return Capacitor.isNativePlatform();
}

export async function checkBiometrics(): Promise<CheckBiometryResult | null> {
  if (!isNativeBiometricPlatform()) {
    return null;
  }
  try {
    return await BiometricAuth.checkBiometry();
  } catch {
    return null;
  }
}

export async function savePasscodeForBiometrics(passcode: string): Promise<void> {
  if (!isNativeBiometricPlatform()) {
    return;
  }
  await ensurePrefix();
  await SecureStorage.setItem(PASSCODE_KEY, passcode);
}

export async function removeSavedBiometricPasscode(): Promise<void> {
  if (!isNativeBiometricPlatform()) {
    return;
  }
  await ensurePrefix();
  await SecureStorage.removeItem(PASSCODE_KEY);
}

export async function unlockWithBiometrics(): Promise<string | null> {
  if (!isNativeBiometricPlatform()) {
    return null;
  }

  const info = await checkBiometrics();
  if (!info || (!info.isAvailable && !info.deviceIsSecure)) {
    return null;
  }

  await BiometricAuth.authenticate({
    reason: 'Unlock Oxidity Wallet',
    cancelTitle: 'Cancel',
    allowDeviceCredential: true,
    androidTitle: 'Unlock Oxidity Wallet',
    androidSubtitle: 'Use fingerprint or device credentials',
    androidConfirmationRequired: false,
    androidBiometryStrength: AndroidBiometryStrength.strong,
  });

  await ensurePrefix();
  const passcode = await SecureStorage.getItem(PASSCODE_KEY);
  return typeof passcode === 'string' && passcode.length > 0 ? passcode : null;
}
