import {
  AndroidBiometryStrength,
  BiometricAuth,
  type CheckBiometryResult,
} from '@aparajita/capacitor-biometric-auth';
import {
  isNativeSecureStoragePlatform,
  secureStorageGetItem,
  secureStorageRemoveItem,
  secureStorageSetItem,
} from './secureStorage';

const PASSCODE_KEY = 'unlock_passcode';

export function isNativeBiometricPlatform(): boolean {
  return isNativeSecureStoragePlatform();
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
  await secureStorageSetItem(PASSCODE_KEY, passcode);
}

export async function removeSavedBiometricPasscode(): Promise<void> {
  if (!isNativeBiometricPlatform()) {
    return;
  }
  await secureStorageRemoveItem(PASSCODE_KEY);
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

  const passcode = await secureStorageGetItem(PASSCODE_KEY);
  return typeof passcode === 'string' && passcode.length > 0 ? passcode : null;
}
