import {
  Compass,
  Flame,
  Gem,
  Orbit,
  Rocket,
  Shield,
  Wallet,
  Zap,
  type LucideIcon,
} from 'lucide-react';

import { DEFAULT_WALLET_AVATAR_ID, type WalletAvatarId } from '../lib/walletDefaults';
import { cn } from '../utils/cn';

type WalletAvatarOption = {
  id: WalletAvatarId;
  label: string;
  icon: LucideIcon;
  gradientClassName: string;
};

export const WALLET_AVATAR_OPTIONS: WalletAvatarOption[] = [
  { id: 'orbit', label: 'Orbit', icon: Orbit, gradientClassName: 'from-sky-500 to-blue-700' },
  { id: 'shield', label: 'Shield', icon: Shield, gradientClassName: 'from-emerald-500 to-teal-700' },
  { id: 'vault', label: 'Vault', icon: Wallet, gradientClassName: 'from-indigo-500 to-violet-700' },
  { id: 'flame', label: 'Flame', icon: Flame, gradientClassName: 'from-orange-500 to-rose-700' },
  { id: 'compass', label: 'Compass', icon: Compass, gradientClassName: 'from-cyan-500 to-sky-700' },
  { id: 'gem', label: 'Gem', icon: Gem, gradientClassName: 'from-fuchsia-500 to-pink-700' },
  { id: 'rocket', label: 'Rocket', icon: Rocket, gradientClassName: 'from-amber-500 to-orange-700' },
  { id: 'zap', label: 'Zap', icon: Zap, gradientClassName: 'from-blue-500 to-indigo-700' },
];

export function getWalletAvatarOption(avatarId?: string | null): WalletAvatarOption {
  return (
    WALLET_AVATAR_OPTIONS.find((option) => option.id === avatarId)
    || WALLET_AVATAR_OPTIONS.find((option) => option.id === DEFAULT_WALLET_AVATAR_ID)
    || WALLET_AVATAR_OPTIONS[0]
  );
}

interface WalletAvatarProps {
  avatarId?: string | null;
  className?: string;
  iconClassName?: string;
}

export function WalletAvatar({ avatarId, className, iconClassName }: WalletAvatarProps) {
  const option = getWalletAvatarOption(avatarId);
  const Icon = option.icon;

  return (
    <div
      className={cn(
        'flex items-center justify-center rounded-full bg-gradient-to-br text-white shadow-lg shadow-black/20',
        option.gradientClassName,
        className,
      )}
    >
      <Icon className={cn('h-5 w-5', iconClassName)} strokeWidth={1.9} />
    </div>
  );
}
