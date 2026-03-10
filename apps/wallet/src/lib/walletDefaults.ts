import type { PersistedTrackedToken } from './walletVault';

export const WALLET_AVATAR_IDS = [
  'orbit',
  'shield',
  'vault',
  'flame',
  'compass',
  'gem',
  'rocket',
  'zap',
] as const;

export type WalletAvatarId = (typeof WALLET_AVATAR_IDS)[number];

export interface NativeAssetDescriptor {
  chainKey: string;
  symbol: string;
  name: string;
  address: string;
  logo?: string;
}

export const DEFAULT_WALLET_AVATAR_ID: WalletAvatarId = WALLET_AVATAR_IDS[0];

const ETH_LOGO_URL = 'https://cryptologos.cc/logos/ethereum-eth-logo.png';
const SOL_LOGO_URL = 'https://cryptologos.cc/logos/solana-sol-logo.png';

const DEFAULT_ETHEREUM_TRACKED_TOKENS: PersistedTrackedToken[] = [
  {
    id: 'ethereum:0xdac17f958d2ee523a2206206994597c13d831ec7',
    chainKey: 'ethereum',
    symbol: 'USDT',
    name: 'Tether USD',
    address: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
    logo: 'https://cryptologos.cc/logos/tether-usdt-logo.png',
  },
  {
    id: 'ethereum:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
    chainKey: 'ethereum',
    symbol: 'USDC',
    name: 'USDC',
    address: '0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
    logo: 'https://cryptologos.cc/logos/usd-coin-usdc-logo.png',
  },
  {
    id: 'ethereum:0x514910771af9ca656af840dff83e8264ecf986ca',
    chainKey: 'ethereum',
    symbol: 'LINK',
    name: 'Chainlink',
    address: '0x514910771AF9Ca656af840dff83E8264EcF986CA',
    logo: 'https://cryptologos.cc/logos/chainlink-link-logo.png',
  },
  {
    id: 'ethereum:0x6b175474e89094c44da98b954eedeac495271d0f',
    chainKey: 'ethereum',
    symbol: 'DAI',
    name: 'DAI',
    address: '0x6B175474E89094C44Da98b954EedeAC495271d0F',
    logo: 'https://cryptologos.cc/logos/multi-collateral-dai-dai-logo.png',
  },
  {
    id: 'ethereum:0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce',
    chainKey: 'ethereum',
    symbol: 'SHIB',
    name: 'Shiba Inu',
    address: '0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE',
    logo: 'https://cryptologos.cc/logos/shiba-inu-shib-logo.png',
  },
  {
    id: 'ethereum:0x6982508145454ce325ddbe47a25d4ec3d2311933',
    chainKey: 'ethereum',
    symbol: 'PEPE',
    name: 'PEPE',
    address: '0x6982508145454Ce325dDbE47a25d4ec3d2311933',
    logo: 'https://cryptologos.cc/logos/pepe-pepe-logo.png',
  },
];

const NATIVE_ASSET_BY_CHAIN: Record<string, NativeAssetDescriptor> = {
  ethereum: {
    chainKey: 'ethereum',
    symbol: 'ETH',
    name: 'Ethereum',
    address: '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE',
    logo: ETH_LOGO_URL,
  },
  bsc: {
    chainKey: 'bsc',
    symbol: 'BNB',
    name: 'BNB Smart Chain',
    address: '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE',
    logo: 'https://cryptologos.cc/logos/bnb-bnb-logo.png',
  },
  polygon: {
    chainKey: 'polygon',
    symbol: 'POL',
    name: 'Polygon',
    address: '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE',
    logo: 'https://cryptologos.cc/logos/polygon-matic-logo.png',
  },
  base: {
    chainKey: 'base',
    symbol: 'ETH',
    name: 'Base',
    address: '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE',
    logo: ETH_LOGO_URL,
  },
  'avalanche-c': {
    chainKey: 'avalanche-c',
    symbol: 'AVAX',
    name: 'Avalanche C-Chain',
    address: '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE',
    logo: 'https://cryptologos.cc/logos/avalanche-avax-logo.png',
  },
  optimism: {
    chainKey: 'optimism',
    symbol: 'ETH',
    name: 'Optimism',
    address: '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE',
    logo: ETH_LOGO_URL,
  },
  arbitrum: {
    chainKey: 'arbitrum',
    symbol: 'ETH',
    name: 'Arbitrum One',
    address: '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE',
    logo: ETH_LOGO_URL,
  },
  pulsechain: {
    chainKey: 'pulsechain',
    symbol: 'PLS',
    name: 'PulseChain',
    address: '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE',
    logo: 'https://cryptologos.cc/logos/pulsechain-pls-logo.png',
  },
  linea: {
    chainKey: 'linea',
    symbol: 'ETH',
    name: 'Linea',
    address: '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE',
    logo: ETH_LOGO_URL,
  },
  unichain: {
    chainKey: 'unichain',
    symbol: 'ETH',
    name: 'Unichain',
    address: '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE',
    logo: ETH_LOGO_URL,
  },
  solana: {
    chainKey: 'solana',
    symbol: 'SOL',
    name: 'Solana',
    address: 'So11111111111111111111111111111111111111112',
    logo: SOL_LOGO_URL,
  },
};

export function cloneDefaultTrackedTokens(): PersistedTrackedToken[] {
  return DEFAULT_ETHEREUM_TRACKED_TOKENS.map((token) => ({ ...token }));
}

export function ensureDefaultTrackedTokens(tokens: PersistedTrackedToken[]): PersistedTrackedToken[] {
  const merged = [...tokens];

  for (const defaultToken of DEFAULT_ETHEREUM_TRACKED_TOKENS) {
    const exists = merged.some(
      (candidate) =>
        candidate.chainKey === defaultToken.chainKey
        && candidate.address.toLowerCase() === defaultToken.address.toLowerCase(),
    );

    if (!exists) {
      merged.push({ ...defaultToken });
    }
  }

  return merged;
}

export function getDefaultWalletAvatarId(index = 0): WalletAvatarId {
  return WALLET_AVATAR_IDS[index % WALLET_AVATAR_IDS.length];
}

export function isWalletAvatarId(value: string | undefined | null): value is WalletAvatarId {
  return Boolean(value) && WALLET_AVATAR_IDS.includes(value as WalletAvatarId);
}

export function getNativeAssetDescriptor(chainKey: string): NativeAssetDescriptor | null {
  return NATIVE_ASSET_BY_CHAIN[chainKey] ? { ...NATIVE_ASSET_BY_CHAIN[chainKey] } : null;
}

export function getBackgroundPreloadTokens(
  chainKey: string,
  customTokens: Array<{ logo?: string; address: string }>,
) {
  const nativeAsset = getNativeAssetDescriptor(chainKey);
  return [
    ...(nativeAsset ? [{ logo: nativeAsset.logo, address: nativeAsset.address }] : []),
    ...customTokens.map((token) => ({ logo: token.logo, address: token.address })),
  ];
}
