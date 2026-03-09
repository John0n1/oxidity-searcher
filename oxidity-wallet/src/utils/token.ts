/**
 * Returns a fallback logo URL for a token based on its contract address.
 * Uses the Trust Wallet assets repository as a primary source.
 * @param address The contract address of the token
 * @returns A URL string for the token logo
 */
export function getTokenLogoUrl(address: string): string {
  if (!address || address === '0x0000...0000' || address.includes('...')) {
    return '';
  }

  // Normalize address (Trust Wallet repo uses checksummed addresses, 
  // but we'll try lowercase first as many services support it or redirect)
  const normalizedAddress = address.toLowerCase();
  
  // Trust Wallet Assets is a very reliable source for Ethereum tokens
  return `https://raw.githubusercontent.com/trustwallet/assets/master/blockchains/ethereum/assets/${address}/logo.png`;
}

/**
 * Attempts to get a logo from multiple sources.
 * Since we can't easily check if an image exists client-side without a fetch,
 * we provide a primary one.
 */
export const TOKEN_LOGO_SOURCES = [
  (addr: string) => `https://raw.githubusercontent.com/trustwallet/assets/master/blockchains/ethereum/assets/${addr}/logo.png`,
  (addr: string) => `https://raw.githubusercontent.com/uniswap/assets/master/blockchains/ethereum/assets/${addr}/logo.png`,
];
