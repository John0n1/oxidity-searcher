const preloadedLogoUrls = new Set<string>();
const inflightLogoRequests = new Map<string, Promise<void>>();

export interface TokenLogoLike {
  logo?: string;
  address?: string;
}

export function getTrustWalletEthereumLogoUrl(address: string): string {
  if (!address || address.includes('...')) {
    return '';
  }

  return `https://raw.githubusercontent.com/trustwallet/assets/master/blockchains/ethereum/assets/${address}/logo.png`;
}

export function getTokenLogoCandidates(input: TokenLogoLike): string[] {
  const candidates = [input.logo];

  if (input.address && /^0x[a-fA-F0-9]{40}$/.test(input.address)) {
    candidates.push(getTrustWalletEthereumLogoUrl(input.address));
  }

  return candidates.filter((candidate, index, values): candidate is string => {
    if (!candidate) {
      return false;
    }
    return values.indexOf(candidate) === index;
  });
}

export function preloadTokenLogoUrl(url: string): Promise<void> {
  if (!url || preloadedLogoUrls.has(url)) {
    return Promise.resolve();
  }

  const inflight = inflightLogoRequests.get(url);
  if (inflight) {
    return inflight;
  }

  const request = new Promise<void>((resolve) => {
    const image = new Image();
    image.decoding = 'async';
    image.referrerPolicy = 'no-referrer';
    image.onload = () => {
      preloadedLogoUrls.add(url);
      inflightLogoRequests.delete(url);
      resolve();
    };
    image.onerror = () => {
      inflightLogoRequests.delete(url);
      resolve();
    };
    image.src = url;
  });

  inflightLogoRequests.set(url, request);
  return request;
}

export async function preloadTokenLogos(tokens: TokenLogoLike[]): Promise<void> {
  const urls = tokens.flatMap((token) => getTokenLogoCandidates(token));
  await Promise.all(urls.map((url) => preloadTokenLogoUrl(url)));
}
