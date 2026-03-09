import { useState } from 'react';
import { Globe } from 'lucide-react';
import { cn } from '../utils/cn';
import { getTokenLogoUrl } from '../utils/token';

interface TokenLogoProps {
  logo?: string;
  symbol: string;
  address?: string;
  className?: string;
}

export function TokenLogo({ logo, symbol, address, className }: TokenLogoProps) {
  const [hasError, setHasError] = useState(false);
  
  // Fallback URL based on address if logo is missing or failed
  const fallbackLogo = address ? getTokenLogoUrl(address) : undefined;

  const currentLogo = !hasError ? (logo || fallbackLogo) : undefined;

  return (
    <div className={cn("w-10 h-10 rounded-full bg-zinc-800 flex items-center justify-center overflow-hidden", className)}>
      {currentLogo ? (
        <img 
          src={currentLogo} 
          alt={symbol} 
          className="w-full h-full object-cover"
          loading="lazy"
          decoding="async"
          onError={() => {
            // If the primary logo fails, and it wasn't already the fallback, try the fallback
            // But since we're already trying the fallback, if it fails, we just set error
            setHasError(true);
          }}
          referrerPolicy="no-referrer"
        />
      ) : (
        <div className="w-full h-full bg-indigo-500/20 flex items-center justify-center text-indigo-400 font-bold">
          {symbol ? symbol[0] : <Globe className="w-5 h-5 text-zinc-600" />}
        </div>
      )}
    </div>
  );
}
