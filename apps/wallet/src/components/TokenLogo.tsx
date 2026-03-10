import { useEffect, useMemo, useState } from 'react';
import { Globe } from 'lucide-react';
import { cn } from '../utils/cn';
import { getTokenLogoCandidates } from '../lib/tokenLogos';

interface TokenLogoProps {
  logo?: string;
  symbol: string;
  address?: string;
  className?: string;
}

export function TokenLogo({ logo, symbol, address, className }: TokenLogoProps) {
  const candidates = useMemo(() => getTokenLogoCandidates({ logo, address }), [logo, address]);
  const [candidateIndex, setCandidateIndex] = useState(0);

  useEffect(() => {
    setCandidateIndex(0);
  }, [candidates]);

  const currentLogo = candidates[candidateIndex];

  return (
    <div className={cn("w-10 h-10 rounded-full bg-zinc-800 flex items-center justify-center overflow-hidden", className)}>
      {currentLogo ? (
        <img 
          src={currentLogo} 
          alt={symbol} 
          className="w-full h-full object-cover"
          loading="eager"
          decoding="async"
          fetchPriority="high"
          onError={() => {
            setCandidateIndex((current) => current + 1);
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
