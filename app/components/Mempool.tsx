
import React, { useState, useEffect } from 'react';
import { MempoolEntry } from '../types';
import { Layers, Zap, Hexagon } from 'lucide-react';

const Mempool: React.FC<{ isRunning: boolean }> = ({ isRunning }) => {
  const [entries, setEntries] = useState<MempoolEntry[]>([]);

  useEffect(() => {
    if (!isRunning) return;

    const interval = setInterval(() => {
      const types: Array<'Arbitrage' | 'Sandwich' | 'Liquid' | 'None'> = ['Arbitrage', 'Sandwich', 'Liquid', 'None'];
      const type = types[Math.floor(Math.random() * types.length)];
      const potential = type === 'None' ? 0 : Math.random() * 0.2;

      const newEntry: MempoolEntry = {
        hash: '0x' + Array.from({length: 40}, () => Math.floor(Math.random() * 16).toString(16)).join(''),
        from: '0x' + Array.from({length: 40}, () => Math.floor(Math.random() * 16).toString(16)).join(''),
        to: '0x' + Array.from({length: 40}, () => Math.floor(Math.random() * 16).toString(16)).join(''),
        value: (Math.random() * 10).toFixed(2),
        gasPrice: (Math.random() * 50 + 10).toFixed(1),
        mevType: type,
        potential: potential
      };

      setEntries(prev => [newEntry, ...prev].slice(0, 50));
    }, 400);

    return () => clearInterval(interval);
  }, [isRunning]);

  return (
    <div className="flex flex-col h-full bg-[#0f0f11] border border-zinc-800 rounded-3xl overflow-hidden">
      <div className="p-4 border-b border-zinc-800 bg-zinc-900/20 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Layers className="text-orange-500" size={18} />
          <h3 className="text-sm font-bold text-white uppercase tracking-wider">Mempool Stream</h3>
        </div>
        <div className="flex items-center gap-4 text-[10px] font-mono text-zinc-500">
            <span>TPS: ~4.2k</span>
            <span className="flex items-center gap-1"><div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse"></div> FEED_ACTIVE</span>
        </div>
      </div>
      
      <div className="flex-1 overflow-y-auto font-mono text-[11px]">
        <table className="w-full text-left border-collapse">
          <thead className="sticky top-0 bg-zinc-900 text-zinc-500 z-10">
            <tr>
              <th className="p-3 border-b border-zinc-800 font-medium">TX HASH</th>
              <th className="p-3 border-b border-zinc-800 font-medium">TYPE</th>
              <th className="p-3 border-b border-zinc-800 font-medium text-right">POTENTIAL</th>
              <th className="p-3 border-b border-zinc-800 font-medium text-right">GAS</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry, idx) => (
              <tr key={entry.hash} className={`group hover:bg-white/5 transition-colors ${idx === 0 ? 'bg-orange-500/5' : ''}`}>
                <td className="p-3 border-b border-zinc-800/50">
                  <div className="flex items-center gap-2">
                    <Hexagon size={12} className="text-zinc-600 group-hover:text-zinc-400" />
                    <span className="text-zinc-400">{entry.hash.slice(0, 14)}...</span>
                  </div>
                </td>
                <td className="p-3 border-b border-zinc-800/50">
                  <span className={`px-2 py-0.5 rounded-full text-[9px] font-bold ${
                    entry.mevType === 'Sandwich' ? 'bg-purple-500/10 text-purple-400' :
                    entry.mevType === 'Arbitrage' ? 'bg-cyan-500/10 text-cyan-400' :
                    entry.mevType === 'Liquid' ? 'bg-yellow-500/10 text-yellow-400' :
                    'text-zinc-600'
                  }`}>
                    {entry.mevType}
                  </span>
                </td>
                <td className="p-3 border-b border-zinc-800/50 text-right">
                  <span className={entry.potential > 0 ? 'text-green-400 font-bold' : 'text-zinc-600'}>
                    {entry.potential > 0 ? `+${entry.potential.toFixed(3)} ETH` : '—'}
                  </span>
                </td>
                <td className="p-3 border-b border-zinc-800/50 text-right text-zinc-500">
                  {entry.gasPrice} Gwei
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Mempool;
