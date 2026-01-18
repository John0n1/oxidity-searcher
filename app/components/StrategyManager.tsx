
import React, { useState } from 'react';
import { BrainCircuit, Sparkles, TrendingUp, ShieldCheck, ChevronRight, Loader2 } from 'lucide-react';
import { StrategyStats, LogEntry } from '../types';
import { analyzePerformance } from '../services/geminiService';

interface StrategyManagerProps {
  stats: StrategyStats;
  logs: LogEntry[];
}

const StrategyManager: React.FC<StrategyManagerProps> = ({ stats, logs }) => {
  const [analysis, setAnalysis] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleRunAnalysis = async () => {
    setIsLoading(true);
    const result = await analyzePerformance(stats, logs);
    setAnalysis(result);
    setIsLoading(false);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="p-8 bg-gradient-to-br from-indigo-600/20 via-[#0f0f11] to-[#0f0f11] border border-zinc-800 rounded-[2.5rem] relative overflow-hidden group">
        <div className="absolute top-0 right-0 w-64 h-64 bg-indigo-500/10 blur-[100px] pointer-events-none group-hover:bg-indigo-500/20 transition-all"></div>
        
        <div className="relative z-10">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-3 bg-indigo-500/20 rounded-2xl text-indigo-400">
                <BrainCircuit size={32} />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-white">Gemini Strategy Analyst</h2>
              <p className="text-zinc-500 text-sm">Deep learning analysis of your bot performance and log data.</p>
            </div>
          </div>

          <div className="mt-8 flex gap-4">
            <button 
              onClick={handleRunAnalysis}
              disabled={isLoading}
              className="flex items-center gap-2 px-6 py-3 bg-indigo-600 text-white rounded-full font-bold hover:bg-indigo-500 transition-all shadow-xl shadow-indigo-900/40 disabled:opacity-50"
            >
              {isLoading ? <Loader2 className="animate-spin" size={20} /> : <Sparkles size={20} />}
              {isLoading ? 'Processing Neural Logs...' : 'Analyze Recent Performance'}
            </button>
            <button className="flex items-center gap-2 px-6 py-3 bg-zinc-800 text-zinc-300 rounded-full font-bold hover:bg-zinc-700 transition-all">
                View History
            </button>
          </div>
        </div>
      </div>

      {analysis && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 animate-in fade-in slide-in-from-bottom-4 duration-700">
          <div className="md:col-span-2 p-6 bg-[#0f0f11] border border-zinc-800 rounded-3xl space-y-6">
            <div>
                <h4 className="text-xs font-bold text-zinc-500 uppercase tracking-widest mb-4">Executive Summary</h4>
                <p className="text-zinc-300 leading-relaxed text-sm">{analysis.summary}</p>
            </div>

            <div className="space-y-3">
                <h4 className="text-xs font-bold text-zinc-500 uppercase tracking-widest mb-4">AI Recommendations</h4>
                {analysis.recommendations.map((rec: string, i: number) => (
                    <div key={i} className="flex items-center gap-3 p-4 bg-zinc-900/40 rounded-2xl border border-zinc-800 group hover:border-indigo-500/30 transition-all">
                        <div className="w-6 h-6 rounded-full bg-indigo-500/10 flex items-center justify-center text-indigo-400 shrink-0">
                            <ChevronRight size={14} />
                        </div>
                        <span className="text-sm text-zinc-300">{rec}</span>
                    </div>
                ))}
            </div>
          </div>

          <div className="space-y-6">
            <div className="p-6 bg-[#0f0f11] border border-zinc-800 rounded-3xl">
                <h4 className="text-xs font-bold text-zinc-500 uppercase tracking-widest mb-4">Risk Profile</h4>
                <div className="flex flex-col items-center justify-center py-6">
                    <div className={`text-4xl font-black mb-2 ${
                        analysis.riskLevel === 'Low' ? 'text-green-500' : 
                        analysis.riskLevel === 'Medium' ? 'text-orange-500' : 'text-red-500'
                    }`}>
                        {analysis.riskLevel.toUpperCase()}
                    </div>
                    <p className="text-[10px] text-zinc-600 uppercase font-bold tracking-tighter">Current Threat Environment</p>
                </div>
                <div className="mt-4 pt-4 border-t border-zinc-800 space-y-3">
                    <div className="flex justify-between text-xs">
                        <span className="text-zinc-500">Mempool Poisoning</span>
                        <span className="text-green-500">Safe</span>
                    </div>
                    <div className="flex justify-between text-xs">
                        <span className="text-zinc-500">Toxic Token Prob</span>
                        <span className="text-orange-500">Moderate</span>
                    </div>
                </div>
            </div>

            <div className="p-6 bg-indigo-600 rounded-3xl text-white shadow-xl shadow-indigo-900/20">
                <TrendingUp size={24} className="mb-4" />
                <h4 className="text-lg font-bold mb-1">Profit Boost</h4>
                <p className="text-sm opacity-80 mb-4">The analyst suggests adjusting the slippage for USDC/WETH pairs to 120bps for a predicted 4% profit boost.</p>
                <button className="w-full py-2 bg-white text-indigo-600 rounded-xl text-xs font-bold uppercase tracking-wider hover:bg-indigo-50 transition-colors">
                    Apply Optimization
                </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default StrategyManager;
