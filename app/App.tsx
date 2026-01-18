
import React, { useState, useEffect, useCallback, useRef } from 'react';
import { 
  Activity, 
  Terminal, 
  Settings, 
  Zap, 
  Play, 
  Square, 
  Cpu, 
  Wallet, 
  TrendingUp,
  AlertTriangle,
  RefreshCw,
  Search,
  Filter,
  BrainCircuit,
  Layers
} from 'lucide-react';
import { AppTab, LogLevel, LogEntry, StrategyStats, GlobalConfig, PnLPoint } from './types';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Dashboard from './components/Dashboard';
import Logger from './components/Logger';
import ConfigManager from './components/ConfigManager';
import StrategyManager from './components/StrategyManager';
import Mempool from './components/Mempool';
import { speakAlert } from './services/audioService';

const INITIAL_CONFIG: GlobalConfig = {
  debug: false,
  chains: [1, 10, 42161],
  walletAddress: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  maxGasPriceGwei: 200,
  simulationBackend: 'revm',
  flashloanEnabled: true,
  sandwichAttacksEnabled: true,
  mevShareEnabled: true,
  slippageBps: 50,
  voiceAlerts: true
};

const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<AppTab>(AppTab.DASHBOARD);
  const [isRunning, setIsRunning] = useState(false);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [config, setConfig] = useState<GlobalConfig>(INITIAL_CONFIG);
  const [stats, setStats] = useState<StrategyStats>({
    processed: 0,
    submitted: 0,
    skipped: 0,
    failed: 0,
    successRate: 0,
    grossProfitEth: 0,
    gasSpentEth: 0,
    netProfitEth: 0,
  });
  const [pnlHistory, setPnlHistory] = useState<PnLPoint[]>([]);

  // Simulate real-time data ingestion
  useEffect(() => {
    if (!isRunning) return;

    const interval = setInterval(() => {
      const chance = Math.random();
      const timestamp = new Date().toLocaleTimeString();
      
      if (chance > 0.4) {
        const levels = [LogLevel.DEBUG, LogLevel.INFO, LogLevel.VERBOSE, LogLevel.WARNING];
        const randomLevel = levels[Math.floor(Math.random() * levels.length)];
        const modules = ["Mempool", "Strategy", "Engine", "Network", "Simulator"];
        const randomModule = modules[Math.floor(Math.random() * modules.length)];
        
        const newLog: LogEntry = {
          id: Math.random().toString(36).substr(2, 9),
          timestamp,
          level: randomLevel as LogLevel,
          module: randomModule,
          message: randomLevel === LogLevel.WARNING 
            ? "High gas price detected, skipping non-urgent backrun." 
            : `Processed block ${Math.floor(Math.random() * 1000000)} with ${Math.floor(Math.random() * 200)} txs.`
        };
        
        setLogs(prev => [newLog, ...prev].slice(0, 1000));
        
        setStats(prev => {
          const isSubmitted = Math.random() > 0.85;
          const isFailed = isSubmitted && Math.random() > 0.8;
          
          const newProcessed = prev.processed + 1;
          const newSubmitted = isSubmitted ? prev.submitted + 1 : prev.submitted;
          const newFailed = isFailed ? prev.failed + 1 : prev.failed;
          const profit = isSubmitted && !isFailed ? (Math.random() * 0.05) : 0;
          const gas = isSubmitted ? (Math.random() * 0.01) : 0;

          // Trigger Voice Alert on "Big Win"
          if (config.voiceAlerts && profit > 0.04) {
            speakAlert(`Large arbitrage bundle executed successfully. Net profit: ${profit.toFixed(3)} ether.`);
          }

          return {
            ...prev,
            processed: newProcessed,
            submitted: newSubmitted,
            failed: newFailed,
            skipped: prev.skipped + (isSubmitted ? 0 : 1),
            grossProfitEth: prev.grossProfitEth + profit,
            gasSpentEth: prev.gasSpentEth + gas,
            netProfitEth: (prev.grossProfitEth + profit) - (prev.gasSpentEth + gas),
            successRate: newSubmitted > 0 ? Math.round(((newSubmitted - newFailed) / newSubmitted) * 100) : 0
          };
        });
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [isRunning, config.voiceAlerts]);

  useEffect(() => {
    if (isRunning) {
        const historyInterval = setInterval(() => {
            const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
            // Increase buffer to 200 points for better zooming capability
            setPnlHistory(prev => [...prev.slice(-199), { time: now, pnl: stats.netProfitEth, gas: stats.gasSpentEth }]);
        }, 5000);
        return () => clearInterval(historyInterval);
    }
  }, [isRunning, stats.netProfitEth, stats.gasSpentEth]);

  return (
    <div className="flex h-screen bg-[#0a0a0b] text-zinc-100">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
      
      <main className="flex-1 flex flex-col min-w-0 overflow-hidden relative">
        <Header 
          isRunning={isRunning} 
          setIsRunning={setIsRunning} 
          activeTab={activeTab}
        />
        
        <div className="flex-1 overflow-y-auto p-4 md:p-6 space-y-6">
          {activeTab === AppTab.DASHBOARD && (
            <Dashboard stats={stats} isRunning={isRunning} pnlHistory={pnlHistory} />
          )}

          {activeTab === AppTab.MEMPOOL && (
            <Mempool isRunning={isRunning} />
          )}
          
          {activeTab === AppTab.LOGS && (
            <Logger logs={logs} setLogs={setLogs} />
          )}
          
          {activeTab === AppTab.CONFIG && (
            <ConfigManager config={config} setConfig={setConfig} />
          )}

          {activeTab === AppTab.STRATEGY && (
            <StrategyManager stats={stats} logs={logs} />
          )}
        </div>

        <footer className="h-8 border-t border-zinc-800 bg-zinc-900/50 px-4 flex items-center justify-between text-[11px] font-mono text-zinc-500 shrink-0">
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full ${isRunning ? 'bg-cyan-500 shadow-[0_0_8px_rgba(6,182,212,0.5)]' : 'bg-zinc-700'}`}></span>
              {isRunning ? 'ENGINE_LIVE' : 'ENGINE_OFFLINE'}
            </span>
            <span className="hidden sm:inline">WALLET: {config.walletAddress.slice(0, 6)}...{config.walletAddress.slice(-4)}</span>
          </div>
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1 text-cyan-400">
              <Cpu size={12} /> {stats.processed} OPS
            </span>
            <span className="flex items-center gap-1 text-green-400">
              <RefreshCw size={12} className={isRunning ? 'animate-spin' : ''} /> SYNC_OK
            </span>
          </div>
        </footer>
      </main>
    </div>
  );
};

export default App;
