
import React from 'react';
import { GlobalConfig } from '../types';
import { Save, AlertCircle, Info, Volume2 } from 'lucide-react';

interface ConfigManagerProps {
  config: GlobalConfig;
  setConfig: (config: GlobalConfig) => void;
}

const ConfigManager: React.FC<ConfigManagerProps> = ({ config, setConfig }) => {
  const handleChange = (field: keyof GlobalConfig, value: any) => {
    setConfig({ ...config, [field]: value });
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-xl font-bold text-white">System Settings</h3>
          <p className="text-sm text-zinc-500">Configure bot identity, network parameters, and risk management.</p>
        </div>
        <button className="flex items-center gap-2 px-5 py-2 bg-zinc-100 text-zinc-900 rounded-full font-bold text-sm hover:bg-white transition-all shadow-xl shadow-zinc-900/20">
          <Save size={16} /> Save Changes
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-6 bg-[#0f0f11] border border-zinc-800 rounded-3xl space-y-4">
          <div className="flex items-center gap-2 text-white font-bold mb-4">
            <div className="w-2 h-4 bg-orange-500 rounded-full"></div>
            Bot Identity
          </div>
          
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-bold text-zinc-500 uppercase mb-2">Wallet Address</label>
              <input 
                type="text" 
                value={config.walletAddress}
                onChange={(e) => handleChange('walletAddress', e.target.value)}
                className="w-full bg-zinc-900 border border-zinc-800 rounded-xl px-4 py-2.5 text-sm font-mono text-zinc-300 focus:outline-none focus:border-orange-500/50 transition-colors"
              />
            </div>
            <div>
              <label className="block text-xs font-bold text-zinc-500 uppercase mb-2">Simulation Backend</label>
              <select 
                value={config.simulationBackend}
                onChange={(e) => handleChange('simulationBackend', e.target.value)}
                className="w-full bg-zinc-900 border border-zinc-800 rounded-xl px-4 py-2.5 text-sm text-zinc-300 focus:outline-none appearance-none cursor-pointer"
              >
                <option value="revm">REVM (Local In-memory)</option>
                <option value="anvil">Anvil (External Foundry Fork)</option>
              </select>
            </div>
          </div>
        </div>

        <div className="p-6 bg-[#0f0f11] border border-zinc-800 rounded-3xl space-y-4">
          <div className="flex items-center gap-2 text-white font-bold mb-4">
            <div className="w-2 h-4 bg-cyan-500 rounded-full"></div>
            Risk & Network
          </div>

          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-bold text-zinc-500 uppercase mb-2">Gas Cap (Gwei)</label>
                <input 
                  type="number" 
                  value={config.maxGasPriceGwei}
                  onChange={(e) => handleChange('maxGasPriceGwei', Number(e.target.value))}
                  className="w-full bg-zinc-900 border border-zinc-800 rounded-xl px-4 py-2.5 text-sm text-zinc-300"
                />
              </div>
              <div>
                <label className="block text-xs font-bold text-zinc-500 uppercase mb-2">Slippage (Bps)</label>
                <input 
                  type="number" 
                  value={config.slippageBps}
                  onChange={(e) => handleChange('slippageBps', Number(e.target.value))}
                  className="w-full bg-zinc-900 border border-zinc-800 rounded-xl px-4 py-2.5 text-sm text-zinc-300"
                />
              </div>
            </div>

            <div className="p-4 bg-zinc-900/50 rounded-2xl border border-dashed border-zinc-800 flex items-start gap-3">
              <Info className="text-zinc-500 shrink-0" size={16} />
              <p className="text-[10px] text-zinc-500 italic leading-relaxed">
                Max gas price limits will automatically skip bundles if the block base fee exceeds threshold.
              </p>
            </div>
          </div>
        </div>

        <div className="md:col-span-2 p-6 bg-[#0f0f11] border border-zinc-800 rounded-3xl">
          <div className="flex items-center gap-2 text-white font-bold mb-6">
            <div className="w-2 h-4 bg-green-500 rounded-full"></div>
            Active Strategy Modules & Feedback
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
            {[
              { id: 'flashloanEnabled', label: 'Flashloan Engine', desc: 'Use Uniswap/Balancer flashloans' },
              { id: 'sandwichAttacksEnabled', label: 'Sandwich Logic', desc: 'Wrap user swaps with front/back runs' },
              { id: 'mevShareEnabled', label: 'MEV-Share Stream', desc: 'Listen to private mempool hints' },
              { id: 'voiceAlerts', label: 'Gemini Voice Alerts', desc: 'AI-generated audio notifications for high-profit trades', icon: Volume2 },
            ].map((feature) => (
              <div key={feature.id} className="p-4 bg-zinc-900/30 rounded-2xl border border-zinc-800 flex flex-col justify-between group">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    {feature.icon && <feature.icon size={14} className="text-orange-400" />}
                    <span className="text-sm font-bold text-zinc-200">{feature.label}</span>
                  </div>
                  <button 
                    onClick={() => handleChange(feature.id as any, !config[feature.id as keyof GlobalConfig])}
                    className={`relative w-9 h-5 rounded-full transition-colors ${config[feature.id as keyof GlobalConfig] ? 'bg-orange-500' : 'bg-zinc-800'}`}
                  >
                    <div className={`absolute top-1 w-3 h-3 bg-white rounded-full transition-transform ${config[feature.id as keyof GlobalConfig] ? 'translate-x-5' : 'translate-x-1'}`}></div>
                  </button>
                </div>
                <p className="text-[10px] text-zinc-500 leading-tight">{feature.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ConfigManager;
