
import React from 'react';
import { 
  Activity, 
  Terminal, 
  Settings, 
  BrainCircuit,
  Box,
  Layers
} from 'lucide-react';
import { AppTab } from '../types';

interface SidebarProps {
  activeTab: AppTab;
  setActiveTab: (tab: AppTab) => void;
}

const Sidebar: React.FC<SidebarProps> = ({ activeTab, setActiveTab }) => {
  const menuItems = [
    { id: AppTab.DASHBOARD, label: 'Dashboard', icon: Activity },
    { id: AppTab.MEMPOOL, label: 'Mempool', icon: Layers },
    { id: AppTab.LOGS, label: 'Real-time Logs', icon: Terminal },
    { id: AppTab.STRATEGY, label: 'AI Strategy', icon: BrainCircuit },
    { id: AppTab.CONFIG, label: 'Configuration', icon: Settings },
  ];

  return (
    <nav className="w-16 md:w-64 border-r border-zinc-800 flex flex-col bg-[#0f0f11] shrink-0">
      <div className="p-6 flex items-center gap-3">
        <div className="w-8 h-8 bg-gradient-to-br from-orange-500 to-red-600 rounded-lg flex items-center justify-center text-white shadow-lg shadow-orange-900/20">
          <Box size={20} />
        </div>
        <div className="hidden md:block">
          <h1 className="font-bold text-sm tracking-tight text-white">OXIDIZED</h1>
          <p className="text-[10px] text-zinc-500 font-mono">BUILDER v2.4.0</p>
        </div>
      </div>

      <div className="flex-1 px-3 space-y-1 mt-4">
        {menuItems.map((item) => (
          <button
            key={item.id}
            onClick={() => setActiveTab(item.id)}
            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all duration-200 group ${
              activeTab === item.id 
                ? 'bg-orange-500/10 text-orange-400' 
                : 'text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/50'
            }`}
          >
            <item.icon size={20} className={activeTab === item.id ? 'text-orange-400' : 'text-zinc-500 group-hover:text-zinc-300'} />
            <span className="hidden md:block font-medium text-sm">{item.label}</span>
            {activeTab === item.id && (
                <div className="hidden md:block ml-auto w-1.5 h-1.5 rounded-full bg-orange-400 shadow-[0_0_8px_rgba(251,146,60,0.5)]" />
            )}
          </button>
        ))}
      </div>

      <div className="p-4">
        <div className="hidden md:block p-4 bg-zinc-900/50 border border-zinc-800 rounded-2xl">
          <p className="text-[10px] text-zinc-500 uppercase tracking-widest font-bold mb-2 text-center">Engine v2.4 Status</p>
          <div className="w-full h-1 bg-zinc-800 rounded-full overflow-hidden mt-1">
             <div className="w-3/4 h-full bg-orange-500 animate-pulse"></div>
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Sidebar;
