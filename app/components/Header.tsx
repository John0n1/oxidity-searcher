
import React from 'react';
import { Play, Square, Bell, User } from 'lucide-react';
import { AppTab } from '../types';

interface HeaderProps {
  isRunning: boolean;
  setIsRunning: (run: boolean) => void;
  activeTab: AppTab;
}

const Header: React.FC<HeaderProps> = ({ isRunning, setIsRunning, activeTab }) => {
  return (
    <header className="h-16 border-b border-zinc-800 px-6 flex items-center justify-between shrink-0 bg-[#0a0a0b]/80 backdrop-blur-md sticky top-0 z-10">
      <div className="flex items-center gap-4">
        <h2 className="text-lg font-semibold text-white capitalize">{activeTab.toLowerCase().replace('_', ' ')}</h2>
      </div>

      <div className="flex items-center gap-3">
        <button
          onClick={() => setIsRunning(!isRunning)}
          className={`flex items-center gap-2 px-5 py-2 rounded-full font-semibold text-sm transition-all shadow-lg ${
            isRunning 
              ? 'bg-zinc-800 text-zinc-300 hover:bg-zinc-700' 
              : 'bg-orange-500 text-white hover:bg-orange-600 shadow-orange-900/30'
          }`}
        >
          {isRunning ? <Square size={16} fill="currentColor" /> : <Play size={16} fill="currentColor" />}
          {isRunning ? 'Stop Engine' : 'Start Engine'}
        </button>

        <div className="w-px h-6 bg-zinc-800 mx-1"></div>

        <button className="p-2 text-zinc-400 hover:text-white transition-colors relative">
          <Bell size={20} />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-orange-500 rounded-full border-2 border-[#0a0a0b]"></span>
        </button>
        
        <button className="flex items-center gap-2 p-1 pl-3 pr-1 rounded-full bg-zinc-900 border border-zinc-800 hover:border-zinc-700 transition-colors">
            <span className="text-xs font-medium text-zinc-300">Admin</span>
            <div className="w-7 h-7 rounded-full bg-zinc-800 flex items-center justify-center text-zinc-400">
                <User size={16} />
            </div>
        </button>
      </div>
    </header>
  );
};

export default Header;
