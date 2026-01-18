
import React, { useState } from 'react';
import { LogEntry, LogLevel } from '../types';
// Fixed: Added Terminal to the imports from lucide-react to resolve the reference error
import { Trash2, Search, Filter, Download, Terminal } from 'lucide-react';

interface LoggerProps {
  logs: LogEntry[];
  setLogs: (logs: LogEntry[]) => void;
}

const Logger: React.FC<LoggerProps> = ({ logs, setLogs }) => {
  const [filter, setFilter] = useState<LogLevel | 'ALL'>('ALL');
  const [search, setSearch] = useState('');

  const filteredLogs = logs.filter(log => {
    const matchesLevel = filter === 'ALL' || log.level === filter;
    const matchesSearch = log.message.toLowerCase().includes(search.toLowerCase()) || 
                          log.module.toLowerCase().includes(search.toLowerCase());
    return matchesLevel && matchesSearch;
  });

  const getLevelColor = (level: LogLevel) => {
    switch (level) {
      case LogLevel.ERROR: return 'text-red-500 bg-red-500/10';
      case LogLevel.WARNING: return 'text-orange-500 bg-orange-500/10';
      case LogLevel.INFO: return 'text-blue-500 bg-blue-500/10';
      case LogLevel.DEBUG: return 'text-zinc-500 bg-zinc-500/10';
      default: return 'text-zinc-400 bg-zinc-400/5';
    }
  };

  return (
    <div className="h-full flex flex-col bg-[#0f0f11] border border-zinc-800 rounded-3xl overflow-hidden">
      {/* Toolbar */}
      <div className="p-4 border-b border-zinc-800 flex flex-wrap items-center justify-between gap-4 bg-zinc-900/20">
        <div className="flex items-center gap-4 flex-1 min-w-[300px]">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" size={16} />
            <input 
              type="text" 
              placeholder="Search logs..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-zinc-900 border border-zinc-800 rounded-full py-1.5 pl-10 pr-4 text-sm focus:outline-none focus:border-zinc-600 transition-colors"
            />
          </div>
          <div className="flex gap-1 p-1 bg-zinc-900 rounded-full border border-zinc-800">
            {['ALL', LogLevel.INFO, LogLevel.WARNING, LogLevel.DEBUG].map((lvl) => (
              <button
                key={lvl}
                onClick={() => setFilter(lvl as any)}
                className={`px-3 py-1 rounded-full text-[10px] font-bold uppercase transition-all ${
                  filter === lvl ? 'bg-zinc-700 text-white' : 'text-zinc-500 hover:text-zinc-300'
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-2">
            <button className="p-2 text-zinc-500 hover:text-zinc-300 transition-colors" title="Export Logs">
                <Download size={18} />
            </button>
            <button 
                onClick={() => setLogs([])}
                className="p-2 text-zinc-500 hover:text-red-400 transition-colors" title="Clear Logs"
            >
                <Trash2 size={18} />
            </button>
        </div>
      </div>

      {/* Log Feed */}
      <div className="flex-1 overflow-y-auto p-4 font-mono text-xs space-y-1">
        {filteredLogs.length === 0 ? (
          <div className="h-full flex items-center justify-center text-zinc-600 flex-col gap-2">
            <Terminal size={40} />
            <p>No log entries found</p>
          </div>
        ) : (
          filteredLogs.map((log) => (
            <div key={log.id} className="group hover:bg-zinc-800/30 p-1 px-2 rounded-md transition-colors flex gap-4">
              <span className="text-zinc-600 shrink-0 select-none">[{log.timestamp}]</span>
              <span className={`px-1.5 rounded uppercase text-[10px] font-bold w-16 text-center shrink-0 ${getLevelColor(log.level)}`}>
                {log.level}
              </span>
              <span className="text-cyan-600 shrink-0 w-20 truncate">[{log.module}]</span>
              <span className="text-zinc-300 flex-1">{log.message}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default Logger;
