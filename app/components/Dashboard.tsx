
import React, { useState, useMemo } from 'react';
import { 
  TrendingUp, 
  TrendingDown, 
  Zap, 
  Skull, 
  ShieldAlert, 
  Clock,
  ArrowUpRight,
  Target,
  Maximize2
} from 'lucide-react';
import { StrategyStats, PnLPoint } from '../types';
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  BarChart,
  Bar,
  Brush,
  ReferenceLine
} from 'recharts';

interface DashboardProps {
  stats: StrategyStats;
  isRunning: boolean;
  pnlHistory: PnLPoint[];
}

const Dashboard: React.FC<DashboardProps> = ({ stats, isRunning, pnlHistory }) => {
  const [timeRange, setTimeRange] = useState<'1M' | '5M' | '15M' | 'ALL'>('ALL');

  const filteredPnlHistory = useMemo(() => {
    if (timeRange === 'ALL') return pnlHistory;
    const count = timeRange === '1M' ? 12 : timeRange === '5M' ? 60 : 180; // Sampled every 5s
    return pnlHistory.slice(-count);
  }, [pnlHistory, timeRange]);

  const cards = [
    { 
        label: 'Net Profit', 
        value: `${stats.netProfitEth.toFixed(4)} ETH`, 
        icon: TrendingUp, 
        color: 'text-green-400', 
        bg: 'bg-green-500/10',
        detail: `Gross: ${stats.grossProfitEth.toFixed(4)}`
    },
    { 
        label: 'Gas Burned', 
        value: `${stats.gasSpentEth.toFixed(4)} ETH`, 
        icon: Zap, 
        color: 'text-orange-400', 
        bg: 'bg-orange-500/10',
        detail: `Efficiency: ${((stats.grossProfitEth / stats.gasSpentEth) || 0).toFixed(2)}x`
    },
    { 
        label: 'Success Rate', 
        value: `${stats.successRate}%`, 
        icon: Target, 
        color: 'text-cyan-400', 
        bg: 'bg-cyan-500/10',
        detail: `${stats.submitted - stats.failed} of ${stats.submitted} bundled`
    },
    { 
        label: 'Tx Failed', 
        value: stats.failed.toString(), 
        icon: ShieldAlert, 
        color: 'text-red-400', 
        bg: 'bg-red-500/10',
        detail: 'Sim vs On-chain reverts'
    },
  ];

  return (
    <div className="space-y-6">
      {/* Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {cards.map((card, i) => (
          <div key={i} className="p-5 bg-[#0f0f11] border border-zinc-800 rounded-3xl group hover:border-zinc-700 transition-all">
            <div className="flex items-center justify-between mb-4">
              <div className={`p-2 rounded-xl ${card.bg}`}>
                <card.icon size={20} className={card.color} />
              </div>
              <ArrowUpRight size={16} className="text-zinc-600 group-hover:text-zinc-400 transition-colors" />
            </div>
            <p className="text-sm text-zinc-500 font-medium mb-1">{card.label}</p>
            <h3 className="text-2xl font-bold text-white mb-2">{card.value}</h3>
            <p className="text-[11px] font-mono text-zinc-600 uppercase tracking-wider">{card.detail}</p>
          </div>
        ))}
      </div>

      {/* Main Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 p-6 bg-[#0f0f11] border border-zinc-800 rounded-3xl">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
            <div>
              <h3 className="text-base font-bold text-white">Cumulative Performance</h3>
              <p className="text-xs text-zinc-500">Real-time PnL trajectory & gas monitoring</p>
            </div>
            
            <div className="flex items-center gap-4">
              <div className="flex bg-zinc-900 border border-zinc-800 p-1 rounded-xl">
                {(['1M', '5M', '15M', 'ALL'] as const).map(range => (
                  <button
                    key={range}
                    onClick={() => setTimeRange(range)}
                    className={`px-3 py-1 rounded-lg text-[10px] font-bold transition-all ${
                      timeRange === range ? 'bg-zinc-800 text-white shadow-sm' : 'text-zinc-500 hover:text-zinc-300'
                    }`}
                  >
                    {range}
                  </button>
                ))}
              </div>
              
              <div className="hidden sm:flex items-center gap-2">
                  <span className="flex items-center gap-1.5 text-[10px] text-zinc-400 uppercase font-bold tracking-wider">
                      <span className="w-2 h-2 rounded-full bg-cyan-500"></span> Profit
                  </span>
                  <span className="flex items-center gap-1.5 text-[10px] text-zinc-400 uppercase font-bold tracking-wider">
                      <span className="w-2 h-2 rounded-full bg-orange-500"></span> Gas
                  </span>
              </div>
            </div>
          </div>

          <div className="h-[350px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={filteredPnlHistory}>
                <defs>
                  <linearGradient id="pnlColor" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="gasColor" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f97316" stopOpacity={0.1}/>
                    <stop offset="95%" stopColor="#f97316" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" vertical={false} />
                <XAxis 
                  dataKey="time" 
                  stroke="#4b5563" 
                  fontSize={10} 
                  axisLine={false} 
                  tickLine={false} 
                  minTickGap={30}
                />
                <YAxis 
                  stroke="#4b5563" 
                  fontSize={10} 
                  axisLine={false} 
                  tickLine={false} 
                  tickFormatter={(v) => `${v.toFixed(3)}`} 
                />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#18181b', borderColor: '#3f3f46', borderRadius: '12px', boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.5)' }}
                  itemStyle={{ fontSize: '11px', fontWeight: 'bold' }}
                  labelStyle={{ color: '#94a3b8', fontSize: '10px', marginBottom: '4px' }}
                />
                <Area 
                  type="monotone" 
                  dataKey="pnl" 
                  stroke="#06b6d4" 
                  fillOpacity={1} 
                  fill="url(#pnlColor)" 
                  strokeWidth={2} 
                  animationDuration={500}
                />
                <Area 
                  type="monotone" 
                  dataKey="gas" 
                  stroke="#f97316" 
                  fillOpacity={1} 
                  fill="url(#gasColor)" 
                  strokeWidth={1.5} 
                  strokeDasharray="4 4"
                  animationDuration={500}
                />
                <ReferenceLine y={0} stroke="#3f3f46" strokeWidth={1} />
                <Brush 
                  dataKey="time" 
                  height={30} 
                  stroke="#3f3f46" 
                  fill="#18181b"
                  travellerWidth={8}
                  gap={10}
                >
                   <AreaChart data={pnlHistory}>
                      <Area type="monotone" dataKey="pnl" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.2} />
                   </AreaChart>
                </Brush>
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="p-6 bg-[#0f0f11] border border-zinc-800 rounded-3xl flex flex-col">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-base font-bold text-white">Efficiency metrics</h3>
            <button className="p-1.5 text-zinc-600 hover:text-zinc-400 transition-colors">
              <Maximize2 size={16} />
            </button>
          </div>
          <div className="flex-1 min-h-[250px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={[
                { name: 'Proc', val: stats.processed },
                { name: 'Skip', val: stats.skipped },
                { name: 'Sub', val: stats.submitted },
                { name: 'Fail', val: stats.failed }
              ]}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" vertical={false} />
                <XAxis dataKey="name" stroke="#4b5563" fontSize={10} axisLine={false} tickLine={false} />
                <Tooltip 
                  cursor={{ fill: '#27272a', radius: 8 }}
                  contentStyle={{ backgroundColor: '#18181b', borderColor: '#3f3f46', borderRadius: '12px' }}
                />
                <Bar dataKey="val" fill="#f97316" radius={[6, 6, 0, 0]} barSize={40} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-6 p-4 bg-zinc-900/40 rounded-2xl border border-zinc-800/50 space-y-3">
             <div className="flex items-center gap-3">
                <Skull className="text-zinc-600" size={16} />
                <p className="text-xs text-zinc-400">Gas skips: <span className="text-white font-mono">{Math.floor(stats.skipped * 0.3)}</span></p>
             </div>
             <div className="flex items-center gap-3">
                <Clock className="text-zinc-600" size={16} />
                <p className="text-xs text-zinc-400">Avg submission lag: <span className="text-white font-mono">14ms</span></p>
             </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
