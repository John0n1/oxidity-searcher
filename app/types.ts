
export enum LogLevel {
  VERBOSE = 'VERBOSE',
  DEBUG = 'DEBUG',
  INFO = 'INFO',
  WARNING = 'WARNING',
  ERROR = 'ERROR'
}

export interface LogEntry {
  id: string;
  timestamp: string;
  level: LogLevel;
  module: string;
  message: string;
}

export interface MempoolEntry {
  hash: string;
  from: string;
  to: string;
  value: string;
  gasPrice: string;
  mevType: 'Arbitrage' | 'Sandwich' | 'Liquid' | 'None';
  potential: number;
}

export interface StrategyStats {
  processed: number;
  submitted: number;
  skipped: number;
  failed: number;
  successRate: number;
  grossProfitEth: number;
  gasSpentEth: number;
  netProfitEth: number;
}

export interface GlobalConfig {
  debug: boolean;
  chains: number[];
  walletAddress: string;
  maxGasPriceGwei: number;
  simulationBackend: 'revm' | 'anvil';
  flashloanEnabled: boolean;
  sandwichAttacksEnabled: boolean;
  mevShareEnabled: boolean;
  slippageBps: number;
  voiceAlerts: boolean;
}

export enum AppTab {
  DASHBOARD = 'DASHBOARD',
  MEMPOOL = 'MEMPOOL',
  LOGS = 'LOGS',
  CONFIG = 'CONFIG',
  STRATEGY = 'STRATEGY'
}

export interface PnLPoint {
  time: string;
  pnl: number;
  gas: number;
}
