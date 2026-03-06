export type ExecutionPath = 'Sponsored' | 'Private only' | 'Pass-through';
export type TxStatus = 'Included' | 'Pending' | 'Failed' | 'Dropped';

export interface PublicStats {
  sponsoredTxCount: number;
  gasRefundedEth: number;
  mevReturnedUsd: number;
  avgInclusionSeconds: number;
}

export interface ActivityItem {
  id: string;
  txHash?: string;
  path: ExecutionPath;
  netToUserUsd: number;
  status: TxStatus;
  timestamp: string;
}

export interface TimelineStep {
  step: string;
  status: 'done' | 'pending' | 'failed';
  time: string;
}

export interface DashboardTransaction {
  id: string;
  txHash?: string;
  submittedAt: string;
  status: TxStatus;
  path: ExecutionPath;
  reason: string;
  gasCoveredUsd?: number;
  mevRebateUsd?: number;
  netToUserUsd: number;
  timeline?: TimelineStep[];
}

export interface ServiceStatus {
  name: string;
  status: 'operational' | 'degraded' | 'outage';
  uptimePct: number;
  latencyMs: number;
}

export interface Incident {
  id: string;
  title: string;
  impact: 'minor' | 'major' | 'critical';
  startedAt: string;
  resolvedAt?: string;
}

export interface PolicyConfig {
  retainedBps: number;
  perTxGasCapEth: number;
  perDayGasCapEth: number;
}

export interface PublicData {
  generatedAt: string;
  stats: PublicStats;
  activity: ActivityItem[];
  transactions: DashboardTransaction[];
  services: ServiceStatus[];
  incidents: Incident[];
  policy: PolicyConfig;
}

export interface PublicDataResult {
  source: 'live' | 'degraded';
  endpoint?: string;
  data: PublicData;
  error?: string;
}
