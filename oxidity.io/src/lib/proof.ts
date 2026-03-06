export interface ProofCaseStudy {
  title: string;
  profile: string;
  headline: string;
  summary: string;
  environment: string;
  shifts: string[];
  buyerSignals: string[];
}

export interface DiligenceItem {
  title: string;
  description: string;
  href: string;
}

export const proofCategories = [
  'Wallet teams',
  'dApps and protocols',
  'Searchers and desks',
  'Infra operators',
];

export const proofCaseStudies: ProofCaseStudy[] = [
  {
    title: 'Consumer wallet rollout',
    profile: 'Wallet team',
    headline: 'Move high-intent swaps out of browser-shaped infra and into protected partner ingress.',
    summary:
      'This pattern fits wallet teams that want better execution hygiene without pretending every flow deserves sponsorship. The operational win is not a vanity metric. It is a cleaner split between protected routing, selective sponsorship, and finance-readable settlement.',
    environment: 'High-value end-user swap flow with product, ops, and finance stakeholders in the loop.',
    shifts: [
      'Moved signed transaction submission behind server-to-server partner ingress.',
      'Separated `Sponsored` and `Private only` outcomes in product analytics and support playbooks.',
      'Used partner reporting and public status surfaces to reduce ambiguity during rollout.',
    ],
    buyerSignals: [
      'The wallet wants lower-friction execution without exposing a public RPC surface.',
      'The team needs treasury discipline before enabling sponsorship.',
    ],
  },
  {
    title: 'Protocol conversion funnel',
    profile: 'dApp / protocol',
    headline: 'Protect specific user journeys instead of trying to subsidize the entire product.',
    summary:
      'This pattern fits protocols with a few economically meaningful transaction paths. The value is in narrowing sponsorship to the flows that survive simulation, while still keeping non-sponsored traffic on protected routing.',
    environment: 'Conversion-sensitive onchain actions where a small number of routes drive most of the business value.',
    shifts: [
      'Scoped onboarding to a narrow set of routes with clear commercial boundaries.',
      'Kept fallback behavior explicit so non-eligible traffic still benefits from private routing.',
      'Aligned support expectations before production cutover instead of after the first incident.',
    ],
    buyerSignals: [
      'The protocol wants better execution quality on a few high-value routes.',
      'The team cares about reproducible operating rules more than headline subsidy claims.',
    ],
  },
  {
    title: 'Execution desk control plane',
    profile: 'Searcher / desk / infra',
    headline: 'Treat ingress, routing, and reporting as governed infrastructure rather than ad hoc operator tooling.',
    summary:
      'This pattern fits execution teams that already understand private orderflow and mainly need cleaner controls, stronger access boundaries, and partner-grade reporting for internal stakeholders.',
    environment: 'Operator-heavy teams that need auth, CIDR policy, throughput governance, and accountable reporting.',
    shifts: [
      'Replaced loose endpoint usage with bearer-authenticated, CIDR-gated production ingress.',
      'Made request budgeting and partner summary access part of the onboarding contract.',
      'Created a cleaner boundary between public telemetry and partner-only operational detail.',
    ],
    buyerSignals: [
      'The team wants fewer informal workflows around sensitive execution infrastructure.',
      'Ops and finance both need a clearer audit trail than raw transaction traces.',
    ],
  },
];

export const diligenceItems: DiligenceItem[] = [
  {
    title: 'Status and degraded-state behavior',
    description: 'Buyers should be able to inspect service health and telemetry behavior without relying on sales copy.',
    href: '/status',
  },
  {
    title: 'Developer docs and ingress model',
    description: 'Production teams need to see auth, CIDR policy, and method boundaries before any integration call.',
    href: '/developers',
  },
  {
    title: 'Risk and sponsorship policy',
    description: 'Sponsorship only looks credible when the operating constraints are written down and easy to review.',
    href: '/risk-policy',
  },
  {
    title: 'Pricing and commercial posture',
    description: 'Recurring access, governed usage, and minimums matter as much as the technical stack for trust.',
    href: '/pricing',
  },
];
