const BASE_URL = 'https://mitander.dev';
const DEFAULT_IMAGE = `${BASE_URL}/og-image.svg`;
const DEFAULT_ROBOTS = 'index,follow,max-image-preview:large,max-snippet:-1,max-video-preview:-1';
const SCHEMA_SCRIPT_ID = 'route-seo-jsonld';

interface SeoConfig {
  title: string;
  description: string;
  canonicalPath: string;
  robots?: string;
  keywords?: string;
  breadcrumbLabel?: string;
  schema?: Record<string, unknown> | Array<Record<string, unknown>>;
}

const DEFAULT_SEO: SeoConfig = {
  title: 'Mitander | Private Ethereum RPC, Conditional Gas Coverage, Execution Rebates',
  description:
    'Mitander is private Ethereum execution infrastructure: private RPC routing, conditional gas coverage, MEV-aware protection, and transparent execution rebates.',
  canonicalPath: '/',
  robots: DEFAULT_ROBOTS,
  keywords:
    'MEV, gasless transactions, private RPC, private mempool, Ethereum, MEV protection, MEV rebate, searcher infrastructure',
  breadcrumbLabel: 'Home',
  schema: {
    '@context': 'https://schema.org',
    '@graph': [
      {
        '@type': 'WebSite',
        name: 'Mitander',
        url: BASE_URL,
        description:
          'Private Ethereum execution infrastructure with conditional gas coverage and transparent execution rebates.',
      },
      {
        '@type': 'Service',
        name: 'Mitander Private RPC',
        serviceType: 'Private Ethereum RPC and orderflow execution',
        provider: {
          '@type': 'Organization',
          name: 'Mitander',
          url: BASE_URL,
        },
        areaServed: 'Global',
        termsOfService: `${BASE_URL}/risk-policy`,
      },
      {
        '@type': 'FAQPage',
        mainEntity: [
          {
            '@type': 'Question',
            name: 'What is a private RPC for Ethereum?',
            acceptedAnswer: {
              '@type': 'Answer',
              text:
                'A private RPC submits transactions outside the public mempool to reduce exposure to front-running and sandwich attacks.',
            },
          },
          {
            '@type': 'Question',
            name: 'How does conditional gas coverage work?',
            acceptedAnswer: {
              '@type': 'Answer',
              text:
                'Transactions are simulated first. If expected net value is strong and within policy limits, Mitander can cover gas costs and settle rebates.',
            },
          },
          {
            '@type': 'Question',
            name: 'Does Mitander offer MEV protection and rebates?',
            acceptedAnswer: {
              '@type': 'Answer',
              text:
                'Yes. Transactions are privately routed and eligible flow can receive transparent execution rebate settlement with per-transaction ledger visibility.',
            },
          },
          {
            '@type': 'Question',
            name: 'Can wallets and dApps integrate this private RPC?',
            acceptedAnswer: {
              '@type': 'Answer',
              text:
                'Yes. Wallets, dApps, and searcher partners can integrate via documented RPC endpoints and summary APIs.',
            },
          },
        ],
      },
    ],
  },
};

const ROUTE_SEO: Record<string, SeoConfig> = {
  '/': DEFAULT_SEO,
  '/how-it-works': {
    title: 'How Private Ethereum RPC and Conditional Gas Coverage Work | Mitander',
    description:
      'Learn how Mitander simulates Ethereum orderflow, applies policy-based gas coverage decisions, routes privately, and settles rebates.',
    canonicalPath: '/how-it-works',
    robots: DEFAULT_ROBOTS,
    keywords:
      'how private rpc works, gasless ethereum transactions, mev routing, mev bundle execution, private mempool flow',
    breadcrumbLabel: 'How It Works',
    schema: {
      '@type': 'HowTo',
      name: 'How Mitander private Ethereum execution works',
      totalTime: 'PT5M',
      step: [
        { '@type': 'HowToStep', name: 'Submit private transaction' },
        { '@type': 'HowToStep', name: 'Simulate orderflow and MEV outcomes' },
        { '@type': 'HowToStep', name: 'Apply gas-coverage and risk policy' },
        { '@type': 'HowToStep', name: 'Submit bundle to relays/builders' },
        { '@type': 'HowToStep', name: 'Settle gas coverage and rebates' },
      ],
    },
  },
  '/developers': {
    title: 'Ethereum MEV API and Private RPC Documentation | Mitander',
    description:
      'Integrate with Mitander private Ethereum RPC and summary APIs for MEV-aware private routing, gas-coverage telemetry, and production-safe ingress.',
    canonicalPath: '/developers',
    robots: DEFAULT_ROBOTS,
    keywords:
      'ethereum rpc api, mev api, private rpc docs, eth_sendRawTransaction private, searcher api, gasless api',
    breadcrumbLabel: 'Developers',
    schema: [
      {
        '@type': 'TechArticle',
        headline: 'Mitander Developer Documentation',
        url: `${BASE_URL}/developers`,
        author: { '@type': 'Organization', name: 'Mitander' },
      },
      {
        '@type': 'WebAPI',
        name: 'Mitander Private RPC Gateway',
        documentation: `${BASE_URL}/developers`,
        provider: { '@type': 'Organization', name: 'Mitander' },
        endpointUrl: 'https://rpc.mitander.dev',
      },
    ],
  },
  '/partners': {
    title: 'MEV and Gasless Partner Program for Wallets and dApps | Mitander',
    description:
      'Partner with Mitander to route private Ethereum orderflow, enable conditional gas-coverage experiences, and expose transparent execution rebate settlement.',
    canonicalPath: '/partners',
    robots: DEFAULT_ROBOTS,
    keywords:
      'mev partner program, gasless wallet integration, private rpc partner, dapp private orderflow, mev rebates',
    breadcrumbLabel: 'Partners',
  },
  '/status': {
    title: 'Private RPC and MEV Pipeline Status | Mitander',
    description:
      'Live status for Mitander private Ethereum RPC, execution pipeline performance, and gas-coverage/rebate telemetry.',
    canonicalPath: '/status',
    robots: DEFAULT_ROBOTS,
    keywords:
      'private rpc status, ethereum rpc uptime, mev pipeline status, gasless coverage status',
    breadcrumbLabel: 'Status',
  },
  '/risk-policy': {
    title: 'Gas Coverage and MEV Risk Policy | Mitander',
    description:
      'Review Mitander risk controls, eligibility rules, and operational limits for private Ethereum execution and coverage-eligible transactions.',
    canonicalPath: '/risk-policy',
    robots: DEFAULT_ROBOTS,
    keywords:
      'mev risk policy, gas coverage policy, private rpc security, ethereum execution policy',
    breadcrumbLabel: 'Risk Policy',
  },
  '/dashboard': {
    title: 'Partner Dashboard | Mitander',
    description:
      'Partner dashboard for private execution timelines, gas-coverage decisions, and execution rebate ledger reporting.',
    canonicalPath: '/dashboard',
    robots: 'noindex,nofollow,noarchive',
    keywords: 'partner dashboard, mev analytics, coverage ledger, private rpc reporting',
    breadcrumbLabel: 'Dashboard',
  },
  '/private-ethereum-rpc': {
    title: 'Private Ethereum RPC Gateway for Wallets, dApps, and Searchers | Mitander',
    description:
      'Use Mitander private Ethereum RPC to keep transactions out of the public mempool, improve execution privacy, and route to multiple relays/builders.',
    canonicalPath: '/private-ethereum-rpc',
    robots: DEFAULT_ROBOTS,
    keywords:
      'private ethereum rpc, private rpc gateway, ethereum private mempool, mev protection rpc, private transaction relay',
    breadcrumbLabel: 'Private Ethereum RPC',
    schema: {
      '@type': 'WebAPI',
      name: 'Mitander Private Ethereum RPC',
      endpointUrl: 'https://rpc.mitander.dev',
      documentation: `${BASE_URL}/developers`,
      provider: { '@type': 'Organization', name: 'Mitander' },
    },
  },
  '/gasless-ethereum-transactions': {
    title: 'Gasless Ethereum Transactions with Conditional Sponsorship | Mitander',
    description:
      'Mitander supports conditional gasless Ethereum transactions with simulation-first coverage policy, transparent settlement, and user rebate accounting.',
    canonicalPath: '/gasless-ethereum-transactions',
    robots: DEFAULT_ROBOTS,
    keywords:
      'gasless ethereum transactions, gas coverage, ethereum gas refund, sponsored transactions, gas rebate',
    breadcrumbLabel: 'Gasless Transactions',
    schema: {
      '@type': 'FAQPage',
      mainEntity: [
        {
          '@type': 'Question',
          name: 'Are all transactions gasless?',
          acceptedAnswer: {
            '@type': 'Answer',
            text:
              'No. Gas coverage is conditional and determined by simulation, expected net value, and policy limits.',
          },
        },
        {
          '@type': 'Question',
          name: 'What happens when a transaction is not eligible?',
          acceptedAnswer: {
            '@type': 'Answer',
            text:
              'It can still run through private routing, but gas coverage and rebate amounts may be reduced or zero.',
          },
        },
      ],
    },
  },
  '/mev-protection': {
    title: 'Ethereum MEV Protection via Private Orderflow | Mitander',
    description:
      'Mitander MEV protection combines private transaction ingress, multi-relay submission, and risk policy gates to reduce sandwich and frontrun exposure.',
    canonicalPath: '/mev-protection',
    robots: DEFAULT_ROBOTS,
    keywords:
      'mev protection, ethereum mev, mev mitigation, sandwich attack protection, private orderflow, mev private rpc',
    breadcrumbLabel: 'MEV Protection',
    schema: {
      '@type': 'Article',
      headline: 'Ethereum MEV Protection with Private Orderflow',
      author: { '@type': 'Organization', name: 'Mitander' },
      publisher: { '@type': 'Organization', name: 'Mitander' },
      mainEntityOfPage: `${BASE_URL}/mev-protection`,
    },
  },
  '/terms': {
    title: 'Terms of Service | Mitander',
    description:
      'Service terms for Mitander private RPC, policy-based gas coverage, and settlement/rebate infrastructure.',
    canonicalPath: '/terms',
    robots: DEFAULT_ROBOTS,
    keywords:
      'terms of service, private rpc terms, gas coverage terms, mev infrastructure terms',
    breadcrumbLabel: 'Terms',
    schema: {
      '@type': 'WebPage',
      name: 'Mitander Terms of Service',
      url: `${BASE_URL}/terms`,
    },
  },
};

function normalizePath(pathname: string): string {
  const clean = pathname.split('?')[0].split('#')[0] || '/';
  if (clean.length > 1 && clean.endsWith('/')) {
    return clean.slice(0, -1);
  }
  return clean;
}

function resolveSeo(pathname: string): SeoConfig {
  const normalized = normalizePath(pathname);
  return ROUTE_SEO[normalized] ?? DEFAULT_SEO;
}

function upsertMetaByName(name: string, content: string) {
  let meta = document.querySelector(`meta[name="${name}"]`) as HTMLMetaElement | null;
  if (!meta) {
    meta = document.createElement('meta');
    meta.setAttribute('name', name);
    document.head.appendChild(meta);
  }
  meta.setAttribute('content', content);
}

function upsertMetaByProperty(property: string, content: string) {
  let meta = document.querySelector(`meta[property="${property}"]`) as HTMLMetaElement | null;
  if (!meta) {
    meta = document.createElement('meta');
    meta.setAttribute('property', property);
    document.head.appendChild(meta);
  }
  meta.setAttribute('content', content);
}

function upsertCanonical(href: string) {
  let link = document.querySelector('link[rel="canonical"]') as HTMLLinkElement | null;
  if (!link) {
    link = document.createElement('link');
    link.setAttribute('rel', 'canonical');
    document.head.appendChild(link);
  }
  link.setAttribute('href', href);
}

function breadcrumbLabelFor(path: string): string {
  return ROUTE_SEO[path]?.breadcrumbLabel ?? path.split('/').filter(Boolean).join(' ');
}

function buildBreadcrumbSchema(pathname: string): Record<string, unknown> {
  if (pathname === '/') {
    return {
      '@type': 'BreadcrumbList',
      itemListElement: [
        {
          '@type': 'ListItem',
          position: 1,
          name: 'Home',
          item: `${BASE_URL}/`,
        },
      ],
    };
  }

  const segments = pathname.split('/').filter(Boolean);
  const list: Array<Record<string, unknown>> = [
    {
      '@type': 'ListItem',
      position: 1,
      name: 'Home',
      item: `${BASE_URL}/`,
    },
  ];

  let partial = '';
  segments.forEach((segment, index) => {
    partial += `/${segment}`;
    list.push({
      '@type': 'ListItem',
      position: index + 2,
      name: breadcrumbLabelFor(partial),
      item: `${BASE_URL}${partial}`,
    });
  });

  return {
    '@type': 'BreadcrumbList',
    itemListElement: list,
  };
}

function setRouteSchema(pathname: string, seo: SeoConfig, canonical: string) {
  const existing = document.getElementById(SCHEMA_SCRIPT_ID);
  const pageSchema: Record<string, unknown> = {
    '@type': 'WebPage',
    name: seo.title,
    description: seo.description,
    url: canonical,
  };
  const breadcrumbSchema = buildBreadcrumbSchema(pathname);

  const graph: Array<Record<string, unknown>> = [pageSchema, breadcrumbSchema];

  if (seo.schema) {
    if (Array.isArray(seo.schema)) {
      graph.push(...seo.schema);
    } else if ('@context' in seo.schema || '@graph' in seo.schema) {
      const contextual = seo.schema as Record<string, unknown>;
      if (Array.isArray(contextual['@graph'])) {
        graph.push(...(contextual['@graph'] as Array<Record<string, unknown>>));
      } else {
        const { ['@context']: _ignoreContext, ...rest } = contextual;
        graph.push(Object.keys(rest).length > 0 ? rest : contextual);
      }
    } else {
      graph.push(seo.schema);
    }
  }

  const payload = { '@context': 'https://schema.org', '@graph': graph };
  const jsonLd = JSON.stringify(payload, null, 0);

  let script = existing as HTMLScriptElement | null;
  if (!script) {
    script = document.createElement('script');
    script.id = SCHEMA_SCRIPT_ID;
    script.type = 'application/ld+json';
    document.head.appendChild(script);
  }
  script.textContent = jsonLd;
}

export function applySeo(pathname: string) {
  const normalized = normalizePath(pathname);
  const seo = resolveSeo(normalized);
  const canonical = `${BASE_URL}${seo.canonicalPath}`;

  document.title = seo.title;

  upsertMetaByName('description', seo.description);
  upsertMetaByName('robots', seo.robots ?? DEFAULT_ROBOTS);
  upsertMetaByName('author', 'Mitander');
  if (seo.keywords) {
    upsertMetaByName('keywords', seo.keywords);
  }
  upsertCanonical(canonical);

  upsertMetaByProperty('og:type', 'website');
  upsertMetaByProperty('og:site_name', 'Mitander');
  upsertMetaByProperty('og:locale', 'en_US');
  upsertMetaByProperty('og:title', seo.title);
  upsertMetaByProperty('og:description', seo.description);
  upsertMetaByProperty('og:url', canonical);
  upsertMetaByProperty('og:image', DEFAULT_IMAGE);
  upsertMetaByProperty('og:image:alt', 'Mitander private RPC and execution rebate branding');

  upsertMetaByName('twitter:card', 'summary_large_image');
  upsertMetaByName('twitter:title', seo.title);
  upsertMetaByName('twitter:description', seo.description);
  upsertMetaByName('twitter:image', DEFAULT_IMAGE);

  setRouteSchema(normalized, seo, canonical);
}
