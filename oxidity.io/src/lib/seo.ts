const BASE_URL = 'https://oxidity.io';
const DEFAULT_IMAGE = `${BASE_URL}/og-image.svg?v=20260306b`;
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
  title: 'Oxidity | Private Ethereum Execution With Accountable Economics',
  description:
    'Oxidity is private Ethereum execution infrastructure for developers and teams: protected orderflow, policy-based sponsorship, and transparent settlement reporting.',
  canonicalPath: '/',
  robots: DEFAULT_ROBOTS,
  keywords:
    'private ethereum execution, private RPC, orderflow protection, gas sponsorship, settlement reporting, mev protection, wallet infrastructure',
  breadcrumbLabel: 'Home',
  schema: {
    '@context': 'https://schema.org',
    '@graph': [
      {
        '@type': 'WebSite',
        name: 'Oxidity',
        url: BASE_URL,
        description:
          'Private Ethereum execution infrastructure with policy-based sponsorship and transparent settlement reporting.',
      },
      {
        '@type': 'Service',
        name: 'Oxidity Execution Infrastructure',
        serviceType: 'Private Ethereum execution and policy-controlled sponsorship',
        provider: {
          '@type': 'Organization',
          name: 'Oxidity',
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
            name: 'How does policy-based sponsorship work?',
            acceptedAnswer: {
              '@type': 'Answer',
              text:
                'Transactions are simulated first. If expected net value is strong and within policy limits, Oxidity can sponsor gas costs and settle outcomes transparently.',
            },
          },
          {
            '@type': 'Question',
            name: 'Does Oxidity offer MEV protection and rebates?',
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
    title: 'How Private Ethereum Execution Works | Oxidity',
    description:
      'Learn how Oxidity ingests protected Ethereum orderflow, applies sponsorship policy, routes privately, and reports settlement outcomes.',
    canonicalPath: '/how-it-works',
    robots: DEFAULT_ROBOTS,
    keywords:
      'private execution workflow, orderflow protection, sponsorship policy, mev routing, settlement reporting',
    breadcrumbLabel: 'How It Works',
    schema: {
      '@type': 'HowTo',
      name: 'How Oxidity private Ethereum execution works',
      totalTime: 'PT5M',
      step: [
        { '@type': 'HowToStep', name: 'Submit private transaction' },
        { '@type': 'HowToStep', name: 'Simulate orderflow and MEV outcomes' },
        { '@type': 'HowToStep', name: 'Apply sponsorship and risk policy' },
        { '@type': 'HowToStep', name: 'Submit bundle to relays/builders' },
        { '@type': 'HowToStep', name: 'Settle sponsorship and rebates' },
      ],
    },
  },
  '/developers': {
    title: 'Developer Docs for Private Ethereum Execution | Oxidity',
    description:
      'Integrate with Oxidity protected RPC and summary APIs for private routing, policy-based sponsorship, and production-safe ingress.',
    canonicalPath: '/developers',
    robots: DEFAULT_ROBOTS,
    keywords:
      'ethereum rpc api, private execution docs, protected rpc, eth_sendRawTransaction private, searcher api, sponsorship api',
    breadcrumbLabel: 'Developers',
    schema: [
      {
        '@type': 'TechArticle',
        headline: 'Oxidity Developer Documentation',
        url: `${BASE_URL}/developers`,
        author: { '@type': 'Organization', name: 'Oxidity' },
      },
      {
        '@type': 'WebAPI',
        name: 'Oxidity Private RPC Gateway',
        documentation: `${BASE_URL}/developers`,
        provider: { '@type': 'Organization', name: 'Oxidity' },
        endpointUrl: 'https://rpc.oxidity.io',
      },
    ],
  },
  '/partners': {
    title: 'Teams, Companies, and Production Onboarding | Oxidity',
    description:
      'Explore production onboarding for wallets, dApps, desks, and searchers using Oxidity private execution, policy controls, and settlement reporting.',
    canonicalPath: '/partners',
    robots: DEFAULT_ROBOTS,
    keywords:
      'private execution onboarding, wallet infrastructure partner, dapp orderflow, searcher onboarding, ethereum execution partner',
    breadcrumbLabel: 'Teams',
  },
  '/proof': {
    title: 'Proof, Deployment Patterns, and Due Diligence | Oxidity',
    description:
      'Review anonymized deployment patterns, buyer diligence surfaces, and the controls that make Oxidity look credible to developers and companies.',
    canonicalPath: '/proof',
    robots: DEFAULT_ROBOTS,
    keywords:
      'private execution proof, ethereum infrastructure diligence, anonymized case studies, wallet infrastructure proof, mev execution proof',
    breadcrumbLabel: 'Proof',
  },
  '/pricing': {
    title: 'Pricing and Packaging for Private Ethereum Execution | Oxidity',
    description:
      'Review Oxidity packaging for solo developers, startups, wallets, dApps, and enterprise execution teams.',
    canonicalPath: '/pricing',
    robots: DEFAULT_ROBOTS,
    keywords:
      'private rpc pricing, ethereum infrastructure pricing, orderflow pricing, wallet execution pricing, mev infrastructure pricing',
    breadcrumbLabel: 'Pricing',
  },
  '/status': {
    title: 'Private RPC and MEV Pipeline Status | Oxidity',
    description:
      'Live status for Oxidity private Ethereum execution, RPC availability, and public telemetry health.',
    canonicalPath: '/status',
    robots: DEFAULT_ROBOTS,
    keywords:
      'private rpc status, ethereum rpc uptime, mev pipeline status, public telemetry status',
    breadcrumbLabel: 'Status',
  },
  '/risk-policy': {
    title: 'Sponsorship and MEV Risk Policy | Oxidity',
    description:
      'Review Oxidity risk controls, sponsorship eligibility rules, and operational limits for private Ethereum execution.',
    canonicalPath: '/risk-policy',
    robots: DEFAULT_ROBOTS,
    keywords:
      'mev risk policy, sponsorship policy, private rpc security, ethereum execution policy',
    breadcrumbLabel: 'Risk Policy',
  },
  '/dashboard': {
    title: 'Partner Dashboard | Oxidity',
    description:
      'Partner dashboard for private execution timelines, gas-coverage decisions, and execution rebate ledger reporting.',
    canonicalPath: '/dashboard',
    robots: 'noindex,nofollow,noarchive',
    keywords: 'partner dashboard, mev analytics, coverage ledger, private rpc reporting',
    breadcrumbLabel: 'Dashboard',
  },
  '/private-ethereum-rpc': {
    title: 'Private Ethereum RPC Gateway for Wallets, dApps, and Searchers | Oxidity',
    description:
      'Use Oxidity private Ethereum RPC to keep transactions out of the public mempool, improve execution privacy, and route to multiple relays/builders.',
    canonicalPath: '/private-ethereum-rpc',
    robots: DEFAULT_ROBOTS,
    keywords:
      'private ethereum rpc, private rpc gateway, ethereum private mempool, mev protection rpc, private transaction relay',
    breadcrumbLabel: 'Private Ethereum RPC',
    schema: {
      '@type': 'WebAPI',
      name: 'Oxidity Private Ethereum RPC',
      endpointUrl: 'https://rpc.oxidity.io',
      documentation: `${BASE_URL}/developers`,
      provider: { '@type': 'Organization', name: 'Oxidity' },
    },
  },
  '/gasless-ethereum-transactions': {
    title: 'Gasless Ethereum Transactions with Conditional Sponsorship | Oxidity',
    description:
      'Oxidity supports selective gasless Ethereum experiences with simulation-first sponsorship policy, transparent settlement, and private routing.',
    canonicalPath: '/gasless-ethereum-transactions',
    robots: DEFAULT_ROBOTS,
    keywords:
      'gasless ethereum transactions, conditional sponsorship, ethereum gas refund, sponsored transactions, gas rebate',
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
              'It can still run through private routing, but sponsorship and rebate amounts may be reduced or zero.',
          },
        },
      ],
    },
  },
  '/mev-protection': {
    title: 'Ethereum MEV Protection via Private Orderflow | Oxidity',
    description:
      'Oxidity MEV protection combines private transaction ingress, multi-relay submission, and risk policy gates to reduce sandwich and frontrun exposure.',
    canonicalPath: '/mev-protection',
    robots: DEFAULT_ROBOTS,
    keywords:
      'mev protection, ethereum mev, mev mitigation, sandwich attack protection, private orderflow, mev private rpc',
    breadcrumbLabel: 'MEV Protection',
    schema: {
      '@type': 'Article',
      headline: 'Ethereum MEV Protection with Private Orderflow',
      author: { '@type': 'Organization', name: 'Oxidity' },
      publisher: { '@type': 'Organization', name: 'Oxidity' },
      mainEntityOfPage: `${BASE_URL}/mev-protection`,
    },
  },
  '/terms': {
    title: 'Terms of Service | Oxidity',
    description:
      'Service terms for Oxidity private Ethereum execution, sponsorship policy, and settlement reporting infrastructure.',
    canonicalPath: '/terms',
    robots: DEFAULT_ROBOTS,
    keywords:
      'terms of service, private rpc terms, sponsorship terms, mev infrastructure terms',
    breadcrumbLabel: 'Terms',
    schema: {
      '@type': 'WebPage',
      name: 'Oxidity Terms of Service',
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
  upsertMetaByName('author', 'Oxidity');
  if (seo.keywords) {
    upsertMetaByName('keywords', seo.keywords);
  }
  upsertCanonical(canonical);

  upsertMetaByProperty('og:type', 'website');
  upsertMetaByProperty('og:site_name', 'Oxidity');
  upsertMetaByProperty('og:locale', 'en_US');
  upsertMetaByProperty('og:title', seo.title);
  upsertMetaByProperty('og:description', seo.description);
  upsertMetaByProperty('og:url', canonical);
  upsertMetaByProperty('og:image', DEFAULT_IMAGE);
  upsertMetaByProperty('og:image:alt', 'Oxidity private RPC and execution rebate branding');

  upsertMetaByName('twitter:card', 'summary_large_image');
  upsertMetaByName('twitter:title', seo.title);
  upsertMetaByName('twitter:description', seo.description);
  upsertMetaByName('twitter:image', DEFAULT_IMAGE);

  setRouteSchema(normalized, seo, canonical);
}
