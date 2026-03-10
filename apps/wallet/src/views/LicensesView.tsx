import { useMemo, useState } from 'react';
import { ArrowLeft, Search } from 'lucide-react';
import { motion } from 'motion/react';

import { THIRD_PARTY_LICENSES } from '../generated/licenses';
import { useAppStore } from '../store/appStore';

export function LicensesView() {
  const setView = useAppStore((state) => state.setView);
  const [query, setQuery] = useState('');

  const filteredLicenses = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    if (!normalizedQuery) {
      return THIRD_PARTY_LICENSES;
    }

    return THIRD_PARTY_LICENSES.filter((entry) => {
      return [
        entry.name,
        entry.version,
        entry.license,
        entry.repository || '',
        entry.homepage || '',
      ].some((value) => value.toLowerCase().includes(normalizedQuery));
    });
  }, [query]);

  return (
    <motion.div
      initial={{ x: '100%' }}
      animate={{ x: 0 }}
      exit={{ x: '100%' }}
      transition={{ type: 'spring', damping: 25, stiffness: 200 }}
      className="absolute inset-0 z-50 flex flex-col overflow-hidden bg-zinc-950"
    >
      <div className="sticky top-0 z-10 border-b border-white/5 bg-zinc-950/80 p-6 backdrop-blur-xl">
        <div className="flex items-center gap-4">
          <button
            onClick={() => setView('main')}
            className="flex h-10 w-10 items-center justify-center rounded-full bg-zinc-900 transition-colors hover:bg-zinc-800"
          >
            <ArrowLeft className="h-5 w-5" />
          </button>
          <div className="min-w-0">
            <h2 className="text-xl font-semibold">Open Source Licenses</h2>
            <p className="text-xs text-zinc-500">
              {THIRD_PARTY_LICENSES.length} packages bundled in this wallet build
            </p>
          </div>
        </div>

        <div className="relative mt-4">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
          <input
            type="text"
            placeholder="Search packages or licenses..."
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            className="w-full rounded-2xl border border-white/10 bg-zinc-900 py-3 pl-10 pr-4 text-sm text-white placeholder:text-zinc-600 focus:border-indigo-500/50 focus:outline-none"
          />
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-6">
        <div className="space-y-3">
          {filteredLicenses.map((entry) => (
            <div
              key={`${entry.name}@${entry.version}`}
              className="rounded-2xl border border-white/5 bg-zinc-900 p-4"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <h3 className="truncate font-semibold text-white">{entry.name}</h3>
                  <p className="text-xs text-zinc-500">{entry.version}</p>
                </div>
                <span className="shrink-0 rounded-full bg-indigo-500/10 px-3 py-1 text-[10px] font-bold uppercase tracking-wider text-indigo-300">
                  {entry.license}
                </span>
              </div>

              {entry.repository ? (
                <p className="mt-3 break-all font-mono text-[11px] text-zinc-400">{entry.repository}</p>
              ) : null}
              {entry.homepage && entry.homepage !== entry.repository ? (
                <p className="mt-1 break-all text-[11px] text-zinc-500">{entry.homepage}</p>
              ) : null}
            </div>
          ))}

          {filteredLicenses.length === 0 ? (
            <div className="rounded-2xl border border-white/5 bg-zinc-900 p-6 text-center text-sm text-zinc-500">
              No packages match "{query}".
            </div>
          ) : null}
        </div>
      </div>
    </motion.div>
  );
}
