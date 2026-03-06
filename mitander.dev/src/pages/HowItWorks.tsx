import { motion } from 'motion/react';
import { ArrowRight, CheckCircle2, Clock, Shield, Zap } from 'lucide-react';
import { Link } from 'react-router-dom';

const steps = [
  {
    id: 1,
    name: 'Send Transaction',
    description: 'User or wallet sends an Ethereum transaction to rpc.mitander.dev instead of broadcasting in the public mempool.',
    icon: ArrowRight,
  },
  {
    id: 2,
    name: 'Simulation & Analysis',
    description: 'Our MEV engine simulates the transaction with candidate backruns to estimate net value, gas, and risk.',
    icon: Zap,
  },
  {
    id: 3,
    name: 'Policy Decision',
    description: 'The system evaluates the transaction against our risk policy and decides on one of three paths.',
    icon: Shield,
    details: [
      { name: 'Sponsored', desc: 'Gas is covered when policy and expected net value allow it.' },
      { name: 'Private only', desc: 'No gas coverage, but still private routing and possible rebate.' },
      { name: 'Pass-through', desc: 'Route privately with minimal intervention when opportunity is weak.' },
    ]
  },
  {
    id: 4,
    name: 'Bundle Submission',
    description: 'The transaction (and backrun when applicable) is sent privately to multiple Ethereum relays/builders.',
    icon: Clock,
  },
  {
    id: 5,
    name: 'Settlement & Rebate',
    description: 'After inclusion, our settlement service computes gas covered, user rebate, and retained share.',
    icon: CheckCircle2,
  },
];

export function HowItWorks() {
  return (
    <div className="bg-page py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-6 lg:px-8">
        <div className="mx-auto max-w-2xl lg:text-center">
          <h2 className="text-base font-semibold leading-7 text-emerald-600">Process</h2>
          <p className="mt-2 text-3xl font-bold tracking-tight text-zinc-900 sm:text-4xl">
            How Mitander works
          </p>
          <p className="mt-6 text-lg leading-8 text-zinc-600">
            A transparent, deterministic pipeline from private Ethereum transaction submission to execution rebate settlement.
          </p>
        </div>

        <div className="mx-auto mt-16 max-w-2xl sm:mt-20 lg:mt-24 lg:max-w-4xl">
          <div className="space-y-12">
            {steps.map((step, stepIdx) => (
              <motion.div 
                key={step.name} 
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: stepIdx * 0.1 }}
                className="relative flex gap-6"
              >
                <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-zinc-900 text-white shadow-sm">
                  <step.icon className="h-6 w-6" aria-hidden="true" />
                </div>
                <div>
                  <h3 className="text-xl font-semibold leading-8 text-zinc-900">
                    {step.id}. {step.name}
                  </h3>
                  <p className="mt-2 text-base leading-7 text-zinc-600">
                    {step.description}
                  </p>
                  {step.details && (
                    <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-3">
                      {step.details.map((detail) => (
                        <div key={detail.name} className="bg-white rounded-lg p-4 ring-1 ring-zinc-200">
                          <h4 className="font-medium text-zinc-900 text-sm">{detail.name}</h4>
                          <p className="mt-1 text-sm text-zinc-500">{detail.desc}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </motion.div>
            ))}
          </div>
        </div>

        <div className="mx-auto mt-16 max-w-4xl rounded-2xl border border-zinc-200 bg-white p-8">
          <h2 className="text-2xl font-semibold tracking-tight text-zinc-900">Related guides</h2>
          <div className="mt-4 flex flex-wrap gap-4 text-sm font-medium">
            <Link to="/private-ethereum-rpc" className="text-zinc-900 hover:text-zinc-600">
              Private Ethereum RPC guide <span aria-hidden>→</span>
            </Link>
            <Link to="/gasless-ethereum-transactions" className="text-zinc-900 hover:text-zinc-600">
              Gasless transactions policy <span aria-hidden>→</span>
            </Link>
            <Link to="/mev-protection" className="text-zinc-900 hover:text-zinc-600">
              MEV protection breakdown <span aria-hidden>→</span>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
