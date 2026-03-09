import React from 'react';

export function Logo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 100 100" className={className} fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="50" cy="50" r="36" stroke="currentColor" strokeWidth="14" />
      <path d="M 44 14 L 52 46 L 48 46 L 52 54 L 48 54 L 56 86" stroke="currentColor" strokeWidth="4" strokeLinejoin="miter" />
    </svg>
  );
}
