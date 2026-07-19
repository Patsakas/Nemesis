/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      colors: {
        nem: {
          bg: '#020617',
          surface: '#0F172A',
          'surface-2': '#1E293B',
          border: '#334155',
          'border-bright': '#475569',
          text: '#F8FAFC',
          muted: '#94A3B8',
          dim: '#64748B',
          accent: '#22C55E',
          'accent-dim': '#166534',
          'accent-glow': '#4ADE80',
          red: '#EF4444',
          'red-dim': '#7F1D1D',
          yellow: '#F59E0B',
          'yellow-dim': '#78350F',
          blue: '#3B82F6',
          'blue-dim': '#1E3A5F',
          purple: '#A78BFA',
          'purple-dim': '#4C1D95',
        },
      },
      boxShadow: {
        'glow-green': '0 0 15px rgba(34, 197, 94, 0.3)',
        'glow-red': '0 0 15px rgba(239, 68, 68, 0.3)',
        'glow-blue': '0 0 15px rgba(59, 130, 246, 0.3)',
      },
    },
  },
  plugins: [],
}
