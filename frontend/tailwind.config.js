/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#030712',
          panel: '#0f172a',
          line: '#1e293b',
          blue: '#38bdf8',
          green: '#22c55e',
          amber: '#f59e0b',
          red: '#ef4444',
        },
      },
      boxShadow: {
        glow: '0 0 30px rgba(56, 189, 248, 0.15)',
      },
      animation: {
        pulseRing: 'pulseRing 1.5s ease-out infinite',
        shimmer: 'shimmer 2.5s linear infinite',
      },
      keyframes: {
        pulseRing: {
          '0%': { transform: 'scale(0.9)', opacity: 0.8 },
          '100%': { transform: 'scale(1.2)', opacity: 0 },
        },
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
      },
    },
  },
  plugins: [],
}
