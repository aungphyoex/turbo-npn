import { NextConfig } from 'next';

const nextConfig = {
  experimental: {
    viewTransition: true,
    authInterrupts: true,
    serverActions: {
      bodySizeLimit: '30mb',
    },
  },
} satisfies NextConfig;

export default nextConfig;
