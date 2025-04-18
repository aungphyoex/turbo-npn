import { NextConfig } from 'next';

const nextConfig = {
  reactStrictMode: false,
  experimental: {
    viewTransition: true,
    authInterrupts: true,
    serverActions: {
      bodySizeLimit: '30mb',
    },
  },
} satisfies NextConfig;

export default nextConfig;
