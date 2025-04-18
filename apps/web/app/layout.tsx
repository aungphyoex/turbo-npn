import Providers from '@/components/providers';
import { cn } from '@repo/shadcn/lib/utils';
import '@repo/shadcn/shadcn.css';
import { Metadata } from 'next';
import { Inter } from 'next/font/google';
import { ReactNode } from 'react';

const inter = Inter({
  subsets: ['latin'],
  display: 'auto',
  variable: '--font-inter',
  weight: ['400', '500', '600', '700', '800', '900'],
});

export const metadata = {
  metadataBase: new URL('https://turbo-npn.onrender.com'),
  title: {
    default: 'Turbo NPN',
    template: '%s | Turbo NPN',
  },
  openGraph: {
    type: 'website',
    title: 'Turbo NPN',
    description: 'Turbo NPN is the name of the website',
    url: 'https://turbo-npn.onrender.com',
    images: [
      {
        url: '/og-bg.png',
        width: 1200,
        height: 628,
        alt: 'Turbo NPN Logo',
      },
    ],
  },
} satisfies Metadata;

const RootLayout = async ({
  children,
}: Readonly<{
  children: ReactNode;
}>) => {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={cn('antialiased', inter.variable)}
        suppressHydrationWarning
      >
        <Providers>{children}</Providers>
      </body>
    </html>
  );
};

export default RootLayout;
