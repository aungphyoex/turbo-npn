import Providers from '@/components/providers';
import { cn } from '@repo/shadcn/lib/utils';
import '@repo/shadcn/shadcn.css';
import { Metadata } from 'next';
import localFont from 'next/font/local';
import { ReactNode } from 'react';

const GeistSans = localFont({
  src: './fonts/GeistVF.woff',
  variable: '--font-geist-sans',
});
const GeistMono = localFont({
  src: './fonts/GeistMonoVF.woff',
  variable: '--font-geist-mono',
});

export const metadata = {
  title: {
    default: 'Turbo NPN',
    template: '%s | Turbo NPN',
  },
} satisfies Metadata;

const RootLayout = ({
  children,
}: Readonly<{
  children: ReactNode;
}>) => (
  <html lang="en" suppressHydrationWarning>
    <body
      className={cn(GeistMono.variable, GeistSans.variable, 'antialiased')}
      suppressHydrationWarning
    >
      <Providers>{children}</Providers>
    </body>
  </html>
);

export default RootLayout;
