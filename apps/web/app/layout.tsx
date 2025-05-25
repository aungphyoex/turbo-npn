import Providers from '@/components/providers';
import { APP_NAME, APP_URL } from '@repo/constants/app';
import { cn } from '@repo/shadcn/lib/utils';
import '@repo/shadcn/shadcn.css';
import { Metadata } from 'next';
import { JetBrains_Mono } from 'next/font/google';
import { ReactNode } from 'react';

const jetBrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-jetbrains',
  weight: ['400', '500', '600', '700', '800'],
});

export const metadata = {
  metadataBase: new URL(APP_URL),
  title: {
    default: APP_NAME,
    template: `%s | ${APP_NAME}`,
  },
  description:
    'Turbo NPN is the next-generation social platform where you connect, share, and discover in real time. Join the conversation and stay in the loop with what matters most to you.',
  keywords: [
    APP_NAME,
    'social media platform',
    'real-time updates',
    'microblogging app',
    'trending topics',
    'community engagement',
    'follow creators',
    'Myanmar social app',
    'connect with friends',
    'share thoughts',
    'post updates',
    'live conversations',
    'digital community',
    'social network Myanmar',
  ],
  alternates: {
    canonical: '/',
  },
  openGraph: {
    type: 'website',
    title: APP_NAME,
    description:
      'Join Turbo NPN to connect with your world. Share moments, follow trending topics, and be part of a real-time conversation.',
    url: APP_URL,
    locale: 'en-US',
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-video-preview': -1,
      'max-image-preview': 'large',
      'max-snippet': -1,
    },
  },
  twitter: {
    card: 'summary_large_image',
    title: APP_NAME,
    description:
      'Turbo NPN — the real-time social network for discovering, sharing, and connecting across Myanmar and beyond.',
  },
  verification: {
    google: 'your-google-verification-token',
  },
  icons: {
    icon: '/metadata/favicon.ico',
    shortcut: '/metadata/favicon-16x16.png',
    apple: '/metadata/apple-touch-icon.png',
  },
  manifest: '/metadata/site.webmanifest',
} satisfies Metadata;

const RootLayout = async ({
  children,
}: Readonly<{
  children: ReactNode;
}>) => {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={cn('antialiased', jetBrainsMono.variable)}
        suppressHydrationWarning
      >
        <Providers>{children}</Providers>
      </body>
    </html>
  );
};

export default RootLayout;
