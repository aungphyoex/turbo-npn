import Providers from '@/components/providers';
import { APP_NAME, APP_URL } from '@repo/constants/app';
import { cn } from '@repo/shadcn/lib/utils';
import { Metadata } from 'next';
import { Geist, Geist_Mono, Roboto, Roboto_Mono } from 'next/font/google';
import { ReactNode } from 'react';

/** Tailwindcss **/
import '@repo/shadcn/shadcn.css';
import { Toaster } from '@repo/shadcn/sonner';
import { cookies } from 'next/headers';

const geist = Geist({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700', '800', '900'],
  variable: '--font-geist',
});

const geist_mono = Geist_Mono({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700', '800', '900'],
  variable: '--font-geist-mono',
});

const roboto = Roboto({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700', '800', '900'],
  variable: '--font-roboto',
});

const roboto_mono = Roboto_Mono({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
  variable: '--font-roboto-mono',
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
  const cookie = await cookies();
  const select_font = cookie.get('select-font')?.value ?? '--font-geist';
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={cn(
          'antialiased tracking-normal leading-normal',
          geist.variable,
          geist_mono.variable,
          roboto.variable,
          roboto_mono.variable,
        )}
        style={{
          fontFamily: `var(${select_font})`,
        }}
        suppressHydrationWarning
      >
        <Providers>{children}</Providers>
        <Toaster />
      </body>
    </html>
  );
};

export default RootLayout;
