import Providers from '@/components/providers';
import { metadata } from '@/lib';
import '@repo/ui/globals.css';
import { cn } from '@repo/ui/lib/utils';
import { Poppins } from 'next/font/google';

const font_poppins = Poppins({
  weight: ['400', '500', '600', '700', '800', '900'],
  subsets: ['latin'],
  display: 'auto',
});

export const generateMetadata = async () => {
  return metadata;
};

const RootLayout = ({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) => (
  <html lang="en" suppressHydrationWarning>
    <body
      className={cn(font_poppins.className, 'antialiased')}
      suppressHydrationWarning
    >
      <Providers>{children}</Providers>
    </body>
  </html>
);

export default RootLayout;
