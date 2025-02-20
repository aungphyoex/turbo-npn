import { ThemeProvider } from '@repo/shadcn/themes-provider';
import { NuqsAdapter } from 'nuqs/adapters/next/app';
import { ReactNode } from 'react';

type ProvidersProps = {
  children: ReactNode;
};
const Providers = ({ children }: Readonly<ProvidersProps>) => {
  return (
    <ThemeProvider
      attribute="class"
      defaultTheme="system"
      enableSystem
      disableTransitionOnChange={false}
    >
      <NuqsAdapter>{children}</NuqsAdapter>
    </ThemeProvider>
  );
};

export default Providers;
