import Session from '@/components/session';
import { ModeSwitcher } from '@repo/shadcn/mode-switcher';

const Page = () => {
  return (
    <section className="min-h-dvh container">
      <nav className="flex justify-between items-center py-2">
        <h1 className="font-semibold">Turborepo</h1>
        <ModeSwitcher />
        <Session />
      </nav>
    </section>
  );
};

export default Page;
