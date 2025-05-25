import { auth } from '@/auth';
import LogoIcon from '@/components/logo-icon';
import Session from '@/components/session';
import { Button } from '@repo/shadcn/button';
import { ModeSwitcher } from '@repo/shadcn/mode-switcher';
import Link from 'next/link';

const Page = async () => {
  const session = await auth();
  return (
    <section className="min-h-dvh container flex flex-col">
      <nav className="w-full flex justify-between items-center py-5">
        <Link href="/">
          <LogoIcon width={30} height={30} />
        </Link>
        <ModeSwitcher />
        <Session />
      </nav>
      <div className="flex flex-1 flex-col w-full justify-center items-center gap-5">
        <h2>Welcome to the Turborepo</h2>
        <p>This is a monorepo for a Next.js app and a React library.</p>
        {session?.user && (
          <div className=" flex-col flex justify-center items-center gap-5">
            <p>You are logged in as {session?.user.email}</p>
            <Button asChild>
              <Link href={`/${session?.user.username}`}>Your Profile</Link>
            </Button>
          </div>
        )}
      </div>
    </section>
  );
};

export default Page;
