import { ModeSwitcher } from '@repo/shadcn/mode-switcher';
import Image from 'next/image';
import { Montserrat, Roboto_Mono } from 'next/font/google';
import { cn } from '@repo/shadcn/lib/utils';

const RobotoMono = Montserrat({
  subsets: ['latin'],
  display: 'swap',
  weight: ["900"],
})

const Page = () => {
  return (
    <section className="bg-background min-h-dvh flex flex-col justify-center items-center">
      <nav className="container w-full flex justify-between items-center py-6">
        <div className="flex items-center gap-1">
          <Image
            src={'/icon.png'}
            alt={'Image'}
            className="rounded-full block dark:hidden select-none"
            width={35}
            height={35}
          />
          <Image
            src={'/icon-2.png'}
            alt={'Image'}
            className="rounded-full hidden dark:block select-none"
            width={35}
            height={35}
          />
          <h1 className={cn("text-xl font-black text-primary font-mono", RobotoMono.className)}>
            Binary
            <span className="text-[#5b5b5b]">Hubz</span>
          </h1>
        </div>
        <ModeSwitcher />
      </nav>
      <div className="flex-1"></div>
    </section>
  );
};

export default Page;
