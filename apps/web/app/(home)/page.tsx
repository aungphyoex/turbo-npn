import FollowCursor from '@repo/shadcn/follow-cursor';
import { cn } from '@repo/shadcn/lib/utils';
import { ModeSwitcher } from '@repo/shadcn/mode-switcher';
import { TrueFocus } from '@repo/shadcn/true-focus';
import { Montserrat } from 'next/font/google';
import Image from 'next/image';
import { TextureButton } from '@repo/shadcn/texture-button';
import { Button } from '@repo/shadcn/button';
import Link from 'next/link';

const RobotoMono = Montserrat({
  subsets: ['latin'],
  display: 'swap',
  weight: ['900'],
});

const Page = () => {
  return (
    <section className="bg-background min-h-dvh flex flex-col justify-center items-center">
      <FollowCursor />
      <nav className="container w-full flex justify-between items-center py-6">
        <Link href="/" className="flex items-center gap-1">
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
          <div>
            <h1
              className={cn(
                'text-xl font-black text-primary font-mono',
                RobotoMono.className,
              )}
            >
              Binary
              <span className="text-[#5b5b5b] dark:text-slate-400">Hubz</span>
            </h1>
          </div>
        </Link>
        <ModeSwitcher />
      </nav>
      <div className="flex-1 flex justify-center items-center flex-col gap-[90px]">
        <div className="flex justify-center items-center gap-2">
          <TextureButton variant="secondary" className="w-fit select-none">
            Click
          </TextureButton>
          <Button size="lg">
            Click
          </Button>
        </div>
      </div>
    </section>
  );
};

export default Page;
