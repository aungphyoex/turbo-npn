'use client';
import { Button } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils';
import { RotateCw } from '@repo/shadcn/lucide-react';
import { useRouter } from 'next/navigation';
import { useTransition } from 'react';

const Forbidden = () => {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  return (
    <div className="h-svh">
      <div className="m-auto flex h-full w-full flex-col items-center justify-center gap-2">
        <h1 className="text-[7rem] leading-tight font-bold">403</h1>
        <span className="font-medium">Access Denied!</span>
        <p className="text-muted-foreground text-center">
          {"You don't have permission to access this page."} <br />
          Please contact the administrator if you believe this is a mistake.
        </p>
        <div className="mt-6 flex gap-4">
          <Button
            onClick={() => {
              startTransition(() => {
                router.push('/');
              });
            }}
          >
            <RotateCw className={cn('size-4', isPending && 'animate-spin')} />
            Back to Home
          </Button>
        </div>
      </div>
    </div>
  );
};

export default Forbidden;
