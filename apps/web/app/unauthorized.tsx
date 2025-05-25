'use client';
import { Button } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils';
import { RotateCw } from '@repo/shadcn/lucide-react';
import { useRouter } from 'next/navigation';
import { useTransition } from 'react';

const Unauthorized = () => {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  return (
    <div className="h-svh">
      <div className="m-auto flex h-full w-full flex-col items-center justify-center gap-2">
        <h1 className="text-[7rem] leading-tight font-bold">401</h1>
        <span className="font-medium">Unauthorized Access</span>
        <p className="text-muted-foreground text-center">
          {'You need to be logged in to access this page.'} <br />
          Please sign in and try again.
        </p>
        <div className="mt-6 flex gap-4">
          <Button
            onClick={() => {
              startTransition(() => {
                router.push('/auth/sign-in'); // You can change this to your login route
              });
            }}
          >
            <RotateCw className={cn('size-4', isPending && 'animate-spin')} />
            Go to Login
          </Button>
        </div>
      </div>
    </div>
  );
};

export default Unauthorized;
