'use client';

import { Button } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils';
import { RotateCw } from '@repo/shadcn/lucide';
import { useRouter } from 'next/navigation';
import { useEffect, useTransition } from 'react';

const Error = ({ error, reset }: { error: Error; reset: () => void }) => {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  useEffect(() => {
    // Log the error to an error reporting service
    console.error(error);
  }, [error]);

  return (
    <div className="h-svh">
      <div className="m-auto flex h-full w-full flex-col items-center justify-center gap-2">
        {/*<h1 className="text-[7rem] leading-tight font-bold">Error {error.message}</h1>*/}
        <span className="font-medium">Something went wrong</span>
        <p className="text-muted-foreground text-center">
          {'An unexpected error occurred.'}
          ... may be refresh
        </p>
        <div className="mt-6 flex gap-4">
          <Button
            onClick={() => {
              startTransition(() => {
                reset();
                router.refresh();
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

export default Error;
