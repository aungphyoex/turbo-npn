'use client';

import { Button } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils';
import { RotateCw } from '@repo/shadcn/lucide-react';
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
    <div className="w-full flex flex-col min-h-dvh gap-9 items-center justify-center">
      <p className="font-semibold">
        Oh no, something went wrong... maybe refresh?
      </p>
      <Button
        onClick={() => {
          startTransition(() => {
            reset();
            router.refresh();
          });
        }}
      >
        Try Again
        <RotateCw className={cn('size-5', isPending && 'animate-spin')} />
      </Button>
    </div>
  );
};

export default Error;
