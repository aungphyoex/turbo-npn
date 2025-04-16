'use client';

import { signOutAllDevice } from '@/server/auth.server';
import { Button } from '@repo/shadcn/button';
import { Loader2, LogOut } from '@repo/shadcn/lucide-react';
import { useAction } from 'next-safe-action/hooks';

const SessionAllLogout = () => {
  const { execute, isExecuting } = useAction(signOutAllDevice);
  return (
    <Button
      variant="outline"
      className="flex items-center gap-1"
      disabled={isExecuting}
      onClick={() => {
        execute();
      }}
    >
      {isExecuting ? (
        <Loader2 className="size-4 mr-1 animate-spin" />
      ) : (
        <LogOut className="h-4 w-4 mr-1" />
      )}
      Sign Out All Device
    </Button>
  );
};

export default SessionAllLogout;
