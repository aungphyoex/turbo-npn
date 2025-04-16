'use client';

import { signOutOtherDevice } from '@/server/auth.server';
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@repo/shadcn/alert-dialog';
import { Button } from '@repo/shadcn/button';
import { Loader2, LogOut } from '@repo/shadcn/lucide-react';
import { useAction } from 'next-safe-action/hooks';
import { useState } from 'react';

const SessionOtherLogout = ({ session_token }: { session_token: string }) => {
  const { executeAsync, isExecuting } = useAction(signOutOtherDevice);
  const [open, setOpen] = useState(false);
  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className="text-red-500 hover:text-red-600 hover:bg-red-50 dark:hover:bg-destructive dark:hover:text-white"
        >
          <LogOut className="h-4 w-4 mr-1" />
          Sign Out
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Sign out this device?</AlertDialogTitle>
          <AlertDialogDescription>
            The selected device will be signed out and will require sign-in
            again.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel asChild>
            <Button variant="ghost">Cancel</Button>
          </AlertDialogCancel>
          <Button
            disabled={isExecuting}
            variant="destructive"
            onClick={async () => {
              const result = await executeAsync({ session_token });
              if (result?.data) {
                setOpen(false);
              }
            }}
          >
            {isExecuting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Sign Out
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
};

export default SessionOtherLogout;
