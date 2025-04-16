'use client';

import { signOutCurrentDevice } from '@/server/auth.server';
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

const SignOut = () => {
  const { executeAsync, isExecuting } = useAction(signOutCurrentDevice);
  const [open, setOpen] = useState(false);
  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>
        <Button
          className="w-full justify-start text-red-500 hover:text-red-600 hover:bg-red-50 dark:hover:bg-destructive dark:hover:text-white"
          variant="ghost"
        >
          <LogOut className="mr-2 h-4 w-4" />
          Sign Out
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Log out?</AlertDialogTitle>
          <AlertDialogDescription>
            You’ll need to sign in again to access your account.
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
              const result = await executeAsync();
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

export default SignOut;
