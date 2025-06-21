'use client';

import { signOutAllDevice } from '@/server/auth.server';
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
import { Loader2, LogOut } from '@repo/shadcn/lucide';
import { useAction } from 'next-safe-action/hooks';
import { useState } from 'react';

const SessionAllLogout = () => {
  const { executeAsync, isExecuting } = useAction(signOutAllDevice);
  const [open, setOpen] = useState(false);
  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>
        <Button
          variant="outline"
          className="text-red-500 hover:text-red-600 hover:bg-red-50 dark:hover:bg-destructive dark:hover:text-white"
        >
          <LogOut className="size-4 lg:size-5mr-1" />
          Sign Out All Devices
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Sign out all devices?</AlertDialogTitle>
          <AlertDialogDescription>
            All devices will be signed out and will require sign-in again.
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
            {isExecuting && (
              <Loader2 className="mr-2 size-4 lg:size-5animate-spin" />
            )}
            Sign Out
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
};

export default SessionAllLogout;
