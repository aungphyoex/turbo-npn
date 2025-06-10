'use client';

import type React from 'react';

import { deleteAccount } from '@/server/auth.server';
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
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@repo/shadcn/card';
import { Input } from '@repo/shadcn/input';
import { Label } from '@repo/shadcn/label';
import { useSession } from 'next-auth/react';
import { useAction } from 'next-safe-action/hooks';
import { useState } from 'react';

export default function GeneralSettings() {
  const session = useSession({
    required: true,
  });
  const [userData, setUserData] = useState({
    name: session?.data?.user?.profile?.name ?? '',
    email: session?.data?.user.email ?? '',
    username: session?.data?.user.username ?? '',
  });

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>,
  ) => {
    const { name, value } = e.target;
    setUserData((prev) => ({ ...prev, [name]: value }));
  };

  const [password, setPassword] = useState('');
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const {
    executeAsync,
    isExecuting,
    result: { data, validationErrors, serverError },
  } = useAction(deleteAccount);
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>General Account Settings</CardTitle>
          <CardDescription>
            Update your basic profile information
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="">
            <div className="space-y-2">
              <Label htmlFor="name">Name</Label>
              <Input
                disabled
                id="name"
                name="name"
                value={userData.name}
                onChange={handleChange}
              />
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="email">Email Address</Label>
            <Input
              disabled
              id="email"
              name="email"
              type="email"
              value={userData.email}
              onChange={handleChange}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="username">Username</Label>
            <Input
              disabled
              id="username"
              name="username"
              value={userData.username}
              onChange={handleChange}
            />
          </div>
        </CardContent>
        <CardFooter>
          <Button disabled>Save Changes</Button>
        </CardFooter>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Delete Account</CardTitle>
          <CardDescription>
            Permanently delete your account and all of your content
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Once you delete your account, there is no going back. Please be
            certain.
          </p>
        </CardContent>
        <CardFooter>
          <AlertDialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
            <AlertDialogTrigger asChild>
              <Button variant="destructive">Delete Account</Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Delete your account?</AlertDialogTitle>
                <AlertDialogDescription>
                  This action is permanent and will remove all your personal
                  information, settings, and associated data from our system.
                  You will not be able to recover your account after this
                  action.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <Input
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                type="password"
                placeholder="Enter your account password"
              />
              {(validationErrors?.password || serverError) && (
                <p className="text-sm text-red-500">
                  {serverError || validationErrors?.password?._errors?.[0]}
                </p>
              )}
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <Button
                  disabled={isExecuting}
                  onClick={async () => {
                    const data = await executeAsync({
                      password,
                    });
                    console.log(data);
                  }}
                >
                  {isExecuting && '...'}
                  Yes, delete my account
                </Button>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </CardFooter>
      </Card>
    </div>
  );
}
