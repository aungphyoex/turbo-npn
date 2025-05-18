'use client';

import type React from 'react';

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
import { useState } from 'react';

export default function GeneralSettings() {
  const session = useSession({
    required: true,
  });
  const [userData, setUserData] = useState({
    name: session?.data?.user.name ?? '',
    email: session?.data?.user.email ?? '',
    username: session?.data?.user.username ?? '',
  });

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>,
  ) => {
    const { name, value } = e.target;
    setUserData((prev) => ({ ...prev, [name]: value }));
  };

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
          <Button disabled variant="destructive">
            Delete Account
          </Button>
        </CardFooter>
      </Card>
    </div>
  );
}
