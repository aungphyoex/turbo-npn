'use client';

import { resetPassword } from '@/server/auth.server';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@repo/shadcn/card';
import { Input } from '@repo/shadcn/input';
import { Label } from '@repo/shadcn/label';
import { cn } from '@repo/shadcn/lib/utils';
import SubmitButton from '@repo/shadcn/submit-button';
import { Session } from 'next-auth';
import { useAction } from 'next-safe-action/hooks';
import Link from 'next/link';
import { ChangeEvent, useState } from 'react';

const ResetPasswordForm = ({ session }: { session: Session | null }) => {
  const [formData, setFormData] = useState({
    identifier: session?.user?.email ?? '',
    newPassword: '',
    resetToken: '',
  });
  const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
    setFormData((prevState) => ({
      ...prevState,
      [event.target.name]: event.target.value,
    }));
  };
  const {
    execute,
    isExecuting,
    result: { validationErrors, serverError },
  } = useAction(resetPassword);
  return (
    <div className={cn('flex flex-col gap-6')}>
      <Card>
        <CardHeader className="text-center">
          <CardTitle className="text-xl">Welcome back</CardTitle>
          <CardDescription className={cn(serverError && 'text-red-500')}>
            {serverError ?? 'Reset your password with your token'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-6">
            <form
              onSubmit={(event) => {
                event.preventDefault();
                execute(formData);
              }}
            >
              <div className="grid gap-6">
                <div className="grid gap-6">
                  <div className="grid gap-2">
                    <Label htmlFor="email">Email or Username</Label>
                    <Input
                      name="identifier"
                      id="email"
                      placeholder="acme@example.com or your username"
                      onChange={handleChange}
                      autoFocus
                      autoComplete="email"
                      required
                    />
                    {validationErrors?.identifier?._errors?.[0] && (
                      <p className="text-xs text-red-500">
                        {validationErrors.identifier._errors[0]}
                      </p>
                    )}
                  </div>
                  <div className="grid gap-2">
                    <div className="flex items-center">
                      <Label htmlFor="newPassword">New Password</Label>
                    </div>
                    <Input
                      name="newPassword"
                      id="newPassword"
                      type="password"
                      onChange={handleChange}
                      required
                    />
                    {validationErrors?.newPassword?._errors?.[0] && (
                      <p className="text-xs text-red-500">
                        {validationErrors.newPassword._errors[0]}
                      </p>
                    )}
                  </div>
                  <div className="grid gap-2">
                    <div className="flex items-center">
                      <Label htmlFor="resetToken">Enter your reset code</Label>
                    </div>
                    <Input
                      name="resetToken"
                      id="resetToken"
                      onChange={handleChange}
                      required
                    />
                    {validationErrors?.resetToken?._errors?.[0] && (
                      <p className="text-xs text-red-500">
                        {validationErrors.resetToken._errors[0]}
                      </p>
                    )}
                  </div>
                  <SubmitButton
                    isLoading={isExecuting}
                    name={'Reset Password'}
                  />
                </div>
                <div className="text-center text-sm">
                  Don&apos;t have an account?{' '}
                  <Link
                    href={'/auth/sign-up'}
                    className="underline underline-offset-4"
                  >
                    Sign up
                  </Link>
                </div>
              </div>
            </form>
          </div>
        </CardContent>
      </Card>
      <div className="text-balance text-center text-xs text-muted-foreground [&_a]:underline [&_a]:underline-offset-4 [&_a]:hover:text-primary  ">
        By clicking continue, you agree to our <a href="#">Terms of Service</a>{' '}
        and <a href="#">Privacy Policy</a>.
      </div>
    </div>
  );
};

export default ResetPasswordForm;
