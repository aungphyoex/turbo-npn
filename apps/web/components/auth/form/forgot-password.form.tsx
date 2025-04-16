'use client';

import { forgotPassword } from '@/server/auth.server';
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
import { useAction } from 'next-safe-action/hooks';
import Link from 'next/link';
import { ChangeEvent, useState } from 'react';

const ForgotPasswordForm = () => {
  const [formData, setFormData] = useState({
    identifier: '',
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
  } = useAction(forgotPassword);
  return (
    <div className={cn('flex flex-col gap-6')}>
      <Card>
        <CardHeader className="text-center">
          <CardTitle className="text-xl">Welcome back</CardTitle>
          <CardDescription className={cn(serverError && 'text-red-500')}>
            {serverError ?? 'Forgot your password'}
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
                    <Label htmlFor="identifier">Email or Username</Label>
                    <Input
                      name="identifier"
                      id="identifier"
                      placeholder="acme@example.com or your username"
                      onChange={handleChange}
                      autoFocus
                      required
                    />
                    {validationErrors?.identifier?._errors?.[0] && (
                      <p className="text-xs text-red-500">
                        {validationErrors.identifier._errors[0]}
                      </p>
                    )}
                  </div>
                  <SubmitButton
                    isLoading={isExecuting}
                    name={'Send Rest Code'}
                  />
                </div>
                <div className="text-center text-sm">
                  Back to{' '}
                  <Link
                    href={'/sign-in'}
                    className="underline underline-offset-4"
                  >
                    Sign In
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

export default ForgotPasswordForm;
