'use client';

import LogoIcon from '@/components/logo-icon';
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
    <div className={cn('w-full flex flex-col gap-6')}>
      <Card className="max-w-xl w-full mx-auto">
        <CardHeader className="text-center mb-7">
          <LogoIcon className="mb-3" />
          <CardTitle className="text-xl text-start">Forgot Password</CardTitle>
          <CardDescription
            className={cn('text-start', serverError && 'text-red-500')}
          >
            {serverError ?? 'Forgot your password with your email'}
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
                    <Label isRequired htmlFor="identifier">
                      Email
                    </Label>
                    <Input
                      name="identifier"
                      id="identifier"
                      placeholder="acme@example.com"
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
                  <div className="text-sm">
                    Back to{' '}
                    <Link
                      href={'/auth/sign-in'}
                      className="underline underline-offset-4"
                    >
                      Sign In
                    </Link>
                  </div>
                  <SubmitButton
                    isLoading={isExecuting}
                    name={'Send Rest Code'}
                  />
                </div>
              </div>
            </form>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default ForgotPasswordForm;
