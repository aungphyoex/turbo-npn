'use client';

import PasswordValidErrors from '@/components/auth/form/password-valid-errors';
import LogoIcon from '@/components/logo-icon';
import { signUpWithCredentials } from '@/server/auth.server';
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

const SignUpForm = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
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
  } = useAction(signUpWithCredentials);

  return (
    <div className={cn('w-full flex flex-col gap-6')}>
      <Card className="max-w-xl w-full mx-auto">
        <CardHeader className="text-center mb-7">
          <LogoIcon className="mb-3" />
          <CardTitle className="text-xl text-start">SignUp</CardTitle>
          <CardDescription
            className={cn('text-start', serverError && 'text-red-500')}
          >
            {serverError ?? 'Sign Up your account'}
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
                    <Label isRequired htmlFor="email">
                      Email
                    </Label>
                    <Input
                      name="email"
                      id="email"
                      type="email"
                      placeholder="acme@example.com"
                      onChange={handleChange}
                      autoFocus
                      autoComplete="email"
                      required
                    />
                    {validationErrors?.email?._errors?.[0] && (
                      <p className="text-xs text-red-500">
                        {validationErrors.email._errors[0]}
                      </p>
                    )}
                  </div>
                  <div className="grid gap-2">
                    <div className="flex items-center">
                      <Label isRequired htmlFor="password">
                        Password
                      </Label>
                    </div>
                    <Input
                      name="password"
                      id="password"
                      type="password"
                      onChange={handleChange}
                      required
                    />
                    <PasswordValidErrors password={formData.password} />
                    {validationErrors?.password?._errors?.[0] && (
                      <p className="text-xs text-red-500">
                        {validationErrors.password._errors[0]}
                      </p>
                    )}
                  </div>
                  <div className="text-sm">
                    Already have an account?{' '}
                    <Link
                      href={'/auth/sign-in'}
                      className="underline underline-offset-4"
                    >
                      Sign in
                    </Link>
                  </div>
                  <SubmitButton isLoading={isExecuting} name={'Sign Up'} />
                </div>
              </div>
            </form>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default SignUpForm;
