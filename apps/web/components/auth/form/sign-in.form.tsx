'use client';

import { signInWithCredentials } from '@/server/auth.server';
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

const SignInForm = () => {
  const [formData, setFormData] = useState({
    identifier: '',
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
  } = useAction(signInWithCredentials);
  return (
    <div className={cn('flex flex-col gap-6')}>
      <Card>
        <CardHeader className="text-center">
          <CardTitle className="text-xl">Welcome back</CardTitle>
          <CardDescription className={cn(serverError && 'text-red-500')}>
            {serverError ?? 'Sign In with your account'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-6">
            {/*<div className="flex flex-col gap-4">*/}
            {/*  <Button*/}
            {/*    onClick={async () => {*/}
            {/*      await signInWithOAuth('google');*/}
            {/*    }}*/}
            {/*    variant="outline"*/}
            {/*    className="w-full"*/}
            {/*  >*/}
            {/*    <IconBrandGoogleFilled stroke={2} />*/}
            {/*    Sign In with Google*/}
            {/*  </Button>*/}
            {/*</div>*/}
            {/*<div className="relative text-center text-sm after:absolute after:inset-0 after:top-1/2 after:z-0 after:flex after:items-center after:border-t after:border-border">*/}
            {/*  <span className="relative z-10 bg-background px-2 text-muted-foreground">*/}
            {/*    Or continue with*/}
            {/*  </span>*/}
            {/*</div>*/}
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
                      <Label htmlFor="password">Password</Label>
                      <Link
                        href={'/auth/forgot-password'}
                        className="ml-auto text-sm underline-offset-4 hover:underline"
                      >
                        Forgot your password?
                      </Link>
                    </div>
                    <Input
                      name="password"
                      id="password"
                      type="password"
                      onChange={handleChange}
                      required
                    />
                    {validationErrors?.password?._errors?.[0] && (
                      <p className="text-xs text-red-500">
                        {validationErrors.password._errors[0]}
                      </p>
                    )}
                  </div>
                  <SubmitButton isLoading={isExecuting} name={'Sign In'} />
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

export default SignInForm;
