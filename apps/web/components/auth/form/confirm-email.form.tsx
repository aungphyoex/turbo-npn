'use client';

import { confirmEmail } from '@/server/auth.server';
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
import { ChangeEvent, useState } from 'react';

const ConfirmEmailForm = ({ session }: { session: Session | null }) => {
  const [formData, setFormData] = useState({
    email: session?.user.email ?? '',
    token: '',
  });
  const {
    executeAsync,
    isExecuting,
    result: { validationErrors, serverError, bindArgsValidationErrors, data },
  } = useAction(confirmEmail);
  const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
    setFormData((prevState) => ({
      ...prevState,
      [event.target.name]: event.target.value,
    }));
  };
  console.log(serverError, validationErrors, bindArgsValidationErrors, data);
  return (
    <div className={cn('flex flex-col gap-6')}>
      <Card>
        <CardHeader className="text-center">
          <CardTitle className="text-xl">Welcome back</CardTitle>
          <CardDescription className={cn(serverError && 'text-red-500')}>
            {serverError ?? 'Confirm your email'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-6">
            <form
              onSubmit={async (event) => {
                event.preventDefault();
                await executeAsync(formData);
              }}
            >
              <div className="grid gap-6">
                <div className="grid gap-2">
                  <div className="flex items-center">
                    <Label htmlFor="token">Enter your verification code</Label>
                  </div>
                  <Input
                    name="token"
                    id="token"
                    onChange={handleChange}
                    required
                  />
                  {validationErrors?.token?._errors?.[0] && (
                    <p className="text-xs text-red-500">
                      {validationErrors.token._errors[0]}
                    </p>
                  )}
                </div>
                <SubmitButton isLoading={isExecuting} name={'Confirm email'} />
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

export default ConfirmEmailForm;
