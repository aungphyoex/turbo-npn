'use client';

import LogoIcon from '@/components/logo-icon';
import { confirmEmail } from '@/server/auth.server';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@repo/shadcn/card';
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
  REGEXP_ONLY_DIGITS,
} from '@repo/shadcn/input-otp';
import { cn } from '@repo/shadcn/lib/utils';
import SubmitButton from '@repo/shadcn/submit-button';
import { Session } from 'next-auth';
import { useAction } from 'next-safe-action/hooks';
import { useState } from 'react';

const ConfirmEmailForm = ({ session }: { session: Session | null }) => {
  const [formData, setFormData] = useState({
    email: session?.user.email ?? '',
    token: '',
  });
  const {
    executeAsync,
    isExecuting,
    result: { validationErrors, serverError },
  } = useAction(confirmEmail);
  return (
    <div className={cn('w-full flex flex-col gap-6')}>
      <Card className="max-w-xl w-full mx-auto rounded-none">
        <CardHeader className="text-center mb-7">
          <LogoIcon className="mb-3" />
          <CardTitle className="text-xl text-start">Confirm Email</CardTitle>
          <CardDescription
            className={cn('text-start', serverError && 'text-red-500')}
          >
            {serverError ?? 'Enter your verification code'}
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
                <div className="grid gap-2 place-items-center">
                  <InputOTP
                    className="w-full"
                    autoFocus
                    onChange={(token) => {
                      setFormData((prevState) => ({
                        ...prevState,
                        token,
                      }));
                    }}
                    maxLength={6}
                    minLength={6}
                    pattern={REGEXP_ONLY_DIGITS}
                  >
                    <InputOTPGroup className="w-full grid grid-cols-6 gap-5">
                      <InputOTPSlot
                        className="w-full h-10  rounded-xl first:rounded-xl last:rounded-xl border"
                        index={0}
                      />
                      <InputOTPSlot
                        className="w-full h-10  rounded-xl first:rounded-xl last:rounded-xl border"
                        index={1}
                      />
                      <InputOTPSlot
                        className="w-full h-10  rounded-xl first:rounded-xl last:rounded-xl border"
                        index={2}
                      />
                      <InputOTPSlot
                        className="w-full h-10  rounded-xl first:rounded-xl last:rounded-xl border"
                        index={3}
                      />
                      <InputOTPSlot
                        className="w-full h-10  rounded-xl first:rounded-xl last:rounded-xl border"
                        index={4}
                      />
                      <InputOTPSlot
                        className="w-full h-10  rounded-xl first:rounded-xl last:rounded-xl border"
                        index={5}
                      />
                    </InputOTPGroup>
                  </InputOTP>
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
    </div>
  );
};

export default ConfirmEmailForm;
