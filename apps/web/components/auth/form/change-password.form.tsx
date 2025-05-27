'use client';
import PasswordValidErrors from '@/components/auth/form/password-valid-errors';
import { changePassword } from '@/server/auth.server';
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
import { cn } from '@repo/shadcn/lib/utils';
import { toast } from '@repo/shadcn/sonner';
import SubmitButton from '@repo/shadcn/submit-button';
import { useAction } from 'next-safe-action/hooks';
import { ChangeEvent, useState } from 'react';
const ChangePasswordForm = () => {
  const [formData, setFormData] = useState({
    password: '',
    newPassword: '',
    confirmNewPassword: '',
  });
  const {
    executeAsync,
    isExecuting,
    result: { validationErrors, serverError },
  } = useAction(changePassword);

  const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
    setFormData((prevState) => ({
      ...prevState,
      [event.target.name]: event.target.value,
    }));
  };
  return (
    <form
      onSubmit={async (event) => {
        event.preventDefault();
        const result = await executeAsync(formData);
        if (result?.data) {
          setFormData({
            password: '',
            newPassword: '',
            confirmNewPassword: '',
          });
          toast.success('Password changed successfully.', {
            position: 'top-right',
          });
        }
      }}
      className="space-y-6"
    >
      <Card>
        <CardHeader>
          <CardTitle>Change Password</CardTitle>
          <CardDescription className={cn(serverError && 'text-red-500')}>
            {serverError ?? 'Update your password to keep your account secure'}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label isRequired htmlFor="current-password">
              Current Password
            </Label>
            <Input
              disabled={isExecuting}
              onChange={handleChange}
              value={formData.password}
              name="password"
              id="current-password"
              type="password"
            />
            {validationErrors?.password?._errors?.[0] && (
              <p className="text-xs text-red-500">
                {validationErrors?.password?._errors?.[0]}
              </p>
            )}
          </div>

          <div className="space-y-2">
            <Label isRequired htmlFor="new-password">
              New Password
            </Label>
            <Input
              disabled={isExecuting}
              onChange={handleChange}
              value={formData.newPassword}
              name="newPassword"
              id="new-password"
              type="password"
            />
            {validationErrors?.newPassword?._errors?.[0] && (
              <p className="text-xs text-red-500">
                {validationErrors?.newPassword?._errors?.[0]}
              </p>
            )}
            <PasswordValidErrors password={formData.newPassword} />
          </div>

          <div className="space-y-2">
            <Label isRequired htmlFor="confirm-password">
              Confirm New Password
            </Label>
            <Input
              disabled={isExecuting}
              onChange={handleChange}
              value={formData.confirmNewPassword}
              name="confirmNewPassword"
              id="confirm-password"
              type="password"
            />
            {validationErrors?.confirmNewPassword?._errors?.[0] && (
              <p className="text-xs text-red-500">
                {validationErrors?.confirmNewPassword?._errors?.[0]}
              </p>
            )}
          </div>
        </CardContent>
        <CardFooter>
          <SubmitButton isLoading={isExecuting}>Update Password</SubmitButton>
        </CardFooter>
      </Card>
    </form>
  );
};

export default ChangePasswordForm;
