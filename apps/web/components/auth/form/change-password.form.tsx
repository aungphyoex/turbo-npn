'use client';
import PasswordValidErrors from '@/components/auth/form/password-valid-errors';
import { changePassword } from '@/server/auth.server';
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
import { Loader2 } from '@repo/shadcn/lucide-react';
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
        }
      }}
      className="space-y-6"
    >
      <Card>
        <CardHeader>
          <CardTitle>Change Password</CardTitle>
          <CardDescription>
            Update your password to keep your account secure
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label isRequired htmlFor="current-password">
              Current Password
            </Label>
            <Input
              onChange={handleChange}
              name="password"
              id="current-password"
              type="password"
            />
            {serverError && (
              <p className="text-xs text-red-500">{serverError}</p>
            )}
          </div>

          <div className="space-y-2">
            <Label isRequired htmlFor="new-password">
              New Password
            </Label>
            <Input
              onChange={handleChange}
              name="newPassword"
              id="new-password"
              type="password"
            />
            <PasswordValidErrors password={formData.newPassword} />
            {validationErrors?.newPassword?._errors?.[0] && (
              <p className="text-xs text-red-500">
                {validationErrors?.newPassword?._errors?.[0]}
              </p>
            )}
          </div>

          <div className="space-y-2">
            <Label isRequired htmlFor="confirm-password">
              Confirm New Password
            </Label>
            <Input
              onChange={handleChange}
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
          <Button disabled={isExecuting} type="submit">
            {isExecuting && <Loader2 className="size4 animate-spin mr-2" />}{' '}
            Update Password
          </Button>
        </CardFooter>
      </Card>
    </form>
  );
};

export default ChangePasswordForm;
