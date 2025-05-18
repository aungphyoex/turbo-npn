'use client';
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
import { AlertCircle, CheckCircle2, Loader2 } from '@repo/shadcn/lucide-react';
import { useAction } from 'next-safe-action/hooks';
import { ChangeEvent, useState } from 'react';

const ChangeEmailForm = () => {
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
      <Card className="rounded-none">
        <CardHeader>
          <CardTitle>Change Email</CardTitle>
          <CardDescription>
            Update your email to keep your account secure
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
            {validationErrors?.newPassword?._errors?.[0] && (
              <p className="text-xs text-red-500">
                {validationErrors?.newPassword?._errors?.[0]}
              </p>
            )}
            <div className="text-sm space-y-2 mt-2">
              <p className="font-medium">Password requirements:</p>
              <ul className="space-y-1">
                <li className="flex items-center text-green-600">
                  <CheckCircle2 className="h-4 w-4 mr-2" />
                  <span>At least 8 characters</span>
                </li>
                <li className="flex items-center text-green-600">
                  <CheckCircle2 className="h-4 w-4 mr-2" />
                  <span>At least one uppercase letter</span>
                </li>
                <li className="flex items-center text-red-500">
                  <AlertCircle className="h-4 w-4 mr-2" />
                  <span>At least one number</span>
                </li>
                <li className="flex items-center text-red-500">
                  <AlertCircle className="h-4 w-4 mr-2" />
                  <span>At least one special character</span>
                </li>
              </ul>
            </div>
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

export default ChangeEmailForm;
