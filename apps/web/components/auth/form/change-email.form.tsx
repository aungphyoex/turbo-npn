'use client';
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
import SubmitButton from '@repo/shadcn/submit-button';

const ChangeEmailForm = () => {
  return (
    <form className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Change Email</CardTitle>
          <CardDescription>
            Update your email to keep your account secure
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label isRequired htmlFor="current-email">
              Current Email
            </Label>
            <Input disabled name="email" id="current-email" type="email" />
          </div>
          <div className="space-y-2">
            <Label isRequired htmlFor="current-email">
              Verification Code
            </Label>
            <div className="flex justify-center items-center w-full gap-5">
              <Input disabled name="otp" id="current-otp" type="otp" />
              <Button disabled>Get OTP</Button>
            </div>
          </div>
          <div className="space-y-2">
            <Label isRequired htmlFor="new-email">
              New Email
            </Label>
            <Input disabled name="email" id="new-email" type="email" />
          </div>
        </CardContent>
        <CardFooter>
          <SubmitButton disabled isLoading={false} name="Change Email" />
        </CardFooter>
      </Card>
    </form>
  );
};

export default ChangeEmailForm;
