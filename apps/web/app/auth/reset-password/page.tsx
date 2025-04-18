import { auth } from '@/auth';
import ResetPasswordForm from '@/components/auth/form/reset-password.form';

export default async function ResetPasswordPage() {
  const session = await auth();
  return (
    <div className="flex min-h-screen items-center justify-center container">
      <ResetPasswordForm session={session} />
    </div>
  );
}
