import { auth } from '@/auth';
import ConfirmEmailForm from '@/components/auth/form/confirm-email.form';

const Page = async () => {
  const session = await auth();
  return (
    <div className="min-h-dvh container flex justify-center items-center">
      <ConfirmEmailForm session={session} />
    </div>
  );
};

export default Page;
