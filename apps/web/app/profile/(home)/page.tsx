import { auth } from '@/auth';
import GeneralSettings from '@/components/profile/general-settings';

const Page = async () => {
  const session = await auth();
  return (
    <div>
      <GeneralSettings session={session} />
    </div>
  );
};

export default Page;
