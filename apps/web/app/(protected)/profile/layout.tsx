import ProfileHeader from '@/components/profile/profile-header';
import ProfileSidebar from '@/components/profile/profile-sidebar';
import { PropsWithChildren } from 'react';

const Layout = async ({ children }: PropsWithChildren) => {
  return (
    <section className="min-h-screen bg-background">
      <div className="bg-background shadow">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
          <ProfileHeader />
        </div>
      </div>

      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <div className="flex flex-col md:flex-row gap-6">
          <div className="w-full md:w-1/4">
            <ProfileSidebar />
          </div>

          <div className="w-full md:w-3/4">{children}</div>
        </div>
      </div>
    </section>
  );
};

export default Layout;
