import NotFound from '@/app/not-found';
import { auth } from '@/auth';
import BackNavigation from '@/components/back-navigation';
import AppearanceSettings from '@/components/profile/appearance-settings';
import GeneralSettings from '@/components/profile/general-settings';
import ProfileHeader from '@/components/profile/profile-header';
import ProfileSidebar from '@/components/profile/profile-sidebar';
import SecuritySettings from '@/components/profile/security-settings';
import SessionsSettings from '@/components/profile/sessions-settings';
import { getUser } from '@/server/user.server';
import { Card, CardContent, CardHeader, CardTitle } from '@repo/shadcn/card';
import { Tabs, TabsContent } from '@repo/shadcn/tabs';
import { cookies } from 'next/headers';

const Page = async ({
  params,
}: {
  params: Promise<{
    username: string;
  }>;
}) => {
  const { username } = await params;
  const session = await auth();
  const user = await getUser(username);
  const cookie = await cookies();
  const select_font = cookie?.get('select-font')?.value ?? '--font-geist';

  if (!user) {
    return <NotFound />;
  }
  return (
    <section className="min-h-screen bg-background">
      <BackNavigation />
      <div className="bg-background shadow">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
          <ProfileHeader user={user} />
        </div>
      </div>
      <Tabs
        defaultValue="profile"
        className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-6"
      >
        <div className="w-full flex flex-col md:flex-row gap-6">
          {session?.user && session.user.username === username && (
            <div className="w-full md:w-1/4">
              <ProfileSidebar />
            </div>
          )}
          <TabsContent value="profile">
            <Card className="mx-auto">
              <CardHeader>
                <CardTitle>Profile</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <h2>
                  {user.username} is a user on {user.profile.name}
                </h2>
                <hr />
                <h3>Email: {user.email}</h3>
                <h4>Is Verified: {user.isEmailVerified ? 'Yes' : 'No'}</h4>
              </CardContent>
            </Card>
          </TabsContent>
          <TabsContent value="general">
            <GeneralSettings />
          </TabsContent>
          <TabsContent value="security">
            <SecuritySettings />
          </TabsContent>
          <TabsContent value="sessions">
            <SessionsSettings />
          </TabsContent>
          <TabsContent value="appearance">
            <AppearanceSettings select_font={select_font} />
          </TabsContent>
        </div>
      </Tabs>
    </section>
  );
};

export default Page;
