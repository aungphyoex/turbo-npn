import NotFound from '@/app/not-found';
import { getUser } from '@/server/user.server';
import { Card, CardHeader, CardTitle } from '@repo/shadcn/card';

const Page = async ({ params }: { params: Promise<{ username: string }> }) => {
  const { username } = await params;
  const user = await getUser(username);
  console.log(user);
  if (!user) {
    return <NotFound />;
  }
  return (
    <div>
      <Card className="mx-auto">
        <CardHeader>
          <CardTitle>Profile</CardTitle>
        </CardHeader>
      </Card>
    </div>
  );
};

export default Page;
