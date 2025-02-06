import { getUsers } from '@/server/home.server';

const Page = async () => {
  const users = await getUsers();
  console.log(users);
  return <div>HomePage</div>;
};

export default Page;
