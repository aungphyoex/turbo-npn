import { formatDate } from '@repo/utils';

const Page = () => {
  return (
    <section className="min-h-dvh flex flex-col justify-center items-center">
      Hello world
      <span>
        {formatDate(new Date())}
      </span>
    </section>
  );
};

export default Page;
