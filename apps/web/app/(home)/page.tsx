import { Montserrat } from 'next/font/google';

const RobotoMono = Montserrat({
  subsets: ['latin'],
  display: 'swap',
  weight: ['900'],
});

const Page = () => {
  return (
    <section className="bg-background min-h-dvh flex flex-col justify-center items-center">
      Hello world
    </section>
  );
};

export default Page;
