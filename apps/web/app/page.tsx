import { Button } from '@repo/ui/button';
import { Loader2 } from '@repo/ui/icon';
import { Input } from '@repo/ui/input';

const Page = () => {
  return (
    <section className="min-h-dvh flex flex-col justify-center items-center">
      <div className="max-w-lg w-full">
        <h1 className="text-primary text-lg font-semibold mb-6">
          Subscribe now to get update information:
        </h1>
        <Input />
        <div className="mt-5 flex justify-end items-center">
          <Button className="cursor-pointer">
            Submit
            <Loader2 className="size-5 animate-spin" />
          </Button>
        </div>
      </div>
    </section>
  );
};

export default Page;
