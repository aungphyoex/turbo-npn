import { Button } from '@repo/shadcn/button';
import { ChevronLeft } from '@repo/shadcn/lucide';
import Link from 'next/link';
const BackNavigation = () => {
  return (
    <header className="bg-background max-w-6xl mx-auto py-4 px-4 sm:px-6 lg:px-8">
      <Button asChild variant="ghost" className="group">
        <Link href="/">
          <ChevronLeft className="size-5 group-hover:-translate-x-2 transition-transform duration-500" />
          Home
        </Link>
      </Button>
    </header>
  );
};

export default BackNavigation;
