import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@repo/shadcn/accordion';
import { Button } from '@repo/shadcn/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@repo/shadcn/card';
import { Input } from '@repo/shadcn/input';
import { Label } from '@repo/shadcn/label';
import { ModeSwitcher } from '@repo/shadcn/mode-switcher';
import Image from 'next/image';

const Page = () => {
  return (
    <section className="bg-background min-h-dvh flex flex-col justify-center items-center">
      <nav className="container w-full flex justify-between items-center py-6">
        <div className="flex items-center gap-1">
          <Image
            src={'/icon.png'}
            alt={'Image'}
            className="rounded-full block dark:hidden select-none"
            width={35}
            height={35}
          />
          <Image
            src={'/icon-2.png'}
            alt={'Image'}
            className="rounded-full hidden dark:block select-none"
            width={35}
            height={35}
          />
          <h1 className="text-lg font-black text-primary font-mono">Binary</h1>
        </div>
        <ModeSwitcher />
      </nav>
      <div className="flex-1 w-full flex flex-col justify-center items-center">
        <div className="max-w-lg w-full flex items-center gap-2">
          <Input />
          <Button>Submit</Button>
        </div>

        <div className="max-w-lg w-full mt-16 flex justify-center items-center">
          <Card className="w-[350px]">
            <CardHeader>
              <CardTitle>Create project</CardTitle>
              <CardDescription>
                Deploy your new project in one-click.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form>
                <div className="grid w-full items-center gap-4">
                  <div className="flex flex-col space-y-1.5">
                    <Label htmlFor="name">Name</Label>
                    <Input id="name" placeholder="Name of your project" />
                  </div>
                </div>
              </form>
            </CardContent>
            <CardFooter className="flex justify-between">
              <Button variant="outline">Cancel</Button>
              <Button>Deploy</Button>
            </CardFooter>
          </Card>
        </div>

        <div className="max-w-lg w-full mt-16">
          <Accordion type="single" collapsible className="w-full">
            <AccordionItem value="item-1">
              <AccordionTrigger>Is it accessible?</AccordionTrigger>
              <AccordionContent>
                Yes. It adheres to the WAI-ARIA design pattern.
              </AccordionContent>
            </AccordionItem>
            <AccordionItem value="item-2">
              <AccordionTrigger>Is it styled?</AccordionTrigger>
              <AccordionContent>
                Yes. It comes with default styles that matches the other
                components&apos; aesthetic.
              </AccordionContent>
            </AccordionItem>
            <AccordionItem value="item-3">
              <AccordionTrigger>Is it animated?</AccordionTrigger>
              <AccordionContent>
                Yes. It animated by default, but you can disable it if you
                prefer.
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </div>
      </div>
    </section>
  );
};

export default Page;
