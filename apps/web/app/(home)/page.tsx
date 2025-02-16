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

const Page = () => {
  return (
    <section className="bg-background min-h-dvh flex flex-col justify-center items-center">
      <nav className="container w-full flex justify-between items-center py-6">
        <svg
          className="size-9"
          viewBox="0 0 256 318"
          width="1em"
          height="1em"
          xmlns="http://www.w3.org/2000/svg"
          preserveAspectRatio="xMidYMid"
        >
          <defs>
            <linearGradient
              x1="123.779%"
              y1="0%"
              x2="123.779%"
              y2="698.962%"
              id="a"
            >
              <stop stopColor="#1E90FF" offset="0%" />
              <stop stopColor="#FF1E56" offset="100%" />
            </linearGradient>
            <linearGradient
              x1="11.486%"
              y1="-2.194%"
              x2="11.486%"
              y2="512.398%"
              id="b"
            >
              <stop stopColor="#1E90FF" offset="0%" />
              <stop stopColor="#FF1E56" offset="100%" />
            </linearGradient>
            <linearGradient
              x1="-153.743%"
              y1="-62.263%"
              x2="-153.743%"
              y2="278.479%"
              id="c"
            >
              <stop stopColor="#1E90FF" offset="0%" />
              <stop stopColor="#FF1E56" offset="100%" />
            </linearGradient>
            <linearGradient
              x1="-153.743%"
              y1="-178.48%"
              x2="-153.743%"
              y2="162.264%"
              id="d"
            >
              <stop stopColor="#1E90FF" offset="0%" />
              <stop stopColor="#FF1E56" offset="100%" />
            </linearGradient>
            <linearGradient
              x1="11.486%"
              y1="-412.397%"
              x2="11.486%"
              y2="102.194%"
              id="e"
            >
              <stop stopColor="#1E90FF" offset="0%" />
              <stop stopColor="#FF1E56" offset="100%" />
            </linearGradient>
            <linearGradient
              x1="123.779%"
              y1="-598.961%"
              x2="123.779%"
              y2="100%"
              id="f"
            >
              <stop stopColor="#1E90FF" offset="0%" />
              <stop stopColor="#FF1E56" offset="100%" />
            </linearGradient>
          </defs>
          <path
            d="M103.41.095C66.837-1.166 30.268 10.183 0 34.144l20.177 11.35c23.962-17.656 54.226-25.222 83.233-23.961V.095Z"
            fill="url(#a)"
          />
          <path
            d="M210.6 48.016c-25.222-26.483-58.01-42.877-93.319-46.66v21.438c30.268 5.044 56.75 18.916 78.188 40.355L210.6 48.016Z"
            fill="url(#b)"
          />
          <path
            d="M256 151.424c-1.26-32.788-13.871-65.576-35.309-93.32l-15.136 15.133c17.657 23.96 27.747 50.444 29.008 78.187H256Z"
            fill="url(#c)"
          />
          <path
            d="M220.691 259.877c21.438-27.744 34.049-60.532 35.309-93.32h-21.437c-1.26 27.744-11.351 54.227-29.008 78.187l15.136 15.133Z"
            fill="url(#d)"
          />
          <path
            d="M117.281 316.626c34.049-3.783 68.097-20.178 93.32-46.66l-15.132-15.133c-21.437 22.7-49.185 36.571-78.188 40.354v21.439Z"
            fill="url(#e)"
          />
          <path
            d="M0 283.838c30.268 23.96 66.837 35.31 103.41 34.049v-21.439c-29.007 1.262-58.01-6.305-83.233-23.96L0 283.838Z"
            fill="url(#f)"
          />
          <path d="M97.651 71.344c13.479 0 25.919 2.295 37.321 6.886 11.402 4.443 21.177 10.663 29.324 18.66 8.292 7.998 14.734 17.402 19.326 28.214 4.593 10.663 6.887 22.214 6.887 34.655 0 12.44-2.294 24.066-6.887 34.877-4.592 10.663-11.034 19.993-19.326 27.99-8.147 7.998-17.922 14.292-29.324 18.883-11.402 4.443-23.842 6.665-37.32 6.665-13.625 0-26.142-2.222-37.544-6.665-11.257-4.591-20.954-10.885-29.101-18.882-8.147-7.998-14.513-17.328-19.105-27.991-4.592-10.811-6.887-22.437-6.887-34.877 0-12.44 2.295-23.992 6.887-34.655 4.592-10.812 10.958-20.216 19.105-28.213 8.147-7.998 17.844-14.218 29.101-18.66 11.402-4.592 23.92-6.887 37.543-6.887Zm0 42.208c-6.37 0-12.44 1.184-18.216 3.554-5.626 2.222-10.59 5.406-14.884 9.553-4.293 4.146-7.702 9.034-10.219 14.661-2.516 5.628-3.776 11.774-3.776 18.439 0 6.664 1.26 12.81 3.776 18.438 2.517 5.628 5.926 10.515 10.22 14.662 4.293 4.147 9.257 7.404 14.883 9.774 5.776 2.222 11.846 3.332 18.216 3.332 6.37 0 12.368-1.11 17.994-3.332 5.776-2.37 10.813-5.627 15.106-9.774 4.443-4.147 7.925-9.034 10.441-14.662 2.516-5.628 3.777-11.774 3.777-18.438 0-6.665-1.26-12.811-3.777-18.439-2.516-5.627-5.998-10.515-10.44-14.661-4.294-4.147-9.331-7.331-15.107-9.553-5.626-2.37-11.624-3.554-17.994-3.554Z" />
        </svg>
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
