'use client';
import { setCookie } from '@/server/cookie.server';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@repo/shadcn/card';
import { Label } from '@repo/shadcn/label';
import { cn } from '@repo/shadcn/lib/utils';
import { RadioGroup, RadioGroupItem } from '@repo/shadcn/radio-group';
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from '@repo/shadcn/select';
import { useTheme } from '@repo/shadcn/themes-provider';

const AppearanceSettings = ({ select_font }: { select_font: string }) => {
  const { setTheme, resolvedTheme } = useTheme();

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Theme</CardTitle>
          <CardDescription>Select the theme</CardDescription>
        </CardHeader>
        <CardContent>
          <div>
            <RadioGroup
              className="grid grid-cols-2 gap-5 max-w-sm p-0"
              defaultValue={resolvedTheme === 'dark' ? 'dark' : 'light'}
              onValueChange={(value) => setTheme(value)}
            >
              <div className={cn('relative rounded-sm overflow-hidden')}>
                <div className="absolute inset-x-0 p-2 flex items-center">
                  <div className={cn('hidden')}>
                    <RadioGroupItem value="light" id="light" />
                  </div>
                </div>
                <Label htmlFor="light">
                  <div className="border-muted hover:border-accent items-center rounded-md border-2 p-1">
                    <div className="space-y-2 rounded-sm bg-[#ecedef] p-2">
                      <div className="space-y-2 rounded-md bg-white p-2 shadow-xs">
                        <div className="h-2 w-[80px] rounded-lg bg-[#ecedef]" />
                        <div className="h-2 w-[100px] rounded-lg bg-[#ecedef]" />
                      </div>
                      <div className="flex items-center space-x-2 rounded-md bg-white p-2 shadow-xs">
                        <div className="size-4 lg:size-5rounded-full bg-[#ecedef]" />
                        <div className="h-2 w-[100px] rounded-lg bg-[#ecedef]" />
                      </div>
                      <div className="flex items-center space-x-2 rounded-md bg-white p-2 shadow-xs">
                        <div className="size-4 lg:size-5rounded-full bg-[#ecedef]" />
                        <div className="h-2 w-[100px] rounded-lg bg-[#ecedef]" />
                      </div>
                    </div>
                  </div>
                </Label>
              </div>
              <div className={cn('relative rounded-sm overflow-hidden')}>
                <div className="absolute inset-x-0 p-2 flex items-center">
                  <div className={cn('hidden')}>
                    <RadioGroupItem value="dark" id="dark" />
                  </div>
                </div>
                <Label htmlFor="dark">
                  <div className="border-muted bg-popover hover:bg-accent hover:text-accent-foreground items-center rounded-md border-2 p-1">
                    <div className="space-y-2 rounded-sm bg-slate-950 p-2">
                      <div className="space-y-2 rounded-md bg-slate-800 p-2 shadow-xs">
                        <div className="h-2 w-[80px] rounded-lg bg-slate-400" />
                        <div className="h-2 w-[100px] rounded-lg bg-slate-400" />
                      </div>
                      <div className="flex items-center space-x-2 rounded-md bg-slate-800 p-2 shadow-xs">
                        <div className="size-4 lg:size-5rounded-full bg-slate-400" />
                        <div className="h-2 w-[100px] rounded-lg bg-slate-400" />
                      </div>
                      <div className="flex items-center space-x-2 rounded-md bg-slate-800 p-2 shadow-xs">
                        <div className="size-4 lg:size-5rounded-full bg-slate-400" />
                        <div className="h-2 w-[100px] rounded-lg bg-slate-400" />
                      </div>
                    </div>
                  </div>
                </Label>
              </div>
            </RadioGroup>
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Font</CardTitle>
          <CardDescription>Select the font</CardDescription>
        </CardHeader>
        <CardContent>
          <Select
            defaultValue={select_font}
            onValueChange={async (value) => {
              await setCookie({ name: 'select-font', value });
            }}
          >
            <SelectTrigger className="w-full max-w-md">
              <SelectValue placeholder="Select fon" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectLabel>Font</SelectLabel>
                <SelectItem value="--font-geist">Geist</SelectItem>
                <SelectItem value="--font-geist-mono">Geist Mono</SelectItem>
                <SelectItem value="--font-roboto">Roboto</SelectItem>
                <SelectItem value="--font-roboto-mono">Roboto Mono</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
        </CardContent>
      </Card>
    </div>
  );
};

export default AppearanceSettings;
