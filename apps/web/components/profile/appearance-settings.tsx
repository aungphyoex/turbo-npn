'use client';
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
import { useTheme } from '@repo/shadcn/themes-provider';

const AppearanceSettings = () => {
  const { setTheme, resolvedTheme } = useTheme();

  return (
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
            <div
              className={cn(
                'relative rounded-sm overflow-hidden',
                resolvedTheme === 'light' && 'border border-gray-800',
              )}
            >
              <div className="hidden">
                <RadioGroupItem value="light" id="light" />
              </div>
              <Label htmlFor="light">
                <div className="border-muted hover:border-accent items-center rounded-md border-2 p-1">
                  <div className="space-y-2 rounded-sm bg-[#ecedef] p-2">
                    <div className="space-y-2 rounded-md bg-white p-2 shadow-xs">
                      <div className="h-2 w-[80px] rounded-lg bg-[#ecedef]" />
                      <div className="h-2 w-[100px] rounded-lg bg-[#ecedef]" />
                    </div>
                    <div className="flex items-center space-x-2 rounded-md bg-white p-2 shadow-xs">
                      <div className="h-4 w-4 rounded-full bg-[#ecedef]" />
                      <div className="h-2 w-[100px] rounded-lg bg-[#ecedef]" />
                    </div>
                    <div className="flex items-center space-x-2 rounded-md bg-white p-2 shadow-xs">
                      <div className="h-4 w-4 rounded-full bg-[#ecedef]" />
                      <div className="h-2 w-[100px] rounded-lg bg-[#ecedef]" />
                    </div>
                  </div>
                </div>
              </Label>
            </div>
            <div
              className={cn(
                'relative rounded-sm overflow-hidden',
                resolvedTheme === 'dark' && 'border border-gray-500',
              )}
            >
              <div className="hidden">
                <RadioGroupItem value="dark" id="dark" />
              </div>
              <Label htmlFor="dark">
                <div className="border-muted bg-popover hover:bg-accent hover:text-accent-foreground items-center rounded-md border-2 p-1">
                  <div className="space-y-2 rounded-sm bg-slate-950 p-2">
                    <div className="space-y-2 rounded-md bg-slate-800 p-2 shadow-xs">
                      <div className="h-2 w-[80px] rounded-lg bg-slate-400" />
                      <div className="h-2 w-[100px] rounded-lg bg-slate-400" />
                    </div>
                    <div className="flex items-center space-x-2 rounded-md bg-slate-800 p-2 shadow-xs">
                      <div className="h-4 w-4 rounded-full bg-slate-400" />
                      <div className="h-2 w-[100px] rounded-lg bg-slate-400" />
                    </div>
                    <div className="flex items-center space-x-2 rounded-md bg-slate-800 p-2 shadow-xs">
                      <div className="h-4 w-4 rounded-full bg-slate-400" />
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
  );
};

export default AppearanceSettings;
