'use client';

import * as SliderPrimitive from '@radix-ui/react-slider';
import { cn } from '@repo/shadcn/lib/utils';
import * as React from 'react';

interface DualRangeSliderProps
  extends React.ComponentProps<typeof SliderPrimitive.Root> {
  labelPosition?: 'top' | 'bottom';
  label: (value: number | undefined) => React.ReactNode;
}

const DualRangeSlider = React.forwardRef<
  React.ElementRef<typeof SliderPrimitive.Root>,
  DualRangeSliderProps
>(({ className, label, labelPosition = 'top', ...props }, ref) => {
  const initialValue = Array.isArray(props.value)
    ? props.value
    : [props.min, props.max];

  return (
    <SliderPrimitive.Root
      ref={ref}
      className={cn(
        'relative flex w-full touch-none select-none items-center cursor-pointer',
        className,
      )}
      {...props}
    >
      <SliderPrimitive.Track className="relative h-1.5 w-full grow overflow-hidden dark:bg-gray-800 bg-gray-300">
        <SliderPrimitive.Range className="absolute h-full bg-primary" />
      </SliderPrimitive.Track>
      <>
        {initialValue.map((value, index) => (
          <React.Fragment key={index}>
            <SliderPrimitive.Thumb className="relative block size-2 border-2 border-primary bg-background transition-colors disabled:pointer-events-none disabled:opacity-50">
              <div
                className={cn(
                  'absolute flex w-full justify-center items-start gap-0.5 bg-transparent',
                  labelPosition === 'top' && '-top-5',
                  labelPosition === 'bottom' && 'top-4',
                )}
              >
                <span className="inline-block  -translate-y-1 bg-primary text-xs px-1 py-px">
                  {label(value)}
                </span>
              </div>
            </SliderPrimitive.Thumb>
          </React.Fragment>
        ))}
      </>
    </SliderPrimitive.Root>
  );
});
DualRangeSlider.displayName = 'DualRangeSlider';

export { DualRangeSlider };
