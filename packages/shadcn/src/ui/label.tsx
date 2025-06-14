'use client';

import * as LabelPrimitive from '@radix-ui/react-label';
import * as React from 'react';

import { cn } from '@repo/shadcn/lib/utils';

function Label({
  className,
  isRequired,
  children,
  ...props
}: React.ComponentProps<typeof LabelPrimitive.Root> & {
  isRequired?: boolean;
}) {
  return (
    <LabelPrimitive.Root
      data-slot="label"
      className={cn(
        'text-sm leading-none font-medium select-none group-data-[disabled=true]:pointer-events-none group-data-[disabled=true]:opacity-50 peer-disabled:cursor-not-allowed peer-disabled:opacity-50',
        className,
      )}
      {...props}
    >
      {children}
      {isRequired && <span className="text-red-500 ml-1 text-lg">*</span>}
    </LabelPrimitive.Root>
  );
}

export { Label };
