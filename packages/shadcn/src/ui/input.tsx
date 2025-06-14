'use client';
import * as React from 'react';

import { cn } from '@repo/shadcn/lib/utils';
import { Eye, EyeOff } from 'lucide-react';
import { useState } from 'react';

function Input({ className, type, ...props }: React.ComponentProps<'input'>) {
  const [open, setOpen] = useState(false);
  return (
    <div className="w-full relative">
      <input
        type={type === 'password' && open ? 'text' : type}
        data-slot="input"
        className={cn(
          'border-input file:text-foreground placeholder:text-muted-foreground selection:bg-primary selection:text-primary-foreground aria-invalid:outline-destructive/60 aria-invalid:ring-destructive/20 dark:aria-invalid:outline-destructive dark:aria-invalid:ring-destructive/50 ring-ring/10 dark:ring-ring/20 dark:outline-ring/40 outline-ring/50 aria-invalid:border-destructive/60 dark:aria-invalid:border-destructive flex h-9 w-full min-w-0 rounded-md border bg-transparent px-3 py-1 text-base shadow-xs transition-[color,box-shadow] file:inline-flex file:h-7 file:border-0 file:bg-transparent file:text-sm file:font-medium focus-visible:ring-4 focus-visible:outline-1 disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:focus-visible:ring-[3px] aria-invalid:focus-visible:outline-none md:text-sm dark:aria-invalid:focus-visible:ring-4',
          className,
        )}
        {...props}
      />
      {type === 'password' && (
        <div className="absolute inset-y-0 right-0 px-3 flex justify-center items-center">
          <button
            type="button"
            onClick={() => setOpen((prevState) => !prevState)}
          >
            {!open ? <Eye className="size-4" /> : <EyeOff className="size-4" />}
          </button>
        </div>
      )}
    </div>
  );
}

export { Input };
