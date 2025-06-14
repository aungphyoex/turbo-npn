'use client';

import { WrapText } from 'lucide-react';

import { Button, type ButtonProps } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils.js';
import { useToolbar } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';

const HardBreakToolbar = ({
  className,
  onClick,
  children,
  ...props
}: ButtonProps) => {
  const { editor } = useToolbar();

  return (
    <Button
      variant="ghost"
      size="icon"
      className={cn('h-8 w-8 p-0 sm:h-9 sm:w-9', className)}
      onClick={(e) => {
        editor?.chain().focus().setHardBreak().run();
        onClick?.(e);
      }}
      {...props}
    >
      {children ?? <WrapText className="h-4 w-4" />}
    </Button>
  );
};

export { HardBreakToolbar };
