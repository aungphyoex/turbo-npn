'use client';

import { Button, type ButtonProps } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils';
import { useToolbar } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';
import { IconTextWrap } from '@tabler/icons-react';

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
      {children ?? <IconTextWrap className="size-4" />}
    </Button>
  );
};

export { HardBreakToolbar };
