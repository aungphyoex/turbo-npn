'use client';

import { WrapText } from 'lucide-react';

import { Button, type ButtonProps } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils';
import { useToolbar } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';
import { Tooltip, TooltipContent, TooltipTrigger } from '@repo/shadcn/tooltip';

const HardBreakToolbar = ({
  className,
  onClick,
  children,
  ...props
}: ButtonProps) => {
  const { editor } = useToolbar();

  return (
    <Tooltip>
      <TooltipTrigger asChild>
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
      </TooltipTrigger>
      <TooltipContent>
        <span>Hard break</span>
      </TooltipContent>
    </Tooltip>
  );
};

export { HardBreakToolbar };
