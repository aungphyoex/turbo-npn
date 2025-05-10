'use client';

import { Code2 } from 'lucide-react';

import type { ButtonProps } from '@repo/shadcn/button';
import { Button } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils';
import { useToolbar } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';
import { Tooltip, TooltipContent, TooltipTrigger } from '@repo/shadcn/tooltip';

const CodeToolbar = ({
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
          className={cn(
            'h-8 w-8 p-0 sm:h-9 sm:w-9',
            editor?.isActive('code') && 'bg-accent',
            className,
          )}
          onClick={(e) => {
            editor?.chain().focus().toggleCode().run();
            onClick?.(e);
          }}
          disabled={!editor?.can().chain().focus().toggleCode().run()}
          {...props}
        >
          {children ?? <Code2 className="h-4 w-4" />}
        </Button>
      </TooltipTrigger>
      <TooltipContent>
        <span>Code</span>
      </TooltipContent>
    </Tooltip>
  );
};

export { CodeToolbar };
