'use client';

import { Strikethrough } from 'lucide-react';

import { Button, type ButtonProps } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils';
import { useToolbar } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';
import { Tooltip, TooltipContent, TooltipTrigger } from '@repo/shadcn/tooltip';

function StrikeThroughToolbar({
  className,
  onClick,
  children,
  ...props
}: ButtonProps) {
  const { editor } = useToolbar();

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className={cn(
            'h-8 w-8 p-0 sm:h-9 sm:w-9',
            editor?.isActive('strike') && 'bg-accent',
            className,
          )}
          onClick={(e) => {
            editor?.chain().focus().toggleStrike().run();
            onClick?.(e);
          }}
          disabled={!editor?.can().chain().focus().toggleStrike().run()}
          {...props}
        >
          {children ?? <Strikethrough className="h-4 w-4" />}
        </Button>
      </TooltipTrigger>
      <TooltipContent>
        <span>Strikethrough</span>
        <span className="ml-1 text-xs text-gray-11">(cmd + shift + x)</span>
      </TooltipContent>
    </Tooltip>
  );
}

export { StrikeThroughToolbar };
