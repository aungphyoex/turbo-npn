'use client';

import { UnderlineIcon } from 'lucide-react';

import { Button, type ButtonProps } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils';
import { useToolbar } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';
import { Tooltip, TooltipContent, TooltipTrigger } from '@repo/shadcn/tooltip';

function UnderlineToolbar({
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
            editor?.isActive('underline') && 'bg-accent',
            className,
          )}
          onClick={(e) => {
            editor?.chain().focus().toggleUnderline().run();
            onClick?.(e);
          }}
          disabled={!editor?.can().chain().focus().toggleUnderline().run()}
          {...props}
        >
          {children ?? <UnderlineIcon className="h-4 w-4" />}
        </Button>
      </TooltipTrigger>
      <TooltipContent>
        <span>Underline</span>
        <span className="ml-1 text-xs text-gray-11">(cmd + u)</span>
      </TooltipContent>
    </Tooltip>
  );
}

export { UnderlineToolbar };
