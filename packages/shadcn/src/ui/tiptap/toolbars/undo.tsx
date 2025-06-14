'use client';

import { Button, type ButtonProps } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils.js';
import { useToolbar } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';
import { Undo2 } from 'lucide-react';

function UndoToolbar({ className, onClick, children, ...props }: ButtonProps) {
  const { editor } = useToolbar();

  return (
    <Button
      variant="ghost"
      size="icon"
      className={cn('h-8 w-8 p-0 sm:h-9 sm:w-9', className)}
      onClick={(e) => {
        editor?.chain().focus().undo().run();
        onClick?.(e);
      }}
      disabled={!editor?.can().chain().focus().undo().run()}
      {...props}
    >
      {children ?? <Undo2 className="h-4 w-4" />}
    </Button>
  );
}

export { UndoToolbar };
