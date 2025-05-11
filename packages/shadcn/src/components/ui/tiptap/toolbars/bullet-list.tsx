'use client';

import { List } from 'lucide-react';

import { Button, type ButtonProps } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils';
import { useToolbar } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';

const BulletListToolbar = ({
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
      className={cn(
        'h-8 w-8 p-0 sm:h-9 sm:w-9',
        editor?.isActive('bulletList') && 'bg-accent',
        className,
      )}
      onClick={(e) => {
        editor?.chain().focus().toggleBulletList().run();
        onClick?.(e);
      }}
      disabled={!editor?.can().chain().focus().toggleBulletList().run()}
      {...props}
    >
      {children ?? <List className="h-4 w-4" />}
    </Button>
  );
};

export { BulletListToolbar };
