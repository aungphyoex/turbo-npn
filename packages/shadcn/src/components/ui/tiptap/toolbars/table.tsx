'use client';

import { Button, type ButtonProps } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils';
import { useToolbar } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';
import { Table } from 'lucide-react';

const TableToolbar = ({
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
        editor?.isActive('table') && 'bg-accent',
        className,
      )}
      onClick={(e) => {
        editor
          ?.chain()
          .focus()
          .insertTable({ rows: 3, cols: 3, withHeaderRow: true })
          .run();
        onClick?.(e);
      }}
      disabled={
        !editor
          ?.can()
          .chain()
          .focus()
          .insertTable({ rows: 3, cols: 3, withHeaderRow: true })
          .run()
      }
      {...props}
    >
      {children ?? <Table className="h-4 w-4" />}
    </Button>
  );
};

export { TableToolbar };
