'use client';

import { Button } from '@repo/shadcn/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@repo/shadcn/dropdown-menu';
import { cn } from '@repo/shadcn/lib/utils';
import { ScrollArea, ScrollBar } from '@repo/shadcn/scroll-area';
import { useToolbar } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';
import { Editor } from '@tiptap/core';
import {
  Ellipsis,
  Image,
  List,
  ListOrdered,
  ListTodo,
  Table,
} from 'lucide-react';
import React, { Fragment } from 'react';

const utilStyles = [
  {
    name: 'Ordered List',
    icon: <ListOrdered className="size-4 dark:text-white" />,
    type: 'orderedList',
    action: (editor: Editor) => {
      return editor.chain().focus().toggleOrderedList().run();
    },
    isActive: (editor: Editor) => {
      return editor.isActive('orderedList');
    },
    isDisabled: (editor: Editor) => {
      return !editor.can().chain().focus().toggleOrderedList().run();
    },
    cmd: ['⌘', '⇧', '7'],
  },
  {
    name: 'Bullet List',
    icon: <List className="size-4 dark:text-white" />,
    type: 'bulletList',
    action: (editor: Editor) => {
      editor.chain().focus().toggleBulletList().run();
    },
    isActive: (editor: Editor) => {
      return editor.isActive('bulletList');
    },
    cmd: ['⌘', '⇧', '8'],
    isDisabled: (editor: Editor) => {
      return !editor?.can().chain().focus().toggleBulletList().run();
    },
  },
  {
    name: 'Task List',
    icon: <ListTodo className="size-4 dark:text-white" />,
    type: 'taskList',
    action: (editor: Editor) => {
      editor.chain().focus().toggleTaskList().run();
    },
    isActive: (editor: Editor) => {
      return editor.isActive('taskList');
    },
    cmd: ['⌘', '⇧', '9'],
    isDisabled: (editor: Editor) => {
      return !editor?.can().chain().focus().toggleTaskList().run();
    },
  },
  {
    name: 'Table',
    icon: <Table className="size-4 dark:text-white" />,
    type: 'table',
    action: (editor: Editor) => {
      editor
        .chain()
        .focus()
        .insertTable({ rows: 3, cols: 3, withHeaderRow: true })
        .run();
    },
    isActive: (editor: Editor) => {
      return editor.isActive('table');
    },
    isDisabled: (editor: Editor) => {
      return !editor
        .can()
        .chain()
        .focus()
        .insertTable({ rows: 3, cols: 3, withHeaderRow: true })
        .run();
    },
  },
  {
    name: 'Image',
    icon: <Image className="size-4 dark:text-white" />,
    type: 'image-placeholder',
    action: (editor: Editor) => {
      editor?.chain().focus().insertImagePlaceholder().run();
    },
    isActive: (editor: Editor) => {
      return editor.isActive('image');
    },
  },
];
const UtilToolbar = ({
  className,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement>) => {
  const { editor } = useToolbar();

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className={cn(
            'size-8 gap-2 px-3 font-normal focus-visible:ring-0 focus:outline-none',
            editor?.isActive('heading') && 'bg-accent',
            className,
          )}
          {...props}
        >
          <Ellipsis className="h-4 w-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-[250px]" side="bottom">
        <ScrollArea className="w-full h-[200px]">
          {utilStyles.map(
            ({ icon, name, action, isActive, cmd, isDisabled }) => (
              <DropdownMenuItem
                disabled={isDisabled && isDisabled(editor)}
                key={name}
                onClick={() => action(editor)}
                className={cn(
                  'flex items-center justify-between gap-2',
                  isActive(editor) && 'bg-accent',
                )}
              >
                <span className="flex items-center gap-1">
                  {icon} {name}
                </span>
                {cmd && (
                  <kbd className="pointer-events-none inline-flex h-5 select-none items-center gap-1.5 rounded border bg-muted px-1.5 font-mono text-[10px] font-medium text-muted-foreground opacity-100">
                    {cmd.map((item, index) => (
                      <Fragment key={index}>
                        <span className="text-sm capitalize">{item}</span>
                        <span className="text-xs capitalize">
                          {index !== cmd.length - 1 && '+'}
                        </span>
                      </Fragment>
                    ))}
                  </kbd>
                )}
              </DropdownMenuItem>
            ),
          )}
          <ScrollBar orientation="vertical" />
        </ScrollArea>
      </DropdownMenuContent>
    </DropdownMenu>
  );
};

export default UtilToolbar;
