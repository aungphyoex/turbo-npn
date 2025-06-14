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
import { IconBlockquote } from '@tabler/icons-react';
import { Editor } from '@tiptap/core';
import {
  BoldIcon,
  ChevronDown,
  CodeIcon,
  Heading1Icon,
  Heading2Icon,
  Heading3Icon,
  ItalicIcon,
  Layers2,
  Pilcrow,
  StrikethroughIcon,
  UnderlineIcon,
  Zap,
} from 'lucide-react';
import React, { Fragment } from 'react';

const textStyles = [
  {
    name: 'Paragraph',
    icon: <Pilcrow className="size-4 dark:text-white scale-x-[-1]" />,
    type: 'paragraph',
    action: (editor: Editor) => {
      editor.chain().focus().setParagraph().run();
    },
    isActive: (editor: Editor) => {
      return !editor.isActive('heading');
    },
    cmd: ['⌘', '⌥', '0'],
  },
  {
    name: 'Heading 1',
    icon: <Heading1Icon className="size-4 dark:text-white" />,
    type: 1,
    action: (editor: Editor) => {
      editor.chain().focus().toggleHeading({ level: 1 }).run();
    },
    isActive: (editor: Editor) => {
      return editor.isActive('heading', { level: 1 });
    },
    cmd: ['⌘', '⌥', '1'],
  },
  {
    name: 'Heading 2',
    icon: <Heading2Icon className="size-4 dark:text-white" />,
    type: 2,
    action: (editor: Editor) => {
      editor.chain().focus().toggleHeading({ level: 2 }).run();
    },
    isActive: (editor: Editor) => {
      return editor.isActive('heading', { level: 2 });
    },
    cmd: ['⌘', '⌥', '2'],
  },
  {
    name: 'Heading 3',
    icon: <Heading3Icon className="size-4 dark:text-white" />,
    type: 3,
    action: (editor: Editor) => {
      editor.chain().focus().toggleHeading({ level: 3 }).run();
    },
    isActive: (editor: Editor) => {
      return editor.isActive('heading', { level: 3 });
    },
    cmd: ['⌘', '⌥', '3'],
  },
  {
    icon: <BoldIcon className="size-4 dark:text-white" />,
    name: 'Bold',
    type: 'bold',
    action: (editor: Editor) => {
      editor.chain().focus().toggleBold().run();
    },
    isActive: (editor: Editor) => {
      return editor.isActive('bold');
    },
    cmd: ['⌘', 'b'],
  },
  {
    icon: <ItalicIcon className="size-4 dark:text-white" />,
    name: 'Italic',
    type: 'italic',
    action: (editor: Editor) => {
      editor.chain().focus().toggleItalic().run();
    },
    isActive: (editor: Editor) => {
      return editor.isActive('italic');
    },
    cmd: ['⌘', 'i'],
  },
  {
    icon: <StrikethroughIcon className="size-4 dark:text-white" />,
    name: 'Strikethrough',
    type: 'strike',
    action: (editor: Editor) => {
      editor.chain().focus().toggleStrike().run();
    },
    isActive: (editor: Editor) => {
      return editor.isActive('strike');
    },
    cmd: ['⌘', '⇧', 's'],
  },
  {
    icon: <UnderlineIcon className="size-4 dark:text-white" />,
    name: 'Underline',
    type: 'underline',
    action: (editor: Editor) => {
      editor.chain().focus().toggleUnderline().run();
    },
    isActive: (editor: Editor) => {
      return editor.isActive('underline');
    },
    cmd: ['⌘', '⇧', 'u'],
  },
  {
    icon: <CodeIcon className="size-4 dark:text-white" />,
    name: 'Code',
    type: 'code',
    action: (editor: Editor) => {
      editor.chain().focus().toggleCode().run();
    },
    isActive: (editor: Editor) => {
      return editor.isActive('code');
    },
    cmd: ['⌘', 'e'],
  },
  {
    icon: <CodeIcon className="size-4 dark:text-white" />,
    name: 'Code Block',
    type: 'code-block',
    action: (editor: Editor) => {
      editor.chain().focus().toggleCodeBlock().run();
    },
    isActive: (editor: Editor) => {
      return editor.isActive('code-block');
    },
    cmd: ['⌘', '⌥', 'c'],
  },
  {
    name: 'Blockquote',
    icon: <IconBlockquote className="size-4 tdark:ext-white" />,
    type: 'blockquote',
    action: (editor: Editor) => {
      editor.chain().focus().toggleBlockquote().run();
    },
    isActive: (editor: Editor) => {
      return editor.isActive('blockquote');
    },
    cmd: ['⌘', '⇧', 'b'],
  },
] as const;

export const TextToolbar = ({
  className,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement>) => {
  const { editor } = useToolbar();

  const checkIsActive = (type: string | number) => {
    if (typeof type === 'number') {
      return editor?.isActive('heading', { level: type });
    }
    return editor?.isActive(type);
  };

  const activeStyle = textStyles.filter((node) => checkIsActive(node.type));

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className={cn(
            'h-8 w-[128px] gap-2 px-3 font-normal focus-visible:ring-0 focus:outline-none',
            editor?.isActive('heading') && 'bg-accent',
            className,
          )}
          {...props}
        >
          {activeStyle.length > 1 ? (
            <>
              <Layers2 className="size-3 dark:text-white" />
              Multiple
            </>
          ) : (
            <>
              {activeStyle[0] ? (
                <>
                  {activeStyle[0].icon} {activeStyle[0].name}
                </>
              ) : (
                <>
                  <Zap className="size-4 dark:text-white" />
                  Other
                </>
              )}
            </>
          )}
          <ChevronDown className="h-4 w-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-[250px]">
        <ScrollArea className="w-full h-[200px]">
          {textStyles.map(({ icon, name, action, isActive, cmd }) => (
            <DropdownMenuItem
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
            </DropdownMenuItem>
          ))}
          <ScrollBar orientation="vertical" />
        </ScrollArea>
      </DropdownMenuContent>
    </DropdownMenu>
  );
};
