'use client';

import { Button, type ButtonProps } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils';
import { useToolbar } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';
import { Tooltip, TooltipContent, TooltipTrigger } from '@repo/shadcn/tooltip';
import CodeBlockLowlight from '@tiptap/extension-code-block-lowlight';
import { Code } from 'lucide-react';

const CodeBlockToolbar = ({
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
            editor?.isActive('codeBlock') && 'bg-accent',
            className,
          )}
          onClick={(e) => {
            editor?.chain().focus().toggleCodeBlock().run();
            onClick?.(e);
          }}
          disabled={!editor?.can().chain().focus().toggleCodeBlock().run()}
          {...props}
        >
          {children ?? <Code className="h-4 w-4" />}
        </Button>
      </TooltipTrigger>
      <TooltipContent>
        <span>Code Block</span>
      </TooltipContent>
    </Tooltip>
  );
};

export const CodeBlock = CodeBlockLowlight.extend({
  addKeyboardShortcuts() {
    return {
      ...this.parent?.(),
      Tab: ({ editor }) => {
        if (editor.isActive(this.type.name)) {
          editor
            .chain()
            .command(({ tr }) => {
              tr.insertText('  ');
              return true;
            })
            .run();
        }
        return true;
      },
    };
  },
});

export { CodeBlockToolbar };
