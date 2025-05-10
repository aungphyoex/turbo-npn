'use client';
import { cn } from '@repo/shadcn/lib/utils';
import { defaultExtensions } from '@repo/shadcn/tiptap/extensions/extension';
import { TipTapFloatingMenu } from '@repo/shadcn/tiptap/extensions/floating-menu';
import { FloatingToolbar } from '@repo/shadcn/tiptap/extensions/floating-toolbar';
import { CodeLanguage } from '@repo/shadcn/tiptap/toolbars/code-language';
import { EditorToolbar } from '@repo/shadcn/tiptap/toolbars/editor-toolbar';
import { TableMenu } from '@repo/shadcn/tiptap/toolbars/table-menu';
import { EditorContent, type Extension, useEditor } from '@tiptap/react';
import './tiptap.css';

export function RichTextEditor({ className }: { className?: string }) {
  const editor = useEditor({
    immediatelyRender: false,
    extensions: defaultExtensions as Extension[],
    content: '',
    editorProps: {
      attributes: {
        class: 'max-w-full focus:outline-none',
      },
    },
    onUpdate: ({ editor }) => {
      // do what you want to do with output
      // Update stats
      // saving as text/json/hmtml
      // const text = editor.getHTML();
      console.log(editor.getText());
    },
  });

  if (!editor) return null;

  return (
    <div
      className={cn('relative w-full bg-card border-primary border', className)}
    >
      <TableMenu editor={editor} />
      <CodeLanguage editor={editor} />
      <EditorToolbar editor={editor} />
      <FloatingToolbar editor={editor} />
      <TipTapFloatingMenu editor={editor} />
      <EditorContent
        editor={editor}
        className="min-h-[600px] w-full min-w-full cursor-text p-3 md:p-6 no-scrollbar"
      />
    </div>
  );
}
