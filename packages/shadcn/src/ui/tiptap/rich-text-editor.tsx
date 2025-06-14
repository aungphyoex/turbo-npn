'use client';
import { cn } from '@repo/shadcn/lib/utils.js';
import { defaultExtensions } from '@repo/shadcn/tiptap/extensions/extension';
import { TipTapFloatingMenu } from '@repo/shadcn/tiptap/extensions/floating-menu';
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
        class: 'prose-article',
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
    <div className={cn('relative w-full bg-card overflow-hidden', className)}>
      <TableMenu editor={editor} />
      <CodeLanguage editor={editor} />
      <EditorToolbar editor={editor} />
      <TipTapFloatingMenu editor={editor} />
      <EditorContent
        editor={editor}
        className="min-h-[400px] min-w-full cursor-text p-3 md:p-6 no-scrollbar lg:p-12"
      />
    </div>
  );
}
