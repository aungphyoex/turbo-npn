'use client';

import { useMobile } from '@repo/shadcn/hooks/use-mobile';
import { ScrollArea, ScrollBar } from '@repo/shadcn/scroll-area';
import { Separator } from '@repo/shadcn/separator';
import { AlignmentToolbar } from '@repo/shadcn/tiptap/toolbars/alignment';
import { BlockquoteToolbar } from '@repo/shadcn/tiptap/toolbars/blockquote';
import { BoldToolbar } from '@repo/shadcn/tiptap/toolbars/bold';
import { BulletListToolbar } from '@repo/shadcn/tiptap/toolbars/bullet-list';
import { ColorHighlightToolbar } from '@repo/shadcn/tiptap/toolbars/color-and-highlight';
import { HeadingsToolbar } from '@repo/shadcn/tiptap/toolbars/headings';
import { ImagePlaceholderToolbar } from '@repo/shadcn/tiptap/toolbars/image-placeholder-toolbar';
import { ItalicToolbar } from '@repo/shadcn/tiptap/toolbars/italic';
import { LinkToolbar } from '@repo/shadcn/tiptap/toolbars/link';
import { OrderedListToolbar } from '@repo/shadcn/tiptap/toolbars/ordered-list';
import { ToolbarProvider } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';
import { UnderlineToolbar } from '@repo/shadcn/tiptap/toolbars/underline';
import { TooltipProvider } from '@repo/shadcn/tooltip';
import { BubbleMenu, type Editor } from '@tiptap/react';
import { useEffect } from 'react';

export function FloatingToolbar({ editor }: { editor: Editor | null }) {
  const isMobile = useMobile();

  // Prevent default context menu on mobile
  useEffect(() => {
    if (!editor?.options.element || !isMobile) return;

    const handleContextMenu = (e: Event) => {
      e.preventDefault();
    };

    const el = editor.options.element;
    el.addEventListener('contextmenu', handleContextMenu);

    return () => el.removeEventListener('contextmenu', handleContextMenu);
  }, [editor, isMobile]);

  if (!editor) return null;

  if (isMobile) {
    return (
      <TooltipProvider>
        <BubbleMenu
          tippyOptions={{
            duration: 100,
            placement: 'bottom-start',
            offset: [0, 10],
          }}
          shouldShow={() => {
            // Show toolbar when editor is focused and has selection
            return editor.isEditable && editor.isFocused;
          }}
          editor={editor}
          className="w-full min-w-full mx-0 shadow-sm border rounded-sm bg-background"
        >
          <ToolbarProvider editor={editor}>
            <ScrollArea className="h-fit py-0.5 max-w-[300px]">
              <div className="w-full flex items-center px-2 gap-0.5">
                <div className="flex items-center gap-0.5 p-1">
                  {/* Primary formatting */}
                  <BoldToolbar />
                  <ItalicToolbar />
                  <UnderlineToolbar />
                  <Separator orientation="vertical" className="h-6 mx-1" />

                  {/* Structure controls */}
                  <HeadingsToolbar />
                  <BulletListToolbar />
                  <OrderedListToolbar />
                  <Separator orientation="vertical" className="h-6 mx-1" />

                  {/* Rich formatting */}
                  <ColorHighlightToolbar />
                  <LinkToolbar />
                  <ImagePlaceholderToolbar />
                  <Separator orientation="vertical" className="h-6 mx-1" />

                  {/* Additional controls */}
                  <AlignmentToolbar />
                  <BlockquoteToolbar />
                </div>
              </div>
              <ScrollBar className="h-0.5" orientation="horizontal" />
            </ScrollArea>
          </ToolbarProvider>
        </BubbleMenu>
      </TooltipProvider>
    );
  }

  return null;
}
