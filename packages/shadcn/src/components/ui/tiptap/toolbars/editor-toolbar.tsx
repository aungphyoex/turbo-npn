import { ScrollArea, ScrollBar } from '@repo/shadcn/scroll-area';
import { Separator } from '@repo/shadcn/separator';
import { AlignmentToolbar } from '@repo/shadcn/tiptap/toolbars/alignment';
import { BulletListToolbar } from '@repo/shadcn/tiptap/toolbars/bullet-list';
import { ColorHighlightToolbar } from '@repo/shadcn/tiptap/toolbars/color-and-highlight';
import EmojiEditor from '@repo/shadcn/tiptap/toolbars/emoji-toolbar';
import { HardBreakToolbar } from '@repo/shadcn/tiptap/toolbars/hard-break';
import { HorizontalRuleToolbar } from '@repo/shadcn/tiptap/toolbars/horizontal-rule';
import { ImagePlaceholderToolbar } from '@repo/shadcn/tiptap/toolbars/image-placeholder-toolbar';
import { LinkToolbar } from '@repo/shadcn/tiptap/toolbars/link';
import { OrderedListToolbar } from '@repo/shadcn/tiptap/toolbars/ordered-list';
import { RedoToolbar } from '@repo/shadcn/tiptap/toolbars/redo';
import { SearchAndReplaceToolbar } from '@repo/shadcn/tiptap/toolbars/search-and-replace-toolbar';
import { TableToolbar } from '@repo/shadcn/tiptap/toolbars/table';
import { TextToolbar } from '@repo/shadcn/tiptap/toolbars/text-toolbar';
import { ToolbarProvider } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';
import { UndoToolbar } from '@repo/shadcn/tiptap/toolbars/undo';
import { TooltipProvider } from '@repo/shadcn/tooltip';
import { Editor } from '@tiptap/core';

export const EditorToolbar = ({ editor }: { editor: Editor }) => {
  return (
    <div className="sticky top-0 z-20 w-full border-b bg-background">
      <ToolbarProvider editor={editor}>
        <TooltipProvider>
          <ScrollArea className="h-fit py-0.5">
            <div>
              <div className="flex items-center gap-1 px-2">
                <UndoToolbar />
                <RedoToolbar />
                <Separator orientation="vertical" className="mx-1 h-7" />
                <TextToolbar />
                <LinkToolbar />
                <Separator orientation="vertical" className="mx-1 h-7" />
                <BulletListToolbar />
                <OrderedListToolbar />
                <HorizontalRuleToolbar />
                <HardBreakToolbar />
                <Separator orientation="vertical" className="mx-1 h-7" />
                <AlignmentToolbar />
                <Separator orientation="vertical" className="mx-1 h-7" />
                <ImagePlaceholderToolbar />
                <TableToolbar />
                <EmojiEditor />
                <ColorHighlightToolbar />
                <Separator orientation="vertical" className="mx-1 h-7" />
                <div className="flex-1" />
                <SearchAndReplaceToolbar />
              </div>
            </div>
            <ScrollBar className="hidden" orientation="horizontal" />
          </ScrollArea>
        </TooltipProvider>
      </ToolbarProvider>
    </div>
  );
};
