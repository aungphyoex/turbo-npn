import { ScrollArea, ScrollBar } from '@repo/shadcn/scroll-area';
import { Separator } from '@repo/shadcn/separator';
import Ai from '@repo/shadcn/tiptap/extensions/ai';
import { AlignmentToolbar } from '@repo/shadcn/tiptap/toolbars/alignment';
import { ColorHighlightToolbar } from '@repo/shadcn/tiptap/toolbars/color-and-highlight';
import EmojiEditor from '@repo/shadcn/tiptap/toolbars/emoji-toolbar';
import { HardBreakToolbar } from '@repo/shadcn/tiptap/toolbars/hard-break';
import { HorizontalRuleToolbar } from '@repo/shadcn/tiptap/toolbars/horizontal-rule';
import { LinkToolbar } from '@repo/shadcn/tiptap/toolbars/link';
import { RedoToolbar } from '@repo/shadcn/tiptap/toolbars/redo';
import { SearchAndReplaceToolbar } from '@repo/shadcn/tiptap/toolbars/search-and-replace-toolbar';
import { TextToolbar } from '@repo/shadcn/tiptap/toolbars/text-toolbar';
import { ToolbarProvider } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';
import { UndoToolbar } from '@repo/shadcn/tiptap/toolbars/undo';
import UtilToolbar from '@repo/shadcn/tiptap/toolbars/util-toolbar';
import { TooltipProvider } from '@repo/shadcn/tooltip';
import { Editor } from '@tiptap/core';

export const EditorToolbar = ({ editor }: { editor: Editor }) => {
  return (
    <div className="sticky top-0 z-20 w-full border-b bg-accent select-none">
      <ToolbarProvider editor={editor}>
        <TooltipProvider>
          <ScrollArea className="h-fit py-0.5">
            <div>
              <div className="flex items-center gap-1 md:px-2 flex-wrap">
                <div className="w-full md:w-auto flex gap-1 justify-between md:justify-start">
                  <div className="gap-1 md:flex">
                    <UndoToolbar />
                    <RedoToolbar />
                    <Separator orientation="vertical" className="mx-1 h-7" />
                  </div>
                  <TextToolbar />
                  <div className="flex gap-1">
                    <LinkToolbar />
                    <HorizontalRuleToolbar />
                    <HardBreakToolbar />
                    <AlignmentToolbar />
                    <Separator
                      orientation="vertical"
                      className="hidden sm:block mx-1 h-7"
                    />
                  </div>
                </div>
                <EmojiEditor />
                <ColorHighlightToolbar />
                <Ai editor={editor} />
                <UtilToolbar />
                <Separator
                  orientation="vertical"
                  className="hidden sm:block mx-1 h-7"
                />
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
