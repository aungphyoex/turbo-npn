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
    <div className="sticky top-0 z-20 w-full border-b bg-accent select-none px-2 rounded-md">
      <ToolbarProvider editor={editor}>
        <TooltipProvider>
          <div>
            <div className="flex items-center gap-1 md:px-2 flex-wrap">
              <div className="w-full md:w-auto flex gap-1 justify-between md:justify-start">
                <div className="gap-1 md:flex items-center">
                  <UndoToolbar />
                  <RedoToolbar />
                </div>
                <TextToolbar />
                <div className="flex gap-1 items-center">
                  <LinkToolbar />
                  <HorizontalRuleToolbar />
                  <EmojiEditor />
                  <HardBreakToolbar />
                  <AlignmentToolbar />
                </div>
              </div>
              <div className="w-full md:w-fit flex-1 flex items-center justify-between">
                <div className="flex items-center gap-1">
                  <ColorHighlightToolbar />
                  <UtilToolbar />
                </div>
                <SearchAndReplaceToolbar />
              </div>
            </div>
          </div>
        </TooltipProvider>
      </ToolbarProvider>
    </div>
  );
};
