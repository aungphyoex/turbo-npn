import { ScrollArea, ScrollBar } from '@repo/shadcn/scroll-area';
import { Separator } from '@repo/shadcn/separator';
import { AlignmentToolbar } from '@repo/shadcn/tiptap/toolbars/alignment';
import { BlockquoteToolbar } from '@repo/shadcn/tiptap/toolbars/blockquote';
import { BoldToolbar } from '@repo/shadcn/tiptap/toolbars/bold';
import { BulletListToolbar } from '@repo/shadcn/tiptap/toolbars/bullet-list';
import { CodeToolbar } from '@repo/shadcn/tiptap/toolbars/code';
import { CodeBlockToolbar } from '@repo/shadcn/tiptap/toolbars/code-block';
import { ColorHighlightToolbar } from '@repo/shadcn/tiptap/toolbars/color-and-highlight';
import EmojiEditor from '@repo/shadcn/tiptap/toolbars/emoji.editor';
import { FontFamilyToolbar } from '@repo/shadcn/tiptap/toolbars/font-family';
import { HeadingsToolbar } from '@repo/shadcn/tiptap/toolbars/headings';
import { HorizontalRuleToolbar } from '@repo/shadcn/tiptap/toolbars/horizontal-rule';
import { ImagePlaceholderToolbar } from '@repo/shadcn/tiptap/toolbars/image-placeholder-toolbar';
import { ItalicToolbar } from '@repo/shadcn/tiptap/toolbars/italic';
import { LinkToolbar } from '@repo/shadcn/tiptap/toolbars/link';
import { OrderedListToolbar } from '@repo/shadcn/tiptap/toolbars/ordered-list';
import { RedoToolbar } from '@repo/shadcn/tiptap/toolbars/redo';
import { SearchAndReplaceToolbar } from '@repo/shadcn/tiptap/toolbars/search-and-replace-toolbar';
import { StrikeThroughToolbar } from '@repo/shadcn/tiptap/toolbars/strikethrough';
import { TableToolbar } from '@repo/shadcn/tiptap/toolbars/table';
import { ToolbarProvider } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';
import { UnderlineToolbar } from '@repo/shadcn/tiptap/toolbars/underline';
import { UndoToolbar } from '@repo/shadcn/tiptap/toolbars/undo';
import { TooltipProvider } from '@repo/shadcn/tooltip';
import { Editor } from '@tiptap/core';

export const EditorToolbar = ({ editor }: { editor: Editor }) => {
  return (
    <div className="sticky top-0 z-20 w-full border-b bg-background hidden sm:block">
      <ToolbarProvider editor={editor}>
        <TooltipProvider>
          <ScrollArea className="h-fit py-0.5">
            <div>
              <div className="flex items-center gap-1 px-2">
                {/* History Group */}
                <UndoToolbar />
                <RedoToolbar />
                <Separator orientation="vertical" className="mx-1 h-7" />

                {/* Text Structure Group */}
                <HeadingsToolbar />
                <FontFamilyToolbar />
                <BlockquoteToolbar />
                <CodeToolbar />
                <CodeBlockToolbar />
                <Separator orientation="vertical" className="mx-1 h-7" />

                {/* Basic Formatting Group */}
                <BoldToolbar />
                <ItalicToolbar />
                <UnderlineToolbar />
                <StrikeThroughToolbar />
                <LinkToolbar />
                <Separator orientation="vertical" className="mx-1 h-7" />

                {/* Lists & Structure Group */}
                <BulletListToolbar />
                <OrderedListToolbar />
                <HorizontalRuleToolbar />
                <Separator orientation="vertical" className="mx-1 h-7" />

                {/* Alignment Group */}
                <AlignmentToolbar />
                <Separator orientation="vertical" className="mx-1 h-7" />

                {/* Media & Styling Group */}
                <ImagePlaceholderToolbar />
                <TableToolbar />
                <EmojiEditor />
                <ColorHighlightToolbar />
                <Separator orientation="vertical" className="mx-1 h-7" />

                <div className="flex-1" />

                {/* Utility Group */}
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
