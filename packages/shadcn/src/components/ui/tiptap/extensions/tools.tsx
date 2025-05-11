import { Separator } from '@repo/shadcn/separator';
import { AlignmentToolbar } from '@repo/shadcn/tiptap/toolbars/alignment';
import { BulletListToolbar } from '@repo/shadcn/tiptap/toolbars/bullet-list';
import { ColorHighlightToolbar } from '@repo/shadcn/tiptap/toolbars/color-and-highlight';
import EmojiEditor from '@repo/shadcn/tiptap/toolbars/emoji-toolbar';
import { HeadingsToolbar } from '@repo/shadcn/tiptap/toolbars/headings';
import { HorizontalRuleToolbar } from '@repo/shadcn/tiptap/toolbars/horizontal-rule';
import { ImagePlaceholderToolbar } from '@repo/shadcn/tiptap/toolbars/image-placeholder-toolbar';
import { LinkToolbar } from '@repo/shadcn/tiptap/toolbars/link';
import { OrderedListToolbar } from '@repo/shadcn/tiptap/toolbars/ordered-list';
import { SearchAndReplaceToolbar } from '@repo/shadcn/tiptap/toolbars/search-and-replace-toolbar';
import { TableToolbar } from '@repo/shadcn/tiptap/toolbars/table';

const Tools = () => {
  return (
    <div className="w-full flex items-center px-2 gap-0.5">
      <div className="flex items-center gap-1 px-2">
        <HeadingsToolbar />
        <LinkToolbar />
        <Separator orientation="vertical" className="mx-1 h-7" />
        <BulletListToolbar />
        <OrderedListToolbar />
        <HorizontalRuleToolbar />
        <Separator orientation="vertical" className="mx-1 h-7" />
        <AlignmentToolbar />
        <Separator orientation="vertical" className="mx-1 h-7" />
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
  );
};

export default Tools;
