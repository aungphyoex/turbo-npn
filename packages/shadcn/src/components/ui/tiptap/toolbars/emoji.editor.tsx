'use client';

import { Button } from '@repo/shadcn/button';
import {
  EmojiPicker,
  EmojiPickerContent,
  EmojiPickerFooter,
  EmojiPickerSearch,
} from '@repo/shadcn/emoji-picker';
import { cn } from '@repo/shadcn/lib/utils';
import { Popover, PopoverContent, PopoverTrigger } from '@repo/shadcn/popover';
import { useToolbar } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';
import { SmilePlus } from 'lucide-react';
import { useState } from 'react';

const EmojiEditor = () => {
  const [emojiOpen, setEmojiOpen] = useState(false);
  const { editor } = useToolbar();
  return (
    <Popover open={emojiOpen} onOpenChange={setEmojiOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className={cn('h-8 w-8 p-0 sm:h-9 sm:w-9')}
        >
          <SmilePlus className="size-4" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-fit p-0">
        <EmojiPicker
          className="h-[342px]"
          onEmojiSelect={({ emoji }) => {
            editor.commands.insertContent(emoji);
            setEmojiOpen(false);
          }}
        >
          <EmojiPickerSearch />
          <EmojiPickerContent />
          <EmojiPickerFooter />
        </EmojiPicker>
      </PopoverContent>
    </Popover>
  );
};

export default EmojiEditor;
