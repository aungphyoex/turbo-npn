'use client';
/* eslint-disable */
// @ts-nocheck
import { Button } from '@repo/shadcn/button';
import { useMediaQuery } from '@repo/shadcn/hooks/v/use-media-querry';
import { cn } from '@repo/shadcn/lib/utils';
import { Popover, PopoverContent, PopoverTrigger } from '@repo/shadcn/popover';
import { ScrollArea } from '@repo/shadcn/scroll-area';
import {
  MobileToolbarGroup,
  MobileToolbarItem,
} from '@repo/shadcn/tiptap/toolbars/mobile-toolbar-group';
import { useToolbar } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';
import { Tooltip, TooltipContent, TooltipTrigger } from '@repo/shadcn/tooltip';
import { CheckIcon, ChevronDownIcon } from 'lucide-react';

const FONT_FAMILIES = [
  'Inter',
  'Roboto',
  'Open Sans',
  'Georgia',
  'Times New Roman',
  'Courier New',
  'Comic Sans MS',
  'Arial',
  'Verdana',
];

interface FontFamilyItemProps {
  font: string;
  isActive: boolean;
  onClick: () => void;
}

const FontFamilyItem = ({ font, isActive, onClick }: FontFamilyItemProps) => (
  <button
    onClick={onClick}
    className="flex w-full items-center justify-between rounded-sm px-2 py-1 text-sm font-medium hover:bg-gray-3"
    type="button"
  >
    <span style={{ fontFamily: font }}>{font}</span>
    {isActive && <CheckIcon className="h-4 w-4" />}
  </button>
);

export const FontFamilyToolbar = () => {
  const { editor } = useToolbar();
  const isMobile = useMediaQuery('(max-width: 640px)');

  const currentFont = editor?.getAttributes('textStyle').fontFamily;

  const handleFontChange = (font: string) => {
    editor?.chain().focus().setMark('textStyle', { fontFamily: font }).run();
  };

  if (!editor) return null;

  if (isMobile) {
    return (
      <MobileToolbarGroup label="Font">
        {FONT_FAMILIES.map((font) => (
          <MobileToolbarItem
            key={font}
            onClick={() => handleFontChange(font)}
            active={currentFont === font}
          >
            <span style={{ fontFamily: font }}>{font}</span>
          </MobileToolbarItem>
        ))}
      </MobileToolbarGroup>
    );
  }

  return (
    <Popover>
      <div className="relative h-full">
        <Tooltip>
          <TooltipTrigger asChild>
            <PopoverTrigger asChild>
              <Button
                variant="ghost"
                size="sm"
                className={cn('h-8 w-32 p-0 font-normal text-left')}
              >
                <span className="truncate" style={{ fontFamily: currentFont }}>
                  {currentFont || 'Font'}
                </span>
                <ChevronDownIcon className="ml-2 h-4 w-4" />
              </Button>
            </PopoverTrigger>
          </TooltipTrigger>
          <TooltipContent>Font Family</TooltipContent>
        </Tooltip>

        <PopoverContent align="start" className="w-56 p-1 dark:bg-gray-2">
          <ScrollArea className="max-h-80 overflow-y-auto pr-2">
            {FONT_FAMILIES.map((font) => (
              <FontFamilyItem
                key={font}
                font={font}
                isActive={currentFont === font}
                onClick={() => handleFontChange(font)}
              />
            ))}
          </ScrollArea>
        </PopoverContent>
      </div>
    </Popover>
  );
};
