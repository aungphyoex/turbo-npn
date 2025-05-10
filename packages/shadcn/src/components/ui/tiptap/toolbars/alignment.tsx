'use client';

import { useMediaQuery } from '@repo/shadcn/hooks/v/use-media-querry';
import {
  MobileToolbarGroup,
  MobileToolbarItem,
} from '@repo/shadcn/tiptap/toolbars/mobile-toolbar-group';
import {
  AlignCenter,
  AlignJustify,
  AlignLeft,
  AlignRight,
  Check,
  ChevronDown,
} from 'lucide-react';

import { Button } from '@repo/shadcn/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@repo/shadcn/dropdown-menu';
import { useToolbar } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';
import { Tooltip, TooltipContent, TooltipTrigger } from '@repo/shadcn/tooltip';

export const AlignmentToolbar = () => {
  const { editor } = useToolbar();
  const isMobile = useMediaQuery('(max-width: 640px)');
  const handleAlign = (value: string) => {
    editor?.chain().focus().setTextAlign(value).run();
  };

  const isDisabled =
    editor?.isActive('image') ?? editor?.isActive('video') ?? !editor ?? false;

  const currentTextAlign = () => {
    if (editor?.isActive({ textAlign: 'left' })) {
      return 'left';
    }
    if (editor?.isActive({ textAlign: 'center' })) {
      return 'center';
    }
    if (editor?.isActive({ textAlign: 'right' })) {
      return 'right';
    }
    if (editor?.isActive({ textAlign: 'justify' })) {
      return 'justify';
    }

    return 'left';
  };

  const alignmentOptions = [
    {
      name: 'Left',
      value: 'left',
      icon: <AlignLeft className="h-4 w-4" />,
    },
    {
      name: 'Center',
      value: 'center',
      icon: <AlignCenter className="h-4 w-4" />,
    },
    {
      name: 'Right',
      value: 'right',
      icon: <AlignRight className="h-4 w-4" />,
    },
    {
      name: 'Justify',
      value: 'justify',
      icon: <AlignJustify className="h-4 w-4" />,
    },
  ];

  const findIndex = (value: string) => {
    return alignmentOptions.findIndex((option) => option.value === value);
  };

  if (isMobile) {
    return (
      <MobileToolbarGroup
        label={alignmentOptions[findIndex(currentTextAlign())]?.name ?? 'Left'}
      >
        {alignmentOptions.map((option, index) => (
          <MobileToolbarItem
            key={index}
            onClick={() => handleAlign(option.value)}
            active={currentTextAlign() === option.value}
          >
            <span className="mr-2">{option.icon}</span>
            {option.name}
          </MobileToolbarItem>
        ))}
      </MobileToolbarGroup>
    );
  }

  return (
    <DropdownMenu>
      <Tooltip>
        <TooltipTrigger asChild>
          <DropdownMenuTrigger disabled={isDisabled} asChild>
            <Button variant="ghost" size="sm" className="h-8 w-max font-normal">
              <span className="mr-2">
                {alignmentOptions[findIndex(currentTextAlign())]?.icon}
              </span>
              {alignmentOptions[findIndex(currentTextAlign())]?.name}
              <ChevronDown className="ml-2 h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
        </TooltipTrigger>
        <TooltipContent>Text Alignment</TooltipContent>
      </Tooltip>
      <DropdownMenuContent
        loop
        onCloseAutoFocus={(e) => {
          e.preventDefault();
        }}
      >
        <DropdownMenuGroup className=" w-40">
          {alignmentOptions.map((option, index) => (
            <DropdownMenuItem
              onSelect={() => {
                handleAlign(option.value);
              }}
              key={index}
            >
              <span className="mr-2">{option.icon}</span>
              {option.name}

              {option.value === currentTextAlign() && (
                <Check className="ml-auto h-4 w-4" />
              )}
            </DropdownMenuItem>
          ))}
        </DropdownMenuGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
};
