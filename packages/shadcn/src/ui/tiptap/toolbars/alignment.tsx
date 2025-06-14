'use client';

import { AlignCenter, AlignJustify, AlignLeft, AlignRight } from 'lucide-react';

import { Button } from '@repo/shadcn/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@repo/shadcn/dropdown-menu';
import { cn } from '@repo/shadcn/lib/utils';
import { useToolbar } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';

export const AlignmentToolbar = () => {
  const { editor } = useToolbar();
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

  return (
    <DropdownMenu>
      <DropdownMenuTrigger disabled={isDisabled} asChild>
        <Button
          variant="ghost"
          size="sm"
          className="h-8 w-8 p-0 sm:h-9 sm:w-9 font-normal"
        >
          {alignmentOptions[findIndex(currentTextAlign())]?.icon}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent
        loop
        onCloseAutoFocus={(e) => {
          e.preventDefault();
        }}
        className="w-max"
        align="end"
      >
        <DropdownMenuGroup className=" w-full">
          {alignmentOptions.map((option, index) => (
            <DropdownMenuItem
              onSelect={() => {
                handleAlign(option.value);
              }}
              key={index}
              className={cn(
                option.value === currentTextAlign() && 'bg-accent',
                'w-full',
              )}
            >
              <span className="mr-2">{option.icon}</span>
              {option.name}
            </DropdownMenuItem>
          ))}
        </DropdownMenuGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
};
