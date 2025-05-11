'use client';

import { Image } from 'lucide-react';

import { Button, type ButtonProps } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils';
import { useToolbar } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';

export const ImagePlaceholderToolbar = ({
  className,
  onClick,
  children,
  ...props
}: ButtonProps) => {
  const { editor } = useToolbar();

  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!editor || !e.target.files?.length) return;

    const file = e.target.files[0];
    const reader = new FileReader();

    reader.onload = (e) => {
      const result = e.target?.result;
      if (typeof result === 'string') {
        editor.chain().focus().setImage({ src: result }).run();
      }
    };

    reader.readAsDataURL(file as Blob);
  };

  return (
    <Button
      variant="ghost"
      size="icon"
      className={cn(
        'h-8 w-8 p-0 sm:h-9 sm:w-9',
        editor?.isActive('image-placeholder') && 'bg-accent',
        className,
      )}
      onClick={(e) => {
        e.preventDefault();
        editor?.chain().focus().insertImagePlaceholder().run();
        onClick?.(e);
      }}
      {...props}
    >
      {children ?? <Image className="h-4 w-4" />}
    </Button>
  );
};
