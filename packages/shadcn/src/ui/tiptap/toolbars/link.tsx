'use client';

import { PopoverClose } from '@radix-ui/react-popover';
import { Link2, Trash2, X } from 'lucide-react';
import { useEffect, useState, type FormEvent } from 'react';

import { Button, type ButtonProps } from '@repo/shadcn/button';
import { Input } from '@repo/shadcn/input';
import { Label } from '@repo/shadcn/label';
import { getUrlFromString } from '@repo/shadcn/lib/tiptap-utils.js';
import { cn } from '@repo/shadcn/lib/utils';
import { Popover, PopoverContent, PopoverTrigger } from '@repo/shadcn/popover';
import { useToolbar } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';

export const LinkToolbar = ({ className, ...props }: ButtonProps) => {
  const { editor } = useToolbar();
  const [link, setLink] = useState('');

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    const url = getUrlFromString(link);
    url && editor?.chain().focus().setLink({ href: url }).run();
  };

  useEffect(() => {
    setLink(editor?.getAttributes('link').href ?? '');
  }, [editor]);

  return (
    <Popover>
      <PopoverTrigger
        disabled={!editor?.can().chain().setLink({ href: '' }).run()}
        asChild
      >
        <Button
          variant="ghost"
          size="sm"
          className={cn(
            'h-8 w-max px-3 font-normal',
            editor?.isActive('link') && 'bg-accent',
            className,
          )}
          {...props}
        >
          <Link2 className="h-4 w-4" />
        </Button>
      </PopoverTrigger>
      <PopoverContent
        onCloseAutoFocus={(e) => e.preventDefault()}
        asChild
        className="relative px-3 py-2.5"
        side="bottom"
      >
        <div className="relative">
          <PopoverClose className="absolute right-3 top-3">
            <X className="h-4 w-4" />
          </PopoverClose>
          <form onSubmit={handleSubmit}>
            <Label>Link</Label>
            <div className="mt-3 flex items-center justify-end gap-3">
              <Input
                value={link}
                onChange={(e) => setLink(e.target.value)}
                className="w-full focus:outline-0 focus-visible:ring-0 focus-visible:ring-offset-0 focus-visible:outline-0 border-primary"
                placeholder="https://example.com"
              />
              <div className="flex items-center gap-3">
                {editor?.getAttributes('link').href && (
                  <Button
                    type="reset"
                    size="sm"
                    className="h-8 text-gray-11"
                    variant="outline"
                    onClick={() => {
                      editor?.chain().focus().unsetLink().run();
                      setLink('');
                    }}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                )}
                <Button size="sm" className="h-8">
                  {editor?.getAttributes('link').href ? 'Update' : 'Confirm'}
                </Button>
              </div>
            </div>
          </form>
        </div>
      </PopoverContent>
    </Popover>
  );
};
