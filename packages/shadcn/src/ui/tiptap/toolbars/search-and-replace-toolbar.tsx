'use client';
/* eslint-disable */
// @ts-nocheck
import { ArrowLeftIcon, ArrowRightIcon, Repeat, X } from 'lucide-react';
import { useEffect, useState } from 'react';

import { Button } from '@repo/shadcn/button';
import { Checkbox } from '@repo/shadcn/checkbox';
import { Input } from '@repo/shadcn/input';
import { Label } from '@repo/shadcn/label';
import { cn } from '@repo/shadcn/lib/utils';
import { Popover, PopoverContent, PopoverTrigger } from '@repo/shadcn/popover';
import { Separator } from '@repo/shadcn/separator';
import { type SearchAndReplaceStorage } from '@repo/shadcn/tiptap/extensions/search-and-replace';
import { useToolbar } from '@repo/shadcn/tiptap/toolbars/toolbar-provider';

export function SearchAndReplaceToolbar() {
  const { editor } = useToolbar();

  const [open, setOpen] = useState(false);
  const [replacing, setReplacing] = useState(false);
  const [searchText, setSearchText] = useState('');
  const [replaceText, setReplaceText] = useState('');
  const [checked, setChecked] = useState(false);

  const results = editor?.storage?.searchAndReplace
    .results as SearchAndReplaceStorage['results'];
  const selectedResult = editor?.storage?.searchAndReplace
    .selectedResult as SearchAndReplaceStorage['selectedResult'];

  const replace = () => editor?.chain().replace().run();
  const replaceAll = () => editor?.chain().replaceAll().run();
  const selectNext = () => editor?.chain().selectNextResult().run();
  const selectPrevious = () => editor?.chain().selectPreviousResult().run();

  useEffect(() => {
    editor?.chain().setSearchTerm(searchText).run();
  }, [searchText, editor]);

  useEffect(() => {
    editor?.chain().setReplaceTerm(replaceText).run();
  }, [replaceText, editor]);

  useEffect(() => {
    editor?.chain().setCaseSensitive(checked).run();
  }, [checked, editor]);

  useEffect(() => {
    if (!open) {
      setReplaceText('');
      setSearchText('');
      setReplacing(false);
    }
  }, [open]);

  return (
    <Popover open={open}>
      <PopoverTrigger disabled={!editor} asChild>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => {
            setOpen(!open);
          }}
          className={cn('h-8 w-max px-3 font-normal')}
        >
          <Repeat className="h-4 w-4" />
          {/*<p>Refactor</p>*/}
        </Button>
      </PopoverTrigger>
      <PopoverContent
        align="end"
        onCloseAutoFocus={(e) => {
          e.preventDefault();
        }}
        onEscapeKeyDown={() => {
          setOpen(false);
        }}
        className="relative flex w-vw md:w-[400px] px-3 py-2.5"
      >
        {!replacing ? (
          <div className={cn('w-full relative grid gap-1.5 items-center')}>
            <Input
              value={searchText}
              className=" w-full focus:outline-0 focus-visible:ring-0 focus-visible:ring-offset-0 focus-visible:outline-0 border-primary"
              onChange={(e) => {
                setSearchText(e.target.value);
              }}
              placeholder="Search..."
            />
            <div className="flex items-center justify-between">
              <span className="text-sm">
                {results?.length === 0 ? selectedResult : selectedResult + 1}/
                {results?.length}
              </span>
              <div className="flex items-center gap-1">
                <Button
                  onClick={selectPrevious}
                  size="icon"
                  variant="ghost"
                  className="size-7"
                >
                  <ArrowLeftIcon className="size-4" />
                </Button>
                <Button
                  onClick={selectNext}
                  size="icon"
                  className="size-7"
                  variant="ghost"
                >
                  <ArrowRightIcon className="h-4 w-4" />
                </Button>
                <Separator orientation="vertical" className="h-7 mx-0.5" />
                <Button
                  onClick={() => {
                    setReplacing(true);
                  }}
                  size="icon"
                  className="size-7"
                  variant="ghost"
                >
                  <Repeat className="h-4 w-4" />
                </Button>
                <Button
                  onClick={() => {
                    setOpen(false);
                  }}
                  size="icon"
                  className="size-7"
                  variant="ghost"
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>
        ) : (
          <div className={cn('relative w-full')}>
            <X
              onClick={() => {
                setOpen(false);
              }}
              className="absolute right-3 top-3 h-4 w-4 cursor-pointer"
            />
            <div className="flex w-full items-center gap-3">
              <Button
                size="icon"
                className="size-7 rounded-full"
                variant="ghost"
                onClick={() => {
                  setReplacing(false);
                }}
              >
                <ArrowLeftIcon className="h-4 w-4" />
              </Button>
              <h2 className="text-sm font-medium">Search and replace</h2>
            </div>

            <div className="my-2 w-full">
              <div className="mb-3">
                <Label className="mb-1 text-xs text-gray-11">Search</Label>
                <Input
                  value={searchText}
                  onChange={(e) => {
                    setSearchText(e.target.value);
                  }}
                  placeholder="Search..."
                />
                <span className="text-xs">
                  {results?.length === 0 ? selectedResult : selectedResult + 1}/
                  {results?.length}
                </span>
              </div>
              <div className="mb-2">
                <Label className="mb-1 text-xs text-gray-11">
                  Replace with
                </Label>
                <Input
                  className="w-full"
                  value={replaceText}
                  onChange={(e) => {
                    setReplaceText(e.target.value);
                  }}
                  placeholder="Replace..."
                />
              </div>
              <div className="mt-3 flex items-center space-x-2">
                <Checkbox
                  checked={checked}
                  onCheckedChange={(checked: boolean) => {
                    setChecked(checked);
                  }}
                  id="match_case"
                />
                <Label
                  htmlFor="match_case"
                  className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
                >
                  Match case
                </Label>
              </div>
            </div>

            <div className="actions mt-6 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Button
                  onClick={selectPrevious}
                  size="icon"
                  className="h-7 w-7"
                  variant="secondary"
                >
                  <ArrowLeftIcon className="h-4 w-4" />
                </Button>
                <Button
                  onClick={selectNext}
                  size="icon"
                  className="h-7 w-7"
                  variant="secondary"
                >
                  <ArrowRightIcon className="h-4 w-4" />
                </Button>
              </div>

              <div className="main-actions flex items-center gap-2">
                <Button
                  size="sm"
                  className="h-7 px-3 text-xs"
                  variant="secondary"
                  onClick={replaceAll}
                >
                  Replace All
                </Button>
                <Button
                  onClick={replace}
                  size="sm"
                  className="h-7 px-3 text-xs"
                >
                  Replace
                </Button>
              </div>
            </div>
          </div>
        )}
      </PopoverContent>
    </Popover>
  );
}
