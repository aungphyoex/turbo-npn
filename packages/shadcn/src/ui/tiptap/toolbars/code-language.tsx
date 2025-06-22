import { Button } from '@repo/shadcn/button';
import { Input } from '@repo/shadcn/input';
import { cn } from '@repo/shadcn/lib/utils';
import { Popover, PopoverContent, PopoverTrigger } from '@repo/shadcn/popover';
import { ScrollArea } from '@repo/shadcn/scroll-area';
import { Editor } from '@tiptap/core';
import { FloatingMenu, useEditorState } from '@tiptap/react';
import { common } from 'lowlight';
import { ChevronDownIcon } from 'lucide-react';
import { useMemo, useState } from 'react';

export const CodeLanguage = ({ editor }: { editor: Editor | null }) => {
  const [search, setSearch] = useState<string>('');

  const editorState = useEditorState({
    editor,
    selector: (instance) => ({
      getLanguage: instance.editor?.getAttributes('codeBlock').language,
    }),
  });
  const languages = useMemo(() => {
    return Object.keys(common);
  }, []);

  if (!editor || !editorState) {
    return null;
  }

  return (
    <FloatingMenu
      editor={editor}
      tippyOptions={{
        placement: 'top-end',
        appendTo: 'parent',
        duration: 100,
        zIndex: 0,
        offset: [0, 8],
        getReferenceClientRect: () => {
          const { ranges } = editor.state.selection;
          const from = Math.min(...ranges.map((range) => range.$from.pos));
          const to = Math.max(...ranges.map((range) => range.$to.pos));

          let nodePos: number | undefined = undefined;

          editor.state.doc.nodesBetween(from, to, (node, p) => {
            if (node.type.name !== 'codeBlock') {
              return;
            }

            nodePos = p;
            return false;
          });

          if (nodePos !== undefined) {
            const node = editor.view.nodeDOM(nodePos) as HTMLElement;

            if (node) {
              return node.getBoundingClientRect();
            }
          }

          return editor.view.dom.getBoundingClientRect();
        },
      }}
      className={cn('flex w-fit max-w-[90vw] space-x-0.5')}
      shouldShow={({ editor }) => {
        return editor.isActive('codeBlock');
      }}
    >
      <Popover
        onOpenChange={(op) => {
          if (op) {
            setSearch('');
          }
        }}
      >
        <PopoverTrigger asChild>
          {editorState.getLanguage && (
            <Button className="" variant="outline" size="sm">
              {editorState.getLanguage}
              <ChevronDownIcon className="size-4 lg:size-5ms-1 text-default-foreground" />
            </Button>
          )}
        </PopoverTrigger>
        <PopoverContent className="w-40 p-0" align="end">
          <div className="p-1">
            <Input
              placeholder="Search..."
              className="h-9 focus-visible:ring-0 focus-visible:border-primary"
              type="search"
              value={search}
              onChange={(evt) => setSearch(evt.target.value)}
            />
          </div>
          <div className="flex max-h-[320px]">
            <ScrollArea className="grow p-1">
              {languages
                .filter((v) => {
                  if (!search) {
                    return true;
                  }
                  return v.toLowerCase().startsWith(search.toLowerCase());
                })
                .map((l, i) => {
                  return (
                    <div
                      key={i}
                      className="hover:bg-accent p-1 rounded-md cursor-pointer"
                      onClick={() => {
                        editor
                          .chain()
                          .focus(undefined, { scrollIntoView: false })
                          .toggleCodeBlock({ language: l })
                          .run();
                      }}
                    >
                      <span>{l}</span>
                    </div>
                  );
                })}
            </ScrollArea>
          </div>
        </PopoverContent>
      </Popover>
    </FloatingMenu>
  );
};
