import { Button } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils.js';
import { Popover, PopoverContent, PopoverTrigger } from '@repo/shadcn/popover';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@repo/shadcn/tooltip';
import { Editor, FloatingMenu } from '@tiptap/react';
import {
  Columns,
  MoreHorizontal,
  RectangleHorizontal,
  Rows,
} from 'lucide-react';

export const TableMenu = ({ editor }: { editor: Editor | null }) => {
  if (!editor) {
    return null;
  }

  const menuItemClass = cn('px-2 py-1.5 text-sm hover:bg-accent rounded-md');

  return (
    <FloatingMenu
      editor={editor}
      tippyOptions={{
        placement: 'top-end',
        appendTo: 'parent',
        duration: 100,
        zIndex: 0,
        offset: [0, -15],
        getReferenceClientRect: () => {
          const { ranges } = editor.state.selection;
          const from = Math.min(...ranges.map((range) => range.$from.pos));
          const to = Math.max(...ranges.map((range) => range.$to.pos));

          let nodePos: number | undefined = undefined;

          editor.state.doc.nodesBetween(from, to, (_node, p) => {
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
        return editor.isActive('table');
      }}
    >
      <TooltipProvider delayDuration={300}>
        <Popover>
          <Tooltip>
            <PopoverTrigger asChild>
              <TooltipTrigger asChild>
                <Button
                  className="drop-shadow-xs"
                  variant="outline"
                  size="icon"
                >
                  <Columns className="size-4" />
                </Button>
              </TooltipTrigger>
            </PopoverTrigger>
            <TooltipContent>Column</TooltipContent>
          </Tooltip>
          <PopoverContent
            className="flex max-h-80 w-40 p-1 flex-col overflow-hidden overflow-y-auto rounded border shadow-xl"
            align="end"
          >
            <div className="flex flex-col">
              <div
                onClick={() => {
                  editor.chain().focus().addColumnBefore().run();
                }}
                className={menuItemClass}
                role="button"
              >
                Add column before
              </div>
              <div
                onClick={() => {
                  editor.chain().focus().addColumnAfter().run();
                }}
                className={menuItemClass}
                role="button"
              >
                Add column after
              </div>
              <div
                onClick={() => {
                  editor.chain().focus().deleteColumn().run();
                }}
                className={cn([menuItemClass], 'text-destructive')}
                role="button"
              >
                Delete column
              </div>
            </div>
          </PopoverContent>
        </Popover>

        <Popover>
          <Tooltip>
            <PopoverTrigger asChild>
              <TooltipTrigger asChild>
                <Button
                  className="drop-shadow-xs"
                  variant="outline"
                  size="icon"
                >
                  <Rows className="size-4" />
                </Button>
              </TooltipTrigger>
            </PopoverTrigger>
            <TooltipContent>Row</TooltipContent>
          </Tooltip>
          <PopoverContent
            className="flex max-h-80 w-40 p-1 flex-col overflow-hidden overflow-y-auto rounded border shadow-xl"
            align="end"
          >
            <div className="flex flex-col">
              <div
                onClick={() => {
                  editor.chain().focus().addRowBefore().run();
                }}
                className={menuItemClass}
                role="button"
              >
                Add row before
              </div>
              <div
                onClick={() => {
                  editor.chain().focus().addRowAfter().run();
                }}
                className={menuItemClass}
                role="button"
              >
                Add row after
              </div>
              <div
                onClick={() => {
                  editor.chain().focus().deleteRow().run();
                }}
                className={cn([menuItemClass], 'text-destructive')}
                role="button"
              >
                Delete row
              </div>
            </div>
          </PopoverContent>
        </Popover>

        <Popover>
          <Tooltip>
            <PopoverTrigger asChild>
              <TooltipTrigger asChild>
                <Button
                  className="drop-shadow-xs"
                  variant="outline"
                  size="icon"
                >
                  <RectangleHorizontal className="size-4" />
                </Button>
              </TooltipTrigger>
            </PopoverTrigger>
            <TooltipContent>Cell</TooltipContent>
          </Tooltip>
          <PopoverContent
            className="flex max-h-80 w-40 p-1 flex-col overflow-hidden overflow-y-auto rounded border shadow-xl"
            align="end"
          >
            <div className="flex flex-col">
              <div
                onClick={() => {
                  editor.chain().focus().mergeCells().run();
                }}
                className={menuItemClass}
                role="button"
              >
                Merge cells
              </div>
              <div
                onClick={() => {
                  editor.chain().focus().splitCell().run();
                }}
                className={menuItemClass}
                role="button"
              >
                Split cell
              </div>
              <div
                onClick={() => {
                  editor.chain().focus().toggleHeaderCell().run();
                }}
                className={menuItemClass}
                role="button"
              >
                Toggle header cell
              </div>
            </div>
          </PopoverContent>
        </Popover>

        <Popover>
          <Tooltip>
            <PopoverTrigger asChild>
              <TooltipTrigger asChild>
                <Button
                  className="drop-shadow-xs"
                  variant="outline"
                  size="icon"
                >
                  <MoreHorizontal className="size-4" />
                </Button>
              </TooltipTrigger>
            </PopoverTrigger>
            <TooltipContent>Options</TooltipContent>
          </Tooltip>
          <PopoverContent
            className="flex max-h-80 w-40 p-1 flex-col overflow-hidden overflow-y-auto rounded border shadow-xl"
            align="end"
          >
            <div className="flex flex-col">
              <div
                onClick={() => {
                  editor.chain().focus().toggleHeaderRow().run();
                }}
                className={menuItemClass}
                role="button"
              >
                Toggle header row
              </div>
              <div
                onClick={() => {
                  editor.chain().focus().toggleHeaderColumn().run();
                }}
                className={menuItemClass}
                role="button"
              >
                Toggle header col
              </div>
              <div
                onClick={() => {
                  editor.chain().focus().deleteTable().run();
                }}
                className={cn([menuItemClass], 'text-destructive')}
                role="button"
              >
                Delete table
              </div>
            </div>
          </PopoverContent>
        </Popover>
      </TooltipProvider>
    </FloatingMenu>
  );
};
