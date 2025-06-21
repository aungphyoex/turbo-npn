'use client';
// @ts-nocheck
/* eslint-disable */
import { Button } from '@repo/shadcn/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from '@repo/shadcn/dropdown-menu';
import { Input } from '@repo/shadcn/input';
import { cn } from '@repo/shadcn/lib/utils';
import { Separator } from '@repo/shadcn/separator';
import { Editor, Node, mergeAttributes } from '@tiptap/core';
import { NodeViewWrapper, ReactNodeViewRenderer } from '@tiptap/react';
import { AlignCenter, AlignLeft, AlignRight, Trash } from 'lucide-react';
import { IconBrandYoutubeFill } from 'obra-icons-react';
import { useRef, useState } from 'react';

export interface TiptapYouTubeEmbedProps {
  node: any;
  editor: Editor;
  selected: boolean;
  deleteNode: () => void;
  updateAttributes: (attrs: Record<string, any>) => void;
}

export const YouTubeExtension = Node.create({
  name: 'youtube',

  group: 'block',

  atom: true,

  draggable: true,

  addAttributes() {
    return {
      src: {
        default: null,
      },
      width: {
        default: '100%',
      },
      height: {
        default: 315,
      },
      align: {
        default: 'center',
      },
      caption: {
        default: '',
      },
    };
  },

  parseHTML() {
    return [
      {
        tag: 'div[data-type="youtube"]',
      },
    ];
  },

  renderHTML({ HTMLAttributes }) {
    return ['div', mergeAttributes(HTMLAttributes, { 'data-type': 'youtube' })];
  },

  addNodeView() {
    return ReactNodeViewRenderer(TiptapYouTube);
  },
});

function TiptapYouTube({
  node,
  updateAttributes,
  deleteNode,
  editor,
  selected,
}: TiptapYouTubeEmbedProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [caption, setCaption] = useState(node.attrs.caption);
  const [editingCaption, setEditingCaption] = useState(false);
  const [videoUrl, setVideoUrl] = useState(node.attrs.src);
  const [opened, setOpened] = useState(false);

  const extractVideoId = (url: string) => {
    const match = url.match(
      /(?:youtube\.com\/(?:[^/]+\/.+\/|(?:v|e(?:mbed)?)\/|.*[?&]v=)|youtu\.be\/)([^"&?/\s]{11})/,
    );
    return match?.[1];
  };

  const embedLink = extractVideoId(node.attrs.src)
    ? `https://www.youtube.com/embed/${extractVideoId(node.attrs.src)}`
    : '';

  const handleReplace = () => {
    if (videoUrl) {
      updateAttributes({ src: videoUrl });
      setOpened(false);
    }
  };
  return (
    <NodeViewWrapper
      ref={containerRef}
      data-type="youtube"
      className={cn(
        'group relative flex flex-col border-2 border-transparent rounded-md transition-all',
        selected && 'border-blue-300',
        node.attrs.align === 'left' && 'left-0',
        node.attrs.align === 'center' && 'mx-auto',
        node.attrs.align === 'right' && 'ml-auto',
      )}
      style={{ width: node.attrs.width }}
    >
      <div className="relative w-full">
        {embedLink && (
          <iframe
            className="rounded-md"
            width="100%"
            height={node.attrs.height}
            src={embedLink}
            frameBorder="0"
            allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
            allowFullScreen
          />
        )}
      </div>

      {editingCaption ? (
        <Input
          className="mt-2 text-center text-sm text-muted-foreground"
          value={caption}
          onChange={(e) => setCaption(e.target.value)}
          onBlur={() => {
            updateAttributes({ caption });
            setEditingCaption(false);
          }}
        />
      ) : (
        <p
          className="mt-2 cursor-text text-center text-sm text-muted-foreground"
          onClick={() => editor?.isEditable && setEditingCaption(true)}
        >
          {caption || 'Add a caption...'}
        </p>
      )}

      {editor?.isEditable && (
        <div
          className={cn(
            'absolute right-4 top-4 flex items-center gap-1 rounded-md border bg-background/80 p-1 backdrop-blur transition-opacity',
            opened ? 'opacity-100' : 'opacity-0 group-hover:opacity-100',
          )}
        >
          <Button
            size="icon"
            className={cn('size-7', node.attrs.align === 'left' && 'bg-accent')}
            variant="ghost"
            onClick={() => updateAttributes({ align: 'left' })}
          >
            <AlignLeft className="size-4" />
          </Button>
          <Button
            size="icon"
            className={cn(
              'size-7',
              node.attrs.align === 'center' && 'bg-accent',
            )}
            variant="ghost"
            onClick={() => updateAttributes({ align: 'center' })}
          >
            <AlignCenter className="size-4" />
          </Button>
          <Button
            size="icon"
            className={cn(
              'size-7',
              node.attrs.align === 'right' && 'bg-accent',
            )}
            variant="ghost"
            onClick={() => updateAttributes({ align: 'right' })}
          >
            <AlignRight className="size-4" />
          </Button>
          <Separator orientation="vertical" className="h-[20px]" />
          <DropdownMenu open={opened} onOpenChange={setOpened}>
            <DropdownMenuTrigger asChild>
              <Button size="icon" variant="ghost" className="size-7">
                <IconBrandYoutubeFill className="size-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" className="p-4 space-y-2 w-64">
              <Input
                value={videoUrl}
                onChange={(e) => setVideoUrl(e.target.value)}
                placeholder="Paste YouTube URL..."
              />
              <Button onClick={handleReplace} size="sm" disabled={!videoUrl}>
                Replace Video
              </Button>
            </DropdownMenuContent>
          </DropdownMenu>
          <Separator orientation="vertical" className="h-[20px]" />
          <Button
            size="icon"
            variant="ghost"
            className="size-7 text-destructive"
            onClick={deleteNode}
          >
            <Trash className="size-4" />
          </Button>
        </div>
      )}
    </NodeViewWrapper>
  );
}
