import { cn } from '@repo/shadcn/lib/utils';
import { ImageExtension } from '@repo/shadcn/tiptap/extensions/image';
import { ImagePlaceholder } from '@repo/shadcn/tiptap/extensions/image-placeholder';
import SearchAndReplace from '@repo/shadcn/tiptap/extensions/search-and-replace';
import { CodeBlock } from '@repo/shadcn/tiptap/toolbars/code-block';
import { mergeAttributes } from '@tiptap/core';
import CharacterCount from '@tiptap/extension-character-count';
import { Color } from '@tiptap/extension-color';
import FontFamily from '@tiptap/extension-font-family';
import { Heading } from '@tiptap/extension-heading';
import Highlight from '@tiptap/extension-highlight';
import Link from '@tiptap/extension-link';
import Placeholder from '@tiptap/extension-placeholder';
import { createColGroup, Table } from '@tiptap/extension-table';
import TableCell from '@tiptap/extension-table-cell';
import TableHeader from '@tiptap/extension-table-header';
import TableRow from '@tiptap/extension-table-row';
import TextAlign from '@tiptap/extension-text-align';
import TextStyle from '@tiptap/extension-text-style';
import { Typography } from '@tiptap/extension-typography';
import Underline from '@tiptap/extension-underline';
import Youtube from '@tiptap/extension-youtube';
import { DOMOutputSpec } from '@tiptap/pm/model';
import StarterKit from '@tiptap/starter-kit';
import { common, createLowlight } from 'lowlight';
import GlobalDragHandle from 'tiptap-extension-global-drag-handle';

export const TiptapStarterKit = StarterKit.configure({
  bulletList: {
    HTMLAttributes: {
      class: cn('list-disc list-outside leading-3 -mt-2'),
    },
  },
  orderedList: {
    HTMLAttributes: {
      class: cn('list-decimal list-outside leading-3 -mt-2'),
    },
  },
  listItem: {
    HTMLAttributes: {
      class: cn('leading-normal -mb-2'),
    },
  },
  blockquote: {
    HTMLAttributes: {
      class: cn('border-l-4 border-gray-600'),
    },
  },
  codeBlock: false,
  code: {
    HTMLAttributes: {
      class: cn(
        'rounded-lg bg-muted text-red-700 dark:bg-muted/90 dark:text-red-400 px-1.5 py-1 font-mono font-medium before:content-none after:content-none',
      ),
      spellcheck: 'false',
    },
  },
  horizontalRule: {
    HTMLAttributes: {
      class: cn('my-4 bg-border border-border'),
    },
  },
  dropcursor: {
    color: '#DBEAFE',
    width: 4,
  },
  gapcursor: false,
  heading: false,
});

const TiptapHeading = Heading.extend({
  renderHTML({ node, HTMLAttributes }) {
    const hasLevel = this.options.levels.includes(node.attrs.level);
    const level = hasLevel ? node.attrs.level : this.options.levels[0];

    if (node.textContent) {
      return [
        `h${level}`,
        mergeAttributes(this.options.HTMLAttributes, HTMLAttributes, {
          id: node.textContent.replaceAll(/\s+/g, '-').toLowerCase(),
        }),
        0,
      ];
    }
    return [
      `h${level}`,
      mergeAttributes(this.options.HTMLAttributes, HTMLAttributes),
      0,
    ];
  },
});

const lowlight = createLowlight(common);
const codeBlock = CodeBlock.configure({
  HTMLAttributes: {
    class: cn(
      'rounded !bg-gray-800 dark:!bg-gray-900 text-gray-200 border p-5 font-mono font-medium',
    ),
    spellcheck: false,
  },
  defaultLanguage: 'plaintext',
  lowlight: lowlight,
});

const TiptapTextAlign = TextAlign.configure({
  types: ['heading', 'paragraph'],
});

const TiptapTable = Table.extend({
  renderHTML({ node, HTMLAttributes }) {
    const { colgroup, tableWidth, tableMinWidth } = createColGroup(
      node,
      this.options.cellMinWidth,
    );

    const table: DOMOutputSpec = [
      'div',
      {
        class: 'table-wrapper overflow-y-auto my-[1em] not-draggable',
      },
      [
        'table',
        mergeAttributes(this.options.HTMLAttributes, HTMLAttributes, {
          style: tableWidth
            ? `width: ${tableWidth}`
            : `minWidth: ${tableMinWidth}`,
        }),
        colgroup,
        ['tbody', 0],
      ],
    ];

    return table;
  },
}).configure({
  HTMLAttributes: {
    class: cn('not-prose table-auto border-collapse w-full'),
  },
  lastColumnResizable: false,
  allowTableNodeSelection: true,
});

const TiptapTableHeader = TableHeader.configure({
  HTMLAttributes: {
    class: cn(
      'bg-muted dark:bg-gray-900 border border-default p-2 text-start min-w-[150px] font-semibold',
    ),
  },
});

const TiptapTableCell = TableCell.configure({
  HTMLAttributes: {
    class: cn('border border-default p-2 min-w-[150px] align-middle'),
  },
});

const TiptapLink = Link.configure({
  HTMLAttributes: {
    class: cn(
      '!text-foreground underline underline-offset-[3px] transition-colors cursor-pointer',
    ),
  },
  openOnClick: false,
});

const TiptapImage = ImageExtension;

const DragHandle = GlobalDragHandle.configure({
  dragHandleWidth: 25,
  excludedTags: ['table'],
});

const TiptapYoutube = Youtube.configure({
  HTMLAttributes: {
    class: cn('border border-muted'),
  },
  nocookie: true,
});

const TiptapCharacterCount = CharacterCount;

const TiptapHighLight = Highlight.configure({});

const TiptapColor = Color.configure();

const TiptapFontFamily = FontFamily.configure({
  types: ['textStyle'],
});
const TiptapPlaceholder = Placeholder.configure({
  emptyNodeClass: 'is-editor-empty',
  placeholder: ({ node }) => {
    switch (node.type.name) {
      case 'heading':
        return `Heading ${node.attrs.level}`;
      case 'detailsSummary':
        return 'Section title';
      case 'codeBlock':
        // never show the placeholder when editing code
        return '';
      default:
        return "Write, type '/' for commands";
    }
  },
  includeChildren: false,
});

const TiptapSearch = SearchAndReplace;

const TiptapTypography = Typography.configure({});

const TiptapImagePlaceholder = ImagePlaceholder.configure({});

export const defaultExtensions = [
  TiptapStarterKit,
  TiptapHeading,
  TiptapTextAlign,
  TiptapTable,
  TiptapTableHeader,
  TableRow,
  TiptapTableCell,
  TiptapLink,
  TiptapYoutube,
  TiptapCharacterCount,
  TiptapImage,
  Underline,
  TextStyle,
  codeBlock,
  DragHandle,
  TiptapHighLight,
  TiptapColor,
  TiptapFontFamily,
  TiptapPlaceholder,
  TiptapSearch,
  TiptapTypography,
  TiptapImagePlaceholder,
];
