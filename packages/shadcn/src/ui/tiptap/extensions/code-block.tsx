'use client';

import CodeBlockLowlight from '@tiptap/extension-code-block-lowlight';

export const CodeBlock = CodeBlockLowlight.extend({
  addKeyboardShortcuts() {
    return {
      ...this.parent?.(),
      Tab: ({ editor }) => {
        if (editor.isActive(this.type.name)) {
          editor
            .chain()
            .command(({ tr }) => {
              tr.insertText('  ');
              return true;
            })
            .run();
        }
        return true;
      },
    };
  },
});
