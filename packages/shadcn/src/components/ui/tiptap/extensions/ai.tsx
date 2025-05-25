import { createGoogleGenerativeAI } from '@ai-sdk/google';
import { Button } from '@repo/shadcn/button';
import { Label } from '@repo/shadcn/label';
import { Popover, PopoverContent, PopoverTrigger } from '@repo/shadcn/popover';
import { Textarea } from '@repo/shadcn/textarea';
import { Editor } from '@tiptap/core';
import { generateText } from 'ai';
import { Loader2, Sparkles } from 'lucide-react';
import { marked } from 'marked';
import { useState } from 'react';

const Ai = ({ editor }: { editor: Editor }) => {
  const [aiDialogOpen, setAiDialogOpen] = useState(false);
  const [aiPrompt, setAiPrompt] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);

  const google = createGoogleGenerativeAI({
    apiKey: process.env.NEXT_PUBLIC_GOOGLE_API_KEY,
  });

  const generateAIContent = async () => {
    if (!editor || !aiPrompt.trim()) return;

    try {
      setIsGenerating(true);
      const { text } = await generateText({
        model: google('gemini-2.5-flash-preview-04-17'),
        prompt: aiPrompt,
        // maxTokens: 500,
      });
      const html = marked.parse(text);
      editor.commands.insertContent(html);
      setAiPrompt('');
      setAiDialogOpen(false);
      console.log('Passed ai content', text, html);
    } catch (error) {
      console.error('GlobalError generating content:', error);
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <>
      <Popover open={aiDialogOpen} onOpenChange={setAiDialogOpen}>
        <PopoverTrigger asChild>
          <Button
            variant="ghost"
            size="sm"
            className="h-8 px-2 text-xs sm:text-sm hidden md:flex"
            disabled={
              isGenerating ||
              !editor?.can().chain().focus().insertContent('').run()
            }
          >
            <Sparkles className="h-4 w-4" />
            <span className="ml-1 hidden sm:inline">AI</span>
          </Button>
        </PopoverTrigger>
        <PopoverContent
          onCloseAutoFocus={(e) => e.preventDefault()}
          side="bottom"
          align="center"
          className="max-w-full  md:w-[500px]"
        >
          <div className="w-full flex flex-col gap-3 mb-5">
            <Label htmlFor="ai-prompt">Prompt</Label>
            <Textarea
              id="ai-prompt"
              placeholder="Describe what content you want to generate..."
              value={aiPrompt}
              onChange={(e) => setAiPrompt(e.target.value)}
              className="min-h-[100px] max-h-[100px] w-full resize-none focus:outline-none focus-visible:ring-0 focus-visible:ring-offset-0 focus-visible:outline-0"
            />
          </div>
          <Button
            onClick={generateAIContent}
            disabled={isGenerating || !aiPrompt.trim()}
            className="w-full"
          >
            {isGenerating ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Generating...
              </>
            ) : (
              <>
                <Sparkles className="mr-2 h-4 w-4" />
                Generate
              </>
            )}
          </Button>
        </PopoverContent>
      </Popover>
    </>
  );
};

export default Ai;
