import { ModeSwitcher } from '@repo/shadcn/mode-switcher';
import { RichTextEditor } from '@repo/shadcn/tiptap/rich-text-editor';
import { VideoPlayer } from '@repo/shadcn/video/player';

const Page = () => {
  return (
    <section className="min-h-dvh container">
      <nav className="flex justify-between items-center py-2">
        <h1 className="font-semibold">Turborepo</h1>
        <ModeSwitcher />
      </nav>
      <div className="flex justify-center items-center">
        <VideoPlayer
          keyboardControls={false}
          poster={
            'https://images.unsplash.com/photo-1745282480794-10427e218c76'
          }
          src="/test.mp4"
          className="w-full lg:w-[600px] h-[300px]"
        />
      </div>
      <RichTextEditor />
    </section>
  );
};

export default Page;
